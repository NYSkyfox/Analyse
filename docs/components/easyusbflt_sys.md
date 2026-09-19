# easyusbflt.sys 组件深度逆向（USB 管控内核驱动）

> 样本：`samples/os-easy/easyusbflt.sys`（51736 字节，x64 PE32+）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`，自动探测 `x86:LE:64:default:windows`）
> 工程：`/projects/easyusbflt`
> 反编译存档：`/root/ghidra/mmpc/easyusbflt_x64.txt`（79 函数）
> 关联：`easyusbctrl_dll.md`（用户态控制库）、`easyusbinstall_exe.md`（安装器）、`../components/driver-install/easyusbflt_sys.md`（安装包内旧版 46104 字节）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 51736 字节 |
| MD5 | `5333a68063c1b01200366ed897e09ded` |
| SHA-256 | `502a7bfd640ba6e70b585efa4905486032bd083de857d4e7fc831aa259d39844` |
| 格式 | PE32+ 内核驱动（`pei-x86-64`） |
| 入口点 | `0x1939c`（`entry`） |
| PDB | `z:\win_drv\new_drv\easyusb\easyusbflt\objfre_win7_amd64\amd64\easyusbflt.pdb` |
| 编译 | WinDDK `6.1.7600.16385`（KMDF 框架，链接 Wdmlib） |

**导入**：仅 `ntoskrnl.exe`（纯内核），关键 API：
- 过滤驱动：`IoCreateDevice`(Secure)、`IoAttachDeviceToDeviceStack(Safe)`、`IoDetachDevice`、`IoGetLowerDeviceObject`、`IofCallDriver`、`IoBuildDeviceIoControlRequest`
- 符号链接：`IoCreateSymbolicLink` / `IoDeleteSymbolicLink`
- 注册表：`ZwOpenKey` / `ZwQueryValueKey` / `ZwCreateKey` / `ZwSetValueKey`
- 字符串/比较：`RtlInit/Equal/Upcase/Copy*String`、`_wcsnicmp`、`_snwprintf`/`_vsnwprintf`、`wcschr`
- 对象名：`ObQueryNameString`、`ObOpenObjectByPointer`、`IoDeviceObjectType`
- 安全：`RtlCreate/Length/...SecurityDescriptor`、`RtlAddAccessAllowedAce`、`SeCaptureSecurityDescriptor`、`ZwSetSecurityObject`、`SepSddl*`（SDDL 解析）
- 其它：`ExAllocatePool(WithTag)`、`PsGetVersion`、`KeBugCheckEx`、`PoStartNextPowerIrp`

**设备对象**：`\Device\EasyUsbflt`，符号链接 `\DosDevices\EasyUsbflt` → 用户态 `\\.\EasyUsbflt`。
**安全描述符（SDDL）**：`D:P(A;;GA;;;SY)(A;;GA;;;BA)` —— 仅 SYSTEM / Administrators 可 `GA`（全访问）。

---

## 1. 角色概述

`easyusbflt.sys` 是 **USB 设备过滤驱动（filter driver）**，用于**按"已登记设备白名单"阻止未授权 USB 设备接入**。工作方式：

1. **DriverEntry**（`OE-Entered the Driver Entry easyusbflt`）：建设备对象 + 符号链接，注册 IRP，`WdmlibInit`。
2. **AddDevice / 挂接**：对 `\Driver\USBSTOR`（存储盘类）执行 `IoAttachDeviceToDeviceStack` 下挂（`OE-AddDevice physical drv=... physical dev=...`）。
3. **URB 拦截**：在设备栈上截获 URB，**读取 USB 设备描述符**（设备名/VID/PID/Class），与**白名单**比对：命中放行，未命中且驱动处于"工作"态则 **Forbid（拒绝）**。
4. **白名单来源**：注册表 `HKLM\SYSTEM\CurrentControlSet\Services\easyusbflt\list`（多值字符串，`|` 分隔），以及"工作开关" `pw`。

## 2. URB 拦截与判定（核心，`FUN_0001136c`）

```
if (MajorFunction != CREATE) {
    URB = Irp->AssociatedIrp.SystemBuffer;
    if (URB->UrbType == FUNCTION(0x0F) && URB->u.FunctionIoControl.IoControlCode == 0x220003) {
        // 2) 遍历设备栈，定位本设备属于哪个 USB 功能/接口驱动
        pass = 0;
        for (dev = deviceObject; dev; dev = dev->NextDeviceObject) {
            name = dev->DriverObject->DriverName;   // DbgPrint("URB upper drv=%wZ!!!!")
            if (name in { \Driver\hidusb, \Driver\usbhub, \Driver\usbccgp,
                          \Driver\usbvideo, \Driver\DisplayLinkUsbPort, \Driver\MHIKEY10,
                          \Driver\D12TEST, \Driver\usbprint, \Driver\UASPStor,
                          \Driver\usbaudio, \Driver\ksthunk,
                          \Driver\USBSTOR (受 DAT_000143c0 门控) })
                pass = 1;                            // 属已知 USB 栈 → 候选放行
        }

        // 3) 构造并下发一个读设备描述符的 FUNCTION URB (0x88 字节, URB_TYPE 0xB)
        urb = ExAllocatePool(0);
        urb->Length = 0x88; urb->UrbType = 0x88; urb->u.Function.Length = 0x12;
        IoCallDriver(lower, urb);                    // FUN_00011008

        // 4) 从返回的 URB 数据提取设备描述符/名称
        getDevName(dev, &devName);                   // FUN_00011190
        DbgPrint("EasyUsb DevProduct Name =%s, len=%d, idVendor=%d, idProduct=%d, "
                 "bcdDevice=%d, bDeviceClass=%d, bDeviceSubClass=%d, bDeviceProtocol=%d", ...);

        if (!pass) pass = whiteListMatch(devName);   // FUN_00012090
        registerDevice(&g_DevTable, dev, vid, pid, devName, pass, devObj);  // FUN_000122ac

        // 5) 拦截判定
        if (!pass && g_Working /* DAT_00014420 */ != 0) {
            DbgPrint("URB: mydev=%p, lowerdev=%p, urbfunc=%p  Forbid!!!!!!!");
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;        // 0xC0000001
            URB->u.Function.Status = 0x80000700;               // USB_ERROR_GEN_FAIL
            return STATUS_UNSUCCESSFUL;
        }
    }
}
// 否则正常转发
return callNext(Irp);                                          // FUN_00011c98 → IofCallDriver
```

**判定逻辑（`pass` 初始为 0）**：
- **遍历设备栈**：只要栈中出现任一"已知 USB 功能驱动"（`hidusb`/`usbhub`/`usbccgp`/`usbvideo`/`usbaudio`/`usbprint`/`ksthunk`/`UASPStor`/`DisplayLinkUsbPort`/`MHIKEY10`/`D12TEST`）→ 直接 `pass=1`（放行）；
- **`USBSTOR`（存储盘类）**：受 `DAT_000143c0` 门控——`DAT_000143c0==0` 时直接 `pass=1`；否则需 `whiteListMatch(devName)` 命中白名单才 `pass=1`；
- **设备名兜底匹配**：若遍历后 `pass` 仍为 0，则下发一个读设备描述符的 FUNCTION URB，取回设备名（`FUN_00011190`）再 `whiteListMatch` 一次，命中则 `pass=1`；
- 无论结果，均把 `VID/PID/devName/pass/devobj` **登记到全局表** `DAT_00014428`（`FUN_000122ac`，供 `GetUseUsbDev` 上报）；
- **Forbid**：`pass==0` **且** 工作开关 `pw=1`（`DAT_00014420`）→ `STATUS_UNSUCCESSFUL` + URB 状态 `USB_ERROR_GEN_FAIL(0x80000700)`，设备枚举失败 = 设备"看不到/不可用"。

> 归纳：非存储类 USB 设备（键鼠/音频/视频等）默认放行；**重点拦截对象是 `USBSTOR`（移动存储盘）**——当 `DAT_000143c0` 置位且设备名不在白名单时禁止其接入。

## 3. 白名单加载与匹配

**`FUN_00011aac`（ReadWhiteListParameters）**：
```c
ZwOpenKey(hKey, KEY_READ, \\.\Registry\Machine\...\Services\easyusbflt);
ZwQueryValueKey(hKey, "list", REG_*, buf);       // 白名单字符串
DbgPrint("ReadWhiteListParameters whitelist=%s");
parseWhiteList(buf);                             // FUN_000118cc
ZwQueryValueKey(hKey, "pw", REG_*, &v);          // 工作开关 → DAT_00014420
```

**`FUN_000118cc`（parseWhiteList）**：
- 把 `list` 字符串按 **`|`** 分隔成多项；
- 每项 `RtlAnsiStringToUnicodeString` → `RtlUpcaseUnicodeString`（**转大写**）→ `FUN_000120e8` 加入白名单表；
- 匹配时大小写不敏感（`_wcsnicmp` / `FsRtlIsNameInExpression`）。

**`FUN_00012090`（whiteListMatch）**：用设备名/描述符匹配白名单表。
**`FUN_000122ac`（registerDevice）**：把 `VID / PID / devName / pass 标志 / devobj` 登记到全局表 `DAT_00014428`（供 `GetUseUsbDev` 上报"正在使用的设备"）。

## 4. 全局变量

| 全局 | 含义 |
|---|---|
| `DAT_000143c0` | USBSTOR 门控标志（置位时对 USBSTOR 需走白名单匹配，否则直接放行） |
| `DAT_00014420` | **工作开关** `pw`（`1`=拦截生效，`0`=全放行） |
| `DAT_00014428` | 已登记设备表（`GetUseUsbDev` 的数据源） |
| 白名单表 | `FUN_000120e8` 维护，供 `FUN_00012090` 匹配 |

## 5. IOCTL（由 `easyusbctrl.dll` 下发）

| IOCTL | 方向 | 用途 |
|---|---|---|
| `0x9C412404` | in `short[]` | **AddWhiteDevName**：加白名单（设备名数组） |
| `0x9C412408` | out | **GetWhiteDevName**：读白名单 |
| `0x9C41240C` | — | **DelAllWhiteDevName**：清空白名单 |
| `0x9C412410` | out | **StopWorking**：停拦截 |
| `0x9C412414` | out | **StartWorking**：启拦截 |
| `0x9C412418` | out | **GetUseUsbDev**：读已登记使用设备 |
| `0x9C41241C` | out 4B | **IsWorking**：读工作开关 |

> IOCTL 高位 `0x9C41xxxx`：设备类型 `0x9C`、访问/掩码编码，`FILE_DEVICE_UNKNOWN` 私有控制码。

## 6. 关键函数索引（x64）

| 地址 | 职责 |
|---|---|
| `0x16694` 区 | DriverEntry（`OE-Entered the Driver Entry easyusbflt`、`WdmlibInit`） |
| `0x16008`/`0x16244` | AddDevice（挂 `\Driver\USBSTOR`、`IoAttachDeviceToDeviceStack`、`IoCreateSymbolicLink`） |
| `0x1136c` | **URB 拦截 + Forbid 判定** |
| `0x118cc` | parseWhiteList（`\|` 分隔 + 大写化） |
| `0x11aac` | ReadWhiteListParameters（读 `list`/`pw`） |
| `0x1090`/`0x11190` | 下发读描述符 URB / 提取设备名 |
| `0x12090` | 白名单匹配 |
| `0x122ac` | 登记设备到 `DAT_00014428` |
| `0x120e8` | 白名单表插入 |
| `0x11c98` | 正常 IRP 转发（remove-lock + `IofCallDriver`） |

## 7. 与体系的关系

```
DeviceControl.exe / 教师端
  → easyusbctrl.dll（EasyUsb_AddWhiteDevName / StartWorking / ...）
      → \\.\EasyUsbflt   IOCTL 0x9C4124xx
          → easyusbflt.sys（USB 栈过滤 + 描述符读取 + 白名单 Forbid）
```

## 8. 未决项

1. `DAT_000143c0` 的具体触发条件（何种 USBSTOR 场景下走白名单而非直接放行）。
2. `FUN_00011190` 从 FUNCTION URB 回调数据中取"设备名"的确切偏移（`piVar1[0x10..0x12]` = bDeviceClass/SubClass/Protocol，`+0x11` = idVendor 高字节，`+0x46` = idProduct）。
3. 与安装包内旧版（46104 字节，见 `driver-install/easyusbflt_sys.md`）的差异（本顶层版更大，可能含更多 USB 栈驱动名/增强匹配）。

---

*本文覆盖：easyusbflt.sys 指纹与导入、设备对象/符号链接/安全描述符、DriverEntry 与 USBSTOR 挂接、URB 拦截与 Forbid 判定流程、白名单加载（注册表 list/pw）与匹配、全局变量、IOCTL 编目、函数索引、与 easyusbctrl/easyusbinstall 的关系。*