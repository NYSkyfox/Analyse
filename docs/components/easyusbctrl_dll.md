# easyusbctrl.dll 组件深度逆向（USB 管控控制库）

> 样本：`samples/os-easy/x86/easyusbctrl.dll`（60416 字节）、`samples/os-easy/x64/easyusbctrl.dll`（72416 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/easyusbctrl`（x86）
> 反编译存档：`/root/ghidra/mmpc/easyusbctrl_x86.txt`（250 函数）
> 关联：`easyusbflt_sys.md`（内核驱动）、`easyusbinstall_exe.md`（安装器）、`DeviceControl_exe.md`（上层）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | x86 | x64 |
|---|---|---|
| 大小 | 60416 字节 | 72416 字节 |
| MD5 | `ebe7028bfd233ac093b691c2443a568a` | `be02f56652576d866e3a607ca70104c2` |
| SHA-256 | `0d2df5fe7a359d56fabbcb851c45b51ad673ceced3729c1ed03220bbca23cc27` | `18b467e09572c100411f6e6d85fb89a1ae887da3725b35d9ce219d754641336f` |
| 格式 | PE32 DLL（`pei-i386`） | PE32+ DLL（`pei-x86-64`） |
| ImageBase | `0x10000000` | `0x180000000` |
| 入口点 | `0x100022de` | `0x180002698` |

**导入**：`KERNEL32`、`ADVAPI32`、`SHLWAPI`（`SHSetValueW/SHGetValueW/SHDeleteKeyW/SHDeleteValueW`）——无其它第三方库，**自包含**。

**导出（11 个，全部 `EasyUsb_*`，C 命名）**：

| # | 导出 | 行为 |
|---|---|---|
| 0 | `EasyUsb_AddWhiteDevName(short*, uint)` | 加白名单设备名（→ IOCTL `0x9C412404` + 写注册表 `list`） |
| 1 | `EasyUsb_DelAllWhiteDevName()` | 清空白名单（→ IOCTL `0x9C41240C` + `SHDeleteValueW(...,L"list")`） |
| 2 | `EasyUsb_GetUseUsbDev(void*, uint)` | 读"正在使用的 USB 设备"（→ IOCTL `0x9C412418`） |
| 3 | `EasyUsb_GetWhiteDevName(void*, size_t)` | 读白名单（→ IOCTL `0x9C412408`） |
| 4 | `EasyUsb_Intall(void)` | 安装驱动（装 .sys + 注册服务 + 挂 UpperFilters） |
| 5 | `EasyUsb_IsDriverLoading(void*)` | 驱动是否加载（`CreateFileW(\\.\EasyUsbflt)` 是否成功） |
| 6 | `EasyUsb_IsIntall(void*)` | 服务是否已注册（`OpenServiceW("easyusbflt")`） |
| 7 | `EasyUsb_IsWorking(void*)` | 是否工作（→ IOCTL `0x9C41241C`） |
| 8 | `EasyUsb_StartWorking(void)` | 启拦截（→ IOCTL `0x9C412414` + `SHSetValueW(pw=1)`） |
| 9 | `EasyUsb_StopWorking(void)` | 停拦截（→ IOCTL `0x9C412410` + `SHSetValueW(pw=0)`） |
| 10 | `EasyUsb_UnIntall(void)` | 卸载（停服务/删注册 + 移 .sys + 摘 UpperFilters） |

> 注：`Intall`/`UnIntall`/`IsIntall` 是源码拼写（install 少一个 l），保持原名。

---

## 1. 角色概述

`easyusbctrl.dll` 是 **`easyusbflt.sys` 的用户态控制库**：把"USB 白名单/启停/安装"等教学管控操作封装成 11 个 `EasyUsb_*` API。每个 API 分两部分：

1. **`CreateFileW(L"\\\\.\\EasyUsbflt", GENERIC_READ|GENERIC_WRITE(0xC0000000), 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)`** → `DeviceIoControl(\\.\EasyUsbflt, IOCTL, ...)` 驱动即时生效；
2. **写注册表** `HKLM\SYSTEM\CurrentControlSet\Services\easyusbflt`（`list`/`pw`），使驱动重启后仍读回配置（`easyusbflt.sys` 的 `ReadWhiteListParameters` 从该处加载）。

## 2. 设备通信（DeviceIoControl）

| IOCTL | 导出 | 输入/输出 |
|---|---|---|
| `0x9C412404` | AddWhiteDevName | in `short[]`(len=count) |
| `0x9C412408` | GetWhiteDevName | out |
| `0x9C41240C` | DelAllWhiteDevName | — |
| `0x9C412410` | StopWorking | out |
| `0x9C412414` | StartWorking | out |
| `0x9C412418` | GetUseUsbDev | out (len>3) |
| `0x9C41241C` | IsWorking | out 4B |

（与 `easyusbflt_sys.md` §5 的驱动侧编目一一对应。）

## 3. 安装 / 卸载

### `EasyUsb_Intall`（x86 `0x100011f0`）
```c
IsWow64Process(本进程);            // 若 32 位进程运行在 64 位系统上 → 直接返回（不装，避免跨位装错 .sys）
if (!IsIntall()) {
    UnIntall();                    // 先清旧
    copySysToDrivers();            // FUN_10001020：本目录 easyusbflt.sys → C:\Windows\system32\drivers\
    createService("easyusbflt", ..., drivers\easyusbflt.sys);  // FUN_10001cd0
    // 挂接到"磁盘驱动器/存储"类 GUID 的 UpperFilters：
    //   HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\UpperFilters
    //   追加 "easyusbflt"（多值串）
    SHSetValueW(...Class\{36FC9E60-...}, "UpperFilters", REG_MULTI_SZ, "easyusbflt");
}
```

> `{36FC9E60-C465-11CF-8056-444553540000}` 是 **SCSI/存储盘（"Disk Drive"）类 GUID**——即把 easyusbflt 作为**上层过滤驱动**挂到存储设备栈，正是驱动侧挂 `\Driver\USBSTOR` 的注册依据。

### `EasyUsb_UnIntall`（x86 `0x10001490`）
```c
IsWow64Process 同上;
SHDeleteKeyW(HKLM, "SYSTEM\CurrentControlSet\Services\easyusbflt");   // 删服务键（含 list/pw）
DeleteFileW(Windows\system32\drivers\easyusbflt.sys);                // 删驱动文件
从 Class\{36FC9E60-...}\UpperFilters 多值串里摘除 "easyusbflt";        // 若为空则 SHDeleteValueW
```

### `copySysToDrivers`（x86 头部函数）
`GetModuleFileNameW` 取本 DLL 目录 → `easyusbflt.sys` → `CreateFileW` 校验存在 → `GetWindowsDirectoryW` → `CopyFileW(本目录\easyusbflt.sys, C:\Windows\system32\drivers\easyusbflt.sys)`。

## 4. 状态查询

| 导出 | 判定方式 |
|---|---|
| `IsDriverLoading` | `CreateFileW(\\.\EasyUsbflt)` 成功 = 驱动对象存在 |
| `IsIntall` | `OpenSCManagerW` + `OpenServiceW(L"easyusbflt", 0xF01FF)` 成功 |
| `IsWorking` | IOCTL `0x9C41241C` 读 `pw` 返回值 |

## 5. 注册表布局（写/读）

```
HKLM\SYSTEM\CurrentControlSet\Services\easyusbflt
  ├─ (服务主键，CreateServiceW 生成：ImagePath=\SystemRoot\system32\drivers\easyusbflt.sys)
  ├─ list   : REG_MULTI_SZ  白名单设备名（| 或 多值）
  └─ pw     : REG_DWORD     工作开关 1/0
HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}
  └─ UpperFilters : REG_MULTI_SZ  追加/摘除 "easyusbflt"
```

## 6. 关键函数索引（x86）

| 地址 | 职责 |
|---|---|
| 0x10001020 区 | copySysToDrivers（.sys → drivers） |
| 0x100011f0 | `EasyUsb_Intall`（装 .sys+服务+UpperFilters） |
| 0x10001490 | `EasyUsb_UnIntall`（删服务键+.sys+UpperFilters） |
| 0x10001710 | `IsDriverLoading`（打开 `\\.\EasyUsbflt`） |
| 0x10001760 | `IsIntall`（OpenServiceW） |
| 0x100017e0 | `AddWhiteDevName`（IOCTL 0x9C412404 + 写 list） |
| 0x100018d0 | `GetWhiteDevName`（IOCTL 0x9C412408） |
| 0x10001960 | `DelAllWhiteDevName`（IOCTL 0x9C41240C + 删 list） |
| 0x100019f0 | `GetUseUsbDev`（IOCTL 0x9C412418） |
| 0x10001a70 | `StopWorking`（IOCTL 0x9C412410 + pw=0） |
| 0x10001b00 | `StartWorking`（IOCTL 0x9C412414 + pw=1） |
| 0x10001b90 | `IsWorking`（IOCTL 0x9C41241C） |
| 0x10001c20/0x10001cd0 | 路径格式化 / CreateService 封装 |

## 7. 与体系的关系

```
DeviceControl.exe（CtrlCode 0x...=USB 管控）或 教师端
  → easyusbctrl.dll（11 个 EasyUsb_*：白名单/启停/安装/查询）
      ├─ DeviceIoControl(\\.\EasyUsbflt, 0x9C4124xx)  → easyusbflt.sys（即时）
      └─ 注册表 Services\easyusbflt\{list,pw} / Class\{36FC9E60-...}\UpperFilters（持久）
```

## 8. 未决项

1. `AddWhiteDevName` 写入的 `list` 是**覆盖**还是**追加**（`SHSetValueW` 语义为覆盖单值；驱动侧 `parseWhiteList` 按 `|` 分隔 → 白名单以 `|` 串形式整存）。
2. `GetUseUsbDev` 输出结构（驱动侧 `DAT_00014428` 登记表序列化格式）。
3. 安装包内旧版 easyusbinstall.exe（135992 字节）与本控制库安装逻辑的异同（本 DLL 自带安装，exe 为独立命令行安装器）。

---

*本文覆盖：easyusbctrl.dll 指纹与 11 导出、设备 `\\.\EasyUsbflt` 通信与 IOCTL 编目、安装/卸载（.sys→drivers + 服务 + 存储类 UpperFilters）、状态查询、注册表布局、函数索引、与 easyusbflt.sys/easyusbinstall.exe 的关系。*