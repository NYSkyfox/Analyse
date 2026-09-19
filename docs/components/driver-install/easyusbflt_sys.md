# easyusbflt.sys 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包（`/d2=easyusbflt`）
> 样本：`samples/di_flat/easyusbflt.sys`（46104 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_easyusbflt.sys.txt`（99 函数）
> 安装器：`easyusbinstall.exe`（另有 `easyusbctrl.dll`：`EasyUsb_StartWorking/StopWorking`）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 46104 字节 |
| MD5 | `2c4e701e4ca2b3e63f837fe75d9d1833` |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x18277`；DriverEntry = `FUN_0001814e` |
| 导入 | `ntoskrnl.exe`、`HAL.dll` |
| PDB | `z:\win_drv\new_drv\easyusb\easyusbflt\objfre_win7_x86\i386\easyusbflt.pdb` |

## 1. 角色

**USB 设备白名单过滤驱动**（USB 上层过滤器，Upper Filter）。挂到 USB 设备栈上，解析 USB 请求块（URB）识别设备 **VID/PID/设备类**，按白名单决定**放行或阻止（Forbid）**，用于管控 U 盘/外设。

## 2. DriverEntry `FUN_0001814e`

```
DbgPrint("OE Entered the Driver Entry easy…")
FUN_00012102(RegistryPath)
if (*InitSafeBootMode != 0) DAT_000141a0 = 1      // 安全模式标记
FUN_00011454(RegistryPath)
MajorFunction 全部默认 = FUN_000115c2
MajorFunction[IRP_MJ_CREATE(0x38)]              = FUN_00015180
MajorFunction[IRP_MJ_CLOSE(0x40)]               = FUN_00015180
MajorFunction[IRP_MJ_DEVICE_CONTROL(0x70)]      = FUN_00015180
MajorFunction[IRP_MJ_CLEANUP(0x80)]             = FUN_00015180
MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL(0x74)] = FUN_00011742   // ← URB 拦截
MajorFunction[IRP_MJ_SYSTEM_CONTROL(0x90)]      = FUN_0001169e
MajorFunction[IRP_MJ_PNP(0xa4)]                 = FUN_00015382
DriverObject->DriverExtension->AddDevice        = FUN_000151dc
DriverUnload(0x34)                              = LAB_00015006
KeInitializeEvent(&g_Event, NotificationEvent(1), FALSE)
ExInitializePagedLookasideList(&g_Lookaside, 0,0,0, 0x110, 'UnBn'(0x626E4255), 0)
return 0
```

- 设备创建用 `WdmlibIoCreateDeviceSecure`（带安全描述符）+ `IoCreateSymbolicLink`。
- 设备扩展 `0x44` 字节，`IoAttachDeviceToDeviceStack` 挂到目标 USB 设备。

## 3. 设备识别与处置（调试串）

| 串 | 含义 |
|---|---|
| `ReadWhiteListParameters whitelist=%s` | 读取白名单参数 |
| `EasyUsb DevProduct Name =%s, len=%d, idVendor=%d, idProduct=%d, bcdDevice=%d, bDeviceClass=%d, bDeviceSubClass=%d, bDeviceProtocol=%d` | 解析出的 USB 设备描述（VID/PID/类） |
| `URB: mydev=%p, lowerdev=%p, urbfunc=%p  Forbid!!!!!!!` | **命中禁止 → 拦截 URB** |
| `URB upper drv=%wZ!!!!` | 目标上层驱动 |

- **关注/挂接的 USB 类驱动**：`\Driver\USBSTOR`、`\Driver\UASPStor`、`\Driver\usbhub`、`\Driver\usbccgp`、`\Driver\usbprint`、`\Driver\usbvideo`、`\Driver\usbaudio`、`\Driver\ksthunk`、`\DRIVER\hidusb`、`\Driver\MHIKEY10`、`\Driver\D12TEST`、`\Driver\DisplayLinkUsbPort` 等。
- **设备注册表**：`\Registry\Machine\System\CurrentControlSet\Control\Class`，读取 `Class`、`ClassGUID`、`DeviceType`、`DeviceCharacteristics`、`Exclusive`、`Security`、`Properties`、`NoUseClass`、`NoDisplayClass` 等，用于判定设备类别与可显示性。

## 4. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x18277 | entry |
| 0x1814e | DriverEntry |
| 0x151dc | AddDevice（挂 USB 栈） |
| 0x11742 | IRP_MJ_INTERNAL_DEVICE_CONTROL（**URB 拦截/放行**） |
| 0x15180 | CREATE/CLOSE/DEVICE_CONTROL/CLEANUP |
| 0x15382 / 0x1169e | PNP / SYSTEM_CONTROL |
| 0x115c2 | 默认 IRP 处理 |
| WdmlibIoCreateDeviceSecure | 设备安全创建 |
| 0x12102 / 0x11454 / 0x18006 / 0x180e0 | 初始化（含安全模式、白名单） |

## 5. 未决项

1. 白名单来源与格式（注册表 / 文件 / IOCTL 下发）与 `whitelist=%s` 的解析路径需细读。
2. 拦截粒度（按类禁止 vs 按 VID/PID 允许）待确认。
3. `easyusbctrl.dll` 的 `EasyUsb_StartWorking/StopWorking` 与本驱动的联动方式。

---

*本文概述：easyusbflt.sys 指纹、DriverEntry（USB 设备栈挂接、URB 拦截、Lookaside）、USB 设备识别字段与禁止逻辑、关注类驱动与注册表、函数索引。*