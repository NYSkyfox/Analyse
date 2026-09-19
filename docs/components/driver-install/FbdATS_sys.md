# FbdATS.sys 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `FbdATS.sys`（同时被释放到 `$SYSDIR/drivers`）
> 样本：`samples/di_flat/FbdATS.sys`（38936 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_FbdATS.sys.txt`（78 函数）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 38936 字节 |
| MD5 | `8094dc20609d439e21d50bda45871430` |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x16472` |
| 导入 | `ntoskrnl.exe`、`HAL.dll` |
| 安装 | `InstallFbdATS.exe` / `InstallEx.exe`（服务名 `FbdATS`），亦由 DriverInstall 直接放入 `System32\drivers` |

## 1. 角色

**设备/文件系统过滤驱动**——以 `SFilterOEAssets` 名注册为文件系统过滤器，同时创建控制设备 `FbdAssets`，用于**设备资产管控**（枚举并识别设备类型，按策略处置/隐藏），并带进程通行校验（`OEDRV_IsPassProcess`）。

## 2. DriverEntry `FUN_0001614e`

```
FUN_00016006 / FUN_000160e0 / FUN_000117dc(RegistryPath)   // 初始化
RtlInitUnicodeString(L"\\FileSystem\\Filters\\SFilterOEAssets")
IoCreateDevice(driver, 0, name, FILE_DEVICE_DISK_FILE_SYSTEM(8), FILE_DEVICE_SECURE_OPEN(0x100), 0, &g_Device)
   若返回 STATUS_OBJECT_NAME_COLLISION(0xC0000035) → 回退用 L"\\FileSystem\\SFilterOEAssets" 再建
RtlInitUnicodeString(L"\\DosDevices\\FbdAssets")  → IoCreateSymbolicLink
// 分发例程
MajorFunction[IRP_MJ_CREATE(0x38)]        = FUN_00014914
MajorFunction[IRP_MJ_CREATE_NAMED_PIPE(0x3c)] = FUN_00014914
MajorFunction[0x84]                        = FUN_00014914
MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL(0x6c)] = FUN_000154c4
MajorFunction[IRP_MJ_READ(0x44)]           = FUN_000110d6
MajorFunction[IRP_MJ_WRITE(0x48)]          = FUN_00011142
MajorFunction[IRP_MJ_DEVICE_CONTROL(0x70)] = FUN_000113fe
其余默认 FUN_00011006
// 分配 0x70 字节回调表（池标签 'SFl' = 0x6C754653）
p = ExAllocatePoolWithTag(0, 0x70, 'SFl')
p[0]=0x70; p[1..]=FUN_0001400e,1405a,140a6,140f2,14136,1417a,141ca,14214,14258,1429c,
               ... 14a96,142ec,14330,111fc,1437a   // FS_FILTER_CALLBACKS 风格
```

## 3. 设备枚举与识别

- 使用 `IoEnumerateDeviceObjectList` / `IoGetDiskDeviceObject` / `IoGetAttachedDeviceReference` / `IoAttachDeviceToDeviceStackSafe` / `FsRtlRegisterFileSystemFilterCallbacks`。
- 内置 **FILE_DEVICE_* 名称表**：
  `TERMSRV, SERENUM, DFS_VOLUME, DFS_FILE_SYSTEM, FULLSCREEN_VIDEO, SMARTCARD, CHANGER, MASS_STORAGE, MODEM, BUS_EXTENDER, BATTERY, NETWORK_REDIRECTOR, 8042_PORT, WAVE_OUT, WAVE_IN, VIRTUAL_DISK, VIDEO, UNKNOWN, TRANSPORT, TAPE_FILE_SYSTEM, STREAMS, SOUND` → 用于按设备类型分类处置。
- 关注目标设备对象：`\Device\CdRom0`、`\Device\CdRom`、`\Device\RawCdRom`、`\Device\RawDisk`、`\Device\HarddiskVolume[1]`、`\Device\venetdisk`、`\Driver\VolSnap`、`\FileSystem\Fs_Rec`、`\??\C:`。

## 4. 日志 / 判定串

| 串 | 含义 |
|---|---|
| `OEDRV FbdATS OEDRV_IsPassProcess` | 进程通行校验（放行） |
| `OEDRV OEDRV_IsPassProcess not and denied` | 通行校验失败 → 拒绝 |
| `\Device\venetdisk` | 虚拟磁盘设备（疑似需隐藏/管控对象） |

## 5. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x16472 | entry |
| 0x1614e | DriverEntry（建设备/符号链接/挂 IRP/建回调表） |
| 0x16006 / 0x160e0 / 0x117dc | 初始化辅助 |
| 0x11006 | 默认 IRP 处理 |
| 0x14914 | CREATE/CREATE_NAMED_PIPE 处理 |
| 0x154c4 | IRP_MJ_FILE_SYSTEM_CONTROL |
| 0x110d6 / 0x11142 | IRP_MJ_READ / WRITE |
| 0x113fe | IRP_MJ_DEVICE_CONTROL |
| 0x1449 / 0x1982 / 0x2161 / 0x2288 | `IoAttachDeviceToDeviceStack` 装载路径 |
| 0x2412 | `FsRtlRegisterFileSystemFilterCallbacks` |
| 0x1400e…0x1437a | 回调表条目（挂载/卸载/设备处置） |

## 6. 未决项

1. 各回调（0x1400e…1437a）的精确语义（挂载、设备隐藏、读写拦截）需逐函数细读。
2. 与白名单/通行判定的数据来源（注册表? 共享内存? 用户态 IOCTL?）待确认。
3. `SFilterOEAssets` 属**传统文件系统过滤**（非 minifilter），因此在 `fltmc` 中不可见。

---

*本文覆盖：FbdATS.sys 指纹、DriverEntry（设备名双候选、符号链接 FbdAssets、IRP 表、0x70 回调表）、设备枚举与 FILE_DEVICE_* 类型表、进程通行判定、函数索引。*