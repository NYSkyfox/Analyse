# KbFilter.sys 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包（`uninstall_kbfilter.bat` 中 `/d1=KbFilter`）
> 样本：`samples/di_flat/KbFilter.sys`（33816 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_KbFilter.sys.txt`（46 函数）
> 安装器：`KbDriver.exe`（服务名 `KbFilter`）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 33816 字节 |
| MD5 | `7c42b6343b7e400d074298382bd6485d` |
| SHA-256 | `03896f68c0ac88f3920e5017abc90bd2a79af91d4523e21e8310d3b7d08ec15b` | — |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x406140`；DriverEntry = `FUN_00406000` |
| 导入 | `ntoskrnl.exe`、`HAL.dll` |

## 1. 角色

**键盘过滤驱动（键盘上层过滤）**——挂在键盘类驱动栈上，过滤 `IRP_MJ_READ` 返回的键盘输入，用于**按键屏蔽/锁定**（考场防作弊）。代码明显源自微软示例 `Ctrl2cap`（日志自报 `Ctrl2cap.SYS: entering DriverEntry`）。

## 2. DriverEntry `FUN_00406000`

```
DbgPrint("Ctrl2cap.SYS: entering DriverEntry\n")
FUN_00401d32(RegistryPath)                       // 读注册表配置
for (i=0;i<0x1b;i++) MajorFunction[i] = FUN_00405070   // 默认处理
MajorFunction[IRP_MJ_CREATE(0x38)]        = FUN_004016d0
MajorFunction[IRP_MJ_CLOSE(0x40)]         = FUN_004015d0
MajorFunction[IRP_MJ_READ(0x44)]          = FUN_00401000   // ← 键盘输入过滤
MajorFunction[IRP_MJ_DEVICE_CONTROL(0x70)]= FUN_00401820
MajorFunction[IRP_MJ_SYSTEM_CONTROL(0x90)]= FUN_00405130
MajorFunction[IRP_MJ_PNP(0xa4)]           = FUN_004050c0
DriverObject->DriverUnload(0x34)          = FUN_00405160
DriverObject->DriverExtension->AddDevice  = FUN_00405000      // 挂键盘设备栈
RtlInitUnicodeString(L"\\Device\\DevOeKbdFilter")
RtlInitUnicodeString(L"\\DosDevices\\OeKbdFilter")
IoCreateDevice(type = FILE_DEVICE_KEYBOARD(0xB))
IoCreateSymbolicLink(L"\\DosDevices\\OeKbdFilter", L"\\Device\\DevOeKbdFilter")
devObj->Flags |= 0x2004；devObj->Flags &= ~0x80   // DO_BUFFERED_IO 等
FUN_00401dd0(...) x3                              // 初始化 3 个同步对象/回调
日志文件：\SystemRoot\log.txt
```

- 另建一个带 4 字节扩展的内部设备并 `IoAttachDeviceToDeviceStack` 到键盘设备对象（`FUN_00401c66` 一带），成为键盘栈的上层过滤器。

## 3. 键盘输入过滤

**`FUN_00401000`（IRP_MJ_READ）**：为 IRP 设完成例程 `FUN_00401050` 后 `IofCallDriver` 下发。

**`FUN_00401050`（完成例程）**：

```
if (IoStatus.Status >= 0) {
  n = Information / 0xC;                     // KEYBOARD_INPUT_DATA 每条 0xC 字节
  for (i=0;i<n;i++) {
     rec = buf + i*0xC;                      // {MakeCode, Flags, Reserved, ExtraInformation}
     if (g_LogEnabled) FUN_00401c66(MakeCode, Flags);   // 记录
     switch (g_FilterMode) { ... }           // 按键处理（屏蔽/替换/放行）
  }
}
```

- 过滤模式取自 `DAT_00404000`（由 IOCTL `FUN_00401820` 设置），支持多种策略分支。
- 键值处理在 `FUN_00401c66` 等函数中实现。

## 4. 与上层联动

- `DeviceControl` 的 `CtrlCode` 位 `0x0002` = `Enable KC`：构造 `{windowName:"UIStudentMainWnd", keys:[…]}` 并写 `keywords.json`，正是**下发给本键盘过滤驱动的按键规则**。
- 卸载由 `uninstall_kbfilter.bat` → `DriverInstall.exe /OPT=uninst /d1=KbFilter` 完成。

## 5. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x406140 | entry |
| 0x406000 | DriverEntry |
| 0x405000 | AddDevice（挂键盘栈） |
| 0x401000 | IRP_MJ_READ（设完成例程） |
| 0x401050 | 键盘输入完成例程（按键过滤） |
| 0x4016d0 / 0x4015d0 | IRP_MJ_CREATE / CLOSE |
| 0x401820 | IRP_MJ_DEVICE_CONTROL（设置过滤规则/模式） |
| 0x405130 / 0x4050c0 / 0x405160 | SYSTEM_CONTROL / PNP / Unload |
| 0x401c66 | 按键处理/记录 |
| 0x401dd0 | 初始化同步/回调 |

## 6. 未决项

1. `g_FilterMode`（`DAT_00404000`）各取值对应的按键策略需逐分支细读 `FUN_00401050`。
2. 过滤规则来源（注册表 `KbDriver.exe` 写入 vs IOCTL 下发）待确认。

---

*本文覆盖：KbFilter.sys 指纹、DriverEntry（键盘设备/符号链接、IRP 表、AddDevice）、键盘输入完成例程与 KEYBOARD_INPUT_DATA 过滤、与 DeviceControl `Enable KC` 的联动、函数索引。*