# ProcFireWall.sys 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包（`/d3=ProcFireWall`）
> 样本：`samples/di_flat/ProcFireWall.sys`（28696 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_ProcFireWall.sys.txt`（31 函数）
> 安装器：`LoadDriver.exe`（服务名 `ProcFireWall`）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 28696 字节 |
| MD5 | `0699ff48828afe868931a5413a1d7bad` |
| SHA-256 | `5afdc39c27b4e6e460d104fc061a9ce04ba0cb353332c5a78f41a4690c89556b` | — |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x1514f`；DriverEntry = `FUN_00015006` |
| 导入 | `ntoskrnl.exe`、`HAL.dll` |
| PDB | `z:\win_drv\new_drv\procfirewall\procfirewall\objfre_win7_x86\i386\ProcFireWall.pdb` |

## 1. 角色

**进程防火墙驱动**：注册进程创建通知回调，对新建进程做通行判定（`OEDRV_IsPassProcess`），并通过**事件对象与用户态（R3）通信**决定放行/阻断；内部用 SLIST + 非分页 Lookaside 维护待处理队列。

## 2. DriverEntry `FUN_00015006`

```
FUN_000113ea(RegistryPath)
MajorFunction[IRP_MJ_CREATE(0x38)] / [IRP_MJ_CLOSE(0x40)] = LAB_00014006
MajorFunction[IRP_MJ_DEVICE_CONTROL(0x70)]               = FUN_00014078
DriverUnload(0x34)                                       = FUN_0001402a
RtlInitUnicodeString(L"\\Device\\devProcFireWall")
IoCreateDevice(driver, 0, name, FILE_DEVICE_UNKNOWN(0x22), 0, 0, &devObj)
RtlInitUnicodeString(L"\\DosDevices\\ProcFireWall")
IoCreateSymbolicLink(L"\\DosDevices\\ProcFireWall", L"\\Device\\devProcFireWall")
g_Flag0 = 0; g_Flag1 = 1; g_x = 0; g_y = 0
KeInitializeEvent(&g_Event, NotificationEvent(1), FALSE)
g_ListHead = &g_ListHead                       // 自环链表
ExInitializeNPagedLookasideList(&g_Lookaside, 0,0,0, 0xC, 'MORP'(0x50524F4D), 0)
PsSetCreateProcessNotifyRoutine(FUN_000110da, 0)
失败 → 回滚（IoDeleteSymbolicLink + IoDeleteDevice）
```

**卸载**（`FUN_0001402a` 一带）：`PsSetCreateProcessNotifyRoutine(FUN_000110da,1)` → 删符号链接/设备。

## 3. 通信与队列

| 元素 | 说明 |
|---|---|
| `g_pCommR3Event` | 与 R3 通信的事件（`ObReferenceObjectByHandle` + `ExEventObjectType` 从用户句柄取对象） |
| `g_pThreadEvent` | 内核线程等待/唤醒事件 |
| `KeWaitForSingleObject` / `KeSetEvent` | 内核↔用户态同步 |
| `ExInitializeNPagedLookasideList`(tag `'MORP'`) + `Interlocked{Push,Pop}EntrySList` | 待处理进程记录队列（每条 0xC 字节） |
| `DbgPrintEx` / `DbgPrint` | 日志 |

日志串：`g_pThreadEvent = NULL`、`g_pCommR3Event = NULL status = %x`、`status = STATUS_INVALID_BUFFER_SIZE`、`OEDRV ProcFireWall OEDRV_IsPassProcess`。

## 4. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x1514f | entry |
| 0x15006 | DriverEntry |
| 0x110da | **进程创建通知回调**（`PsSetCreateProcessNotifyRoutine`） |
| 0x14078 | IRP_MJ_DEVICE_CONTROL（R3 下发规则/查询） |
| 0x1402a | DriverUnload |
| 0x1139a / 0x113ea | 初始化辅助 |
| 0x1144a / __SEH_prolog4 | 异常/SEH 相关 |

## 5. 未决项

1. 进程创建回调 `FUN_000110da` 与 R3 的完整决策协议（事件名、共享结构、等待超时）需细读。
2. 阻断方式（阻止启动 vs 启动后挂起/结束）待确认。

---

*本文覆盖：ProcFireWall.sys 指纹、DriverEntry（设备/符号链接、IRP 表、事件与 Lookaside 队列、进程通知）、R3 通信元素、函数索引。*