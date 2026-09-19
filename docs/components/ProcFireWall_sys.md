# ProcFireWall.sys 组件深度逆向（进程创建监控驱动）

> 样本：`samples/os-easy/ProcFireWall.sys`（28696 字节，PE32+ x86-64 内核驱动）
> 反编译：Ghidra 12.1.3 headless，15 函数，存档 `/root/ghidra/mmpc/ProcFireWall_run_x64.txt`
> 样本 MD5：`3a391c59a4e1ed85603fd41a045fdeb9`
> 内嵌 PDB：`z:\win_drv\new_drv\procfirewall\procfirewall\objfre_win7_amd64\amd64\ProcFireWall.pdb`
> 另有**同源 x86 架构**样本 `samples/di_flat/ProcFireWall.sys`（=`samples/driverinstall/$_12_/ProcFireWall.sys`，驱动安装程序解包出的内置副本，同样 28696 字节，MD5 `0699ff48828afe868931a5413a1d7bad`；PDB 为同一源码树的 `…objfre_win7_x86\i386\…`），独立分析见 `driver-install/ProcFireWall_sys.md`。二者**同源码同版本，仅目标架构不同**（尺寸相同但架构不同，故 MD5 必然不同）。

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/ProcFireWall.sys` |
| 大小 | 28696 字节 |
| 架构/类型 | PE32+ x86-64 内核驱动（进程创建监控） |
| MD5 | `3a391c59a4e1ed85603fd41a045fdeb9` |
| SHA-256 | `5afdc39c27b4e6e460d104fc061a9ce04ba0cb353332c5a78f41a4690c89556b` | — |
| 内嵌 PDB | `z:\win_drv\new_drv\procfirewall\procfirewall\objfre_win7_amd64\amd64\ProcFireWall.pdb` |

## 1. 定位

**进程创建监控驱动**：用 `PsSetCreateProcessNotifyRoutine` 订阅进程创建事件，把**新进程 PID 排队**，并通过**用户态注册的两个事件对象**通知用户态（DeviceControl），由用户态读取 PID 后决定放行/处理。它是"进程防火墙"的内核**感知**层（决策在用户态）。

## 2. 设备与 DriverEntry（`FUN_00016008`）

| 项 | 值 |
|---|---|
| 设备 | `\Device\devProcFireWall`（`IoCreateDevice` deviceType `0x22`） |
| 符号链接 | `\DosDevices\ProcFireWall`（建/删各一处） |
| 池 | `ExInitializeNPagedLookasideList(tag 'MROP' = 0x50524f4d, size 0x18)` |
| 事件 | `KeInitializeEvent(&DAT_00013238)`；同步用 `ExAcquireFastMutex(&DAT_00013220)` |
| 订阅 | `PsSetCreateProcessNotifyRoutine(FUN_000110d0, 0)`（卸载时传 1 取消） |
| 分发表 | `+0x70`/`+0x80` = 完成例程；`+0xe0` = IRP_MJ_DEVICE_CONTROL（`FUN_00015088`）；`+0x68` = Unload（`FUN_00015008`） |

卸载 `FUN_00015008`：取消订阅 → `ExDeleteNPagedLookasideList` → 删符号链接/设备。

## 3. 进程创建回调（`FUN_000110d0` → `FUN_00011008`）

```
notify(ParentId, ProcessId, Create):
  if Create:  FUN_00011008(ProcessId)   // 入队
              + 若已注册事件 → KeSetEvent / KeWaitForSingleObject
FUN_00011008(pid):
  KeAcquireSpinLockRaiseToDpc
  if 队列计数 < 0x1e (30):
     pop 自 lookaside SList 或按 tag 分配 0x18 字节节点
     node[2]=pid; 挂入双向链表 DAT_00013200/13208; 计数+1; 返回 1
  else: 返回 0（满则丢弃，计数 _DAT_00013154 累加）
  KeReleaseSpinLock
```

即**每创建一个进程，PID 入队（上限 30）**，并可触发事件唤醒用户态。

## 4. IRP_MJ_DEVICE_CONTROL（`FUN_00015088`）

控制码基础 `0x2220xx`；`0x222000`/`0x222008` 分支先做 `"OEDRV ProcFireWall OEDRV_IsPassProcess"` 门控（`FUN_000114b0`；本 build 直接 `return 1`，即放行）：

| IOCTL | 处理 | 语义 |
|---|---|---|
| `0x222000` | `FUN_00011150`：遍历队列→回收；`ObReferenceObjectByHandle(*param_1, 0x100000, ExEventObjectType, …, &DAT_000131c0)` + `param_1[1]` → `DAT_000131c8`；失败打印 `"g_pCommR3Event = NULL status = %x"` | **注册用户态通知事件对**（R3 双向握手事件） |
| `0x222004` | `FUN_000113b4(buf)` → `FUN_000113e0`：加锁遍历队列，把每个节点 PID 写入 `*buf++`，节点回收到 lookaside，计数递减 | **取走待处理的新进程 PID 列表**（用户态逐个决策） |
| `0x222008` | `FUN_00011354`：`ObfDereferenceObject` 两个事件并清零 | **注销通知事件对** |
| 其它 | `STATUS_INVALID_PARAMETER(0xC000000D)`（`-0x3ffffff3`） | — |

缓冲区大小不足时返回 `STATUS_INVALID_BUFFER_SIZE`（`STATUS_INVALID_BUFFER_SIZE` / `-0x3ffffdfa`，见 `FUN_00011150` 打印）。

## 5. 运行模型

```
DeviceControl.exe
  ├─ CreateFile(\\.\ProcFireWall)
  ├─ DeviceIoControl(0x222000, {hEvent_New, hEvent_Done})   // 注册事件对
  ├─ 循环: 等待事件 → DeviceIoControl(0x222004, buf)        // 取新进程 PID 列表
  │        对每个 PID 判白名单/黑名单 → 决策(放行/终止/上报)
  └─ DeviceIoControl(0x222008)                              // 退出时注销
驱动: PsCreateProcessNotify → 入队(≤30) + 置事件
```

这就是"进程防火墙"：内核只负责**感知 + 通知**，**判定与处置在用户态 DeviceControl**（因此规则可热更新，无需改驱动）。

## 6. 与 OEDRV 驱动族的关系

`OEDRV ProcFireWall OEDRV_IsPassProcess` 与 FbdATS / KbFilter / OeNetLimit 同族——统一"进程白名单"语义在**进程维度**的落点（能不能启动/放行某进程）。本 build 中 `FUN_000114b0` 恒返回 1（门控桩化），意味着**进程创建本身不阻止**，实际拦截动作由用户态在读到 PID 后执行（如 `TerminateProcess`）。

## 7. 函数索引

| 地址 | 功能 |
|---|---|
| `0x16008` | DriverEntry（建设备/链接/事件/池 + 订阅进程创建） |
| `0x110d0` | `PsCreateProcessNotifyRoutine` 回调（入队 + 事件） |
| `0x11008` | PID 入队（≤30，lookaside） |
| `0x11150` | IOCTL `0x222000`：注册事件对 + 回收队列 |
| `0x113b4`/`0x113e0` | IOCTL `0x222004`：导出 PID 列表 |
| `0x11354` | IOCTL `0x222008`：注销事件对 |
| `0x15088` | IRP_MJ_DEVICE_CONTROL 分发 |
| `0x15008` | DriverUnload |
| `0x114b0` | IsPassProcess 门控（本 build 恒真） |

## 8. 未决项

1. `0x222004` 队列上限 30 与高并发（批量启动进程）时的丢事件行为（`_DAT_00013154/13158/13160` 计数的掉队统计）；
2. 用户态 DeviceControl 侧对 PID 列表的具体处置策略（放行/终止/上报）——见 DeviceControl_exe.md；
3. 与 `driver-install/` 目录样本（安装程序内置 **x86** 副本）已确认为**同源同版本、仅目标架构不同**（同尺寸、不同 MD5 由此解释）；
4. `ExEventObjectType` 事件对是否为"新进程事件 + 处理完成事件"双向握手（`g_pCommR3Event` 命名暗示 R3 通信）。