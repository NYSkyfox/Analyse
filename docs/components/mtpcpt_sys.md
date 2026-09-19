# mtpcpt.sys 组件深度逆向

> 样本：`samples/os-easy/x64/mtpcpt.sys`（30744 字节）、`samples/os-easy/x86/mtpcpt.sys`（28184 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mtpcpt-analysis`（x64）、`/projects/mtpcptx86`（x86）
> 反编译存档：`/root/ghidra/mmpc/mtpcpt_x64_all.txt`（28 函数）、`mtpcpt_x86_all.txt`（23 函数）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | x64 | x86 |
|---|---|---|
| 大小 | 30744 字节 | 28184 字节 |
| MD5 | `081fed6acc20db5caa83a27092bee64d` | `9f04b1c9a78135f62c60f6a575114174` |
| SHA-256 | `423daffd25d201990e479bc3c900c60d5d3181172e95393ba4ceb6c813d2756a` | `d1306d017d672774c921e99791fd834e66ac0d60869520b8d6f931bea3f3d8b4` |
| 格式 | PE32+ 内核驱动（`pei-x86-64`） | PE32 内核驱动（`pei-i386`） |
| ImageBase | `0x140000000` | `0x400000` |
| 入口点 | `0x1400011a0` | `0x401140` |
| PDB | `E:\yzj\master\10.9\Source\Teacher\Release\mtpcpt.pdb`（两版同源） | 同左 |

**框架**：KMDF（依赖 `WDFLDR.SYS`，`WdfVersionBind/Unbind`；代码含 `FxStub*` 桩）。
**导入**：`ntoskrnl.exe` —— `IoCreateDevice`、`IoCreateSymbolicLink`、`IoDeleteDevice`、`IoDeleteSymbolicLink`、`ObRegisterCallbacks`、`ObUnRegisterCallbacks`、`ObGetFilterVersion`、`PsGetProcessId`、`PsProcessType`、`RtlInitUnicodeString`、`RtlCopyUnicodeString`、`IofCompleteRequest`、`DbgPrint`。

---

## 1. 角色概述

`mtpcpt.sys` 是 Os-Easy 的**进程保护内核驱动**（服务名 `ssdtTookit`，由 AntiHelper.dll 安装），提供设备 `\\.\mtpcpt_link`。它：

1. 创建控制设备 `\Device\mtpcpt` + 符号链接 `\??\mtpcpt_link`；
2. 通过 `ObRegisterCallbacks` 注册**进程对象回调**，对白名单内 PID 的句柄申请**剥离高权限位**；
3. 用 `IRP_MJ_DEVICE_CONTROL` 接受 AntiHelper 的"加/删进程"指令。

> 尽管调试前缀写作 `[SSDTTookit]`，实现**并非 SSDT Hook**，而是标准的 `ObRegisterCallbacks` 进程保护。

---

## 2. DriverEntry（x86 `FUN_004012ec` / x64 `FUN_140001450`）

```
DbgPrint("[SSDTTookit] DriverEntry\n")
RtlInitUnicodeString(&dev,  L"\\Device\\mtpcpt")
RtlInitUnicodeString(&link, L"\\??\\mtpcpt_link")
IoCreateDevice(driver, extSize=8(x86)/0x10(x64), &dev,
               FILE_DEVICE_UNKNOWN(0x22), 0, Exclusive=1, &devObj)
   失败 → DbgPrint("[mtpcpt] IoCreateDevice FALSE: %.8X")，返回
devObj->Flags |= DO_BUFFERED_IO(0x4)          // 使用缓冲 I/O
devObj->DriverObject->... 复制设备名到扩展
IoCreateSymbolicLink(&link, &dev)              // 暴露用户态可达的 \??\mtpcpt_link
   失败 → DbgPrint("...IoCreateSymbolicLink FALSE") + IoDeleteDevice
devObj->Flags &= ~DO_DEVICE_INITIALIZING(0x80)
driver->Flags |= 0x20
// 挂分发例程（x86 offset / x64 offset）
DriverUnload          = FUN_004014c0 / FUN_140001700
IRP_MJ_CREATE  (0)    = FUN_00401560 / FUN_1400017c0
IRP_MJ_CLOSE   (2)    = FUN_00401560 / FUN_1400017c0
IRP_MJ_DEVICE_CONTROL = FUN_004015a0 / FUN_140001810
// 注册进程对象回调
OB_CALLBACK_REGISTRATION reg = {
    .Version = ObGetFilterVersion(),
    .OperationRegistrationCount = 1,
    .Altitude = L"321000",
    .RegistrationContext = NULL,
    .OperationRegistration = &opReg };
OB_OPERATION_REGISTRATION opReg = {
    .ObjectType  = PsProcessType,
    .Operations  = 3,                 // OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
    .PreOperation  = FUN_00401230 / FUN_140001350,
    .PostOperation = NULL };
ObRegisterCallbacks(&reg, &g_CallbackRegistration);   // 失败 → IoDeleteDevice
```

卸载 `FUN_004014c0` / `FUN_140001700`：`ObUnRegisterCallbacks(g_CallbackRegistration)` → `IoDeleteSymbolicLink` → `IoDeleteDevice`。

---

## 3. 进程对象回调（核心保护逻辑）

**预操作回调** `FUN_00401230` / `FUN_140001350`（`OB_PRE_OPERATION_INFORMATION *info`）：

```c
pid = PsGetProcessId(info->Object);            // param_2[2]（x86）/ *(param_2+2)（x64）
if (IsProtectedPid(pid) && info->Operation == OB_OPERATION_HANDLE_CREATE /*1*/) {
    ACCESS_MASK *acc = &info->Parameters->CreateHandleInformation.DesiredAccess;
    if (*acc & PROCESS_TERMINATE(0x0001))       *acc &= ~0x0001;
    if (*acc & PROCESS_VM_OPERATION(0x0008))    *acc &= ~0x0008;
    if (*acc & PROCESS_VM_READ(0x0010))         *acc &= ~0x0010;
    if (*acc & PROCESS_VM_WRITE(0x0020))        *acc &= ~0x0020;
}
return STATUS_SUCCESS;
```

效果：**对被保护进程，任何调用者申请句柄时都无法获得"结束进程"与"进程内存读/写/操作"权限**，
→ 阻断 `TerminateProcess`、内存转储、代码注入、远程 API Hook 等。仅命中 `HANDLE_CREATE`；虽注册了 `HANDLE_DUPLICATE`，但该分支不改权限。

`IsProtectedPid(pid)` = `FUN_00401518`(x86) / `FUN_140001770`(x64)：在**全局 PID 数组**中线性查找。

---

## 4. IOCTL 接口（`IRP_MJ_DEVICE_CONTROL` 处理）

处理函数 `FUN_004015a0` / `FUN_140001810`（`IRP *Irp`）：

```
stack = IoGetCurrentIrpStackLocation(Irp)
code  = stack->Parameters.DeviceIoControl.IoControlCode
len   = stack->Parameters.DeviceIoControl.InputBufferLength
buf   = Irp->AssociatedIrp.SystemBuffer          // DO_BUFFERED_IO

if (code == 0x22A400 && len == 4) {              // 加保护
    pid = *(DWORD*)buf;
    if (pid 不在数组) 放入首个空槽;               // 数组满(8)则忽略
    Status = 0;
}
else if (code == 0x22A404 && len == 4) {         // 解除保护
    pid = *(DWORD*)buf;  从数组清除匹配项;
    Status = 0;
}
else Status = STATUS_INVALID_PARAMETER(0xC000000D);

Irp->IoStatus.Status = Status;  Irp->IoStatus.Information = 0;
IofCompleteRequest(Irp, IO_NO_INCREMENT);
```

- `IRP_MJ_CREATE` / `IRP_MJ_CLOSE` 处理：直接置 Status=0、Information=0 并完成（`FUN_00401560` / `FUN_1400017c0`）。
- 设备用 **DO_BUFFERED_IO**，输入经 `SystemBuffer` 传入。

### IOCTL 编码

| IOCTL | DeviceType | Access | Function | Method | 含义 |
|---|---|---|---|---|---|
| `0x22A400` | 0x22（FILE_DEVICE_UNKNOWN） | 1（FILE_WRITE_ACCESS） | 0x900 | 0（METHOD_BUFFERED） | 保护 PID |
| `0x22A404` | 同上 | 同上 | 0x901 | 同上 | 解除 PID |

（与 AntiHelper.dll 完全对应，见 `AntiHelper_dll.md` §2.1–2.3。）

---

## 5. 全局数据结构

| 符号 | 说明 |
|---|---|
| `DAT_0040304c[8]`（x86）/ `DAT_140003098[8]`（x64） | **被保护 PID 数组，容量 8**，`.data` 零初始化 |
| `DAT_004038c8` / `DAT_140003f68` | `ObRegisterCallbacks` 返回的注册句柄 |

即：**最多同时保护 8 个进程**（去重、满则丢弃新项）。

---

## 6. 闭环：MMPC → AntiHelper → mtpcpt

```
MMPC.exe
  └─ LoadLibraryW("AntiHelper.dll")
       └─ AntiHelper DllMain(PROCESS_ATTACH)
            └─ 安装并启动服务 ssdtTookit（mtpcpt.sys）   ← 本驱动
                 ├─ 创建 \Device\mtpcpt / \??\mtpcpt_link
                 └─ ObRegisterCallbacks(PsProcessType, PreOp)
  └─ AddProcessPid(pid)  → CreateFileA("\\.\mtpcpt_link") → DeviceIoControl(0x22A400)
       └─ mtpcpt: 把 pid 加入保护数组 → 句柄回调剥离危险权限
  └─ DelProcessPid(pid)  → DeviceIoControl(0x22A404) → 从数组移除
```

`protect.map` = `Student.exe`（被守护的主目标），MMPC 拿到其 PID 后调 `AddProcessPid` 保护。

---

## 7. 关键函数索引

| x86 | x64 | 职责 |
|---|---|---|
| 0x401140 | 0x1400011a0 | entry（KMDF 桩 → `_FxDriverEntryWorker`） |
| 0x4012ec | 0x140001450 | DriverEntry（建设备 + 注册回调） |
| 0x4014c0 | 0x140001700 | DriverUnload（注销回调 + 删符号链接/设备） |
| 0x401230 | 0x140001350 | ObPreOperation 回调（剥离权限位） |
| 0x401518 | 0x140001770 | IsProtectedPid（查数组） |
| 0x40150a | 0x14000175c | 取 IRP 当前栈位置 |
| 0x4015a0 | 0x140001810 | IRP_MJ_DEVICE_CONTROL（Add/Del PID） |
| 0x401560 | 0x1400017c0 | IRP_MJ_CREATE / IRP_MJ_CLOSE |

---

## 8. 字符串 / 常量表

| 内容 | 用途 |
|---|---|
| `\Device\mtpcpt` | 设备名 |
| `\??\mtpcpt_link` | 符号链接（用户态 `\\.\mtpcpt_link`） |
| `321000` | `ObRegisterCallbacks` 的 **Altitude** |
| `[SSDTTookit] DriverEntry\n`、`[mtpcpt] DeviceIoControl\n`、`Add Pid:%d\n`、`Del Pid:%d\n` 等 | `DbgPrint` 调试串（仅 x86 版保留明显明文字符串） |
| `[mtpcpt] IoCreateDevice/IoCreateSymbolicLink [SUCCESS\|FALSE]` | 初始化日志 |

> 注：x86 版以 `/n`（斜杠 n）书写换行符，属源码风格，非错误。

---

## 9. 未决项

1. **`Student.exe` 端如何触发保护**：MMPC 的 3s 保活拿到 `Student.exe` PID 后 `AddProcessPid`——需在运行态确认是否还有其它组件（如 Student 自身）也下 PID。
2. 数组容量 8 对应的实际受保护进程集合（是否仅 `Student.exe` + MMPC 自身）待运行态枚举。
3. x86 版 `DbgPrint` 明文齐全，x64 版是否被裁剪/保留需以实机 DbgView 验证。

---

*本文覆盖：文件指纹（双架构）、KMDF 框架、DriverEntry（设备/符号链接/分发例程）、`ObRegisterCallbacks` 进程保护（剥离 PROCESS_TERMINATE/VM_OPERATION/VM_READ/VM_WRITE）、IOCTL 0x22A400/0x22A404 与容量 8 的 PID 数组、MMPC→AntiHelper→mtpcpt 闭环、函数与常量索引。*