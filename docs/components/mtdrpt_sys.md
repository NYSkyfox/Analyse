# mtdrpt.sys 组件深度逆向

> 样本：`samples/os-easy/x64/mtdrpt.sys`（32280 字节）、`samples/os-easy/x86/mtdrpt.sys`（28696 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mtdrpt-analysis`（x64）、`/projects/mtdrptx86`（x86）
> 反编译存档：`/root/ghidra/mmpc/mtdrpt_x64_all.txt`（46 函数）、`mtdrpt_x86_all.txt`（41 函数）
> 分析日期：2026-09-18

---

## 0. 样本信息

| 项 | x64 | x86 |
|---|---|---|
| 大小 | 32280 字节 | 28696 字节 |
| MD5 | `fb2b43367ea745cdfc422a0bc0f737df` | `7c305fdd82690ea5f1798392e21f465e` |
| SHA-256 | `e5c907c964e242cb1665b0a096e87ef02bfab01242be81eb830137566fffb384` | `d5d9ebf837248848e26c30c2d2ef583574d3ca08ed90147e56b314be808978c2` |
| 格式 | PE32+ 内核驱动（`pei-x86-64`） | PE32 内核驱动（`pei-i386`） |
| ImageBase | `0x140000000` | `0x400000` |
| 入口点 | `0x1400061a0` | `0x405120` |
| PDB | `E:\yzj\master\10.9\Source\Teacher\Release\mtdrpt.pdb`（两版同源） | 同左 |

**类型**：**文件系统微过滤器（minifilter）**，依赖 `FLTMGR.SYS`。
**内部名**（调试串）：`myFilter`、`MMCProtect`、`NPMini*`。
**导入**：`FLTMGR.SYS` —— `FltRegisterFilter`、`FltStartFiltering`、`FltUnregisterFilter`、`FltGetFileNameInformation`、`FltParseFileNameInformation`、`FltReleaseFileNameInformation`、`FltAllocateContext`、`FltSet/Get{Instance,Stream,Transaction}Context`、`FltReleaseContext`、`FltCreateCommunicationPort`、`FltCloseCommunicationPort`、`FltCloseClientPort`、`FltBuildDefaultSecurityDescriptor`、`FltFreeSecurityDescriptor`、`FltEnlistInTransaction`；`ntoskrnl` —— `RtlInitUnicodeString`、`RtlPrefixUnicodeString`、`wcslen`、`DbgPrint`。

---

## 1. 角色概述

`mtdrpt.sys` 是 Os-Easy 的**目录保护微过滤器**（服务名 `mmcprotect`，由 AntiHelper.dll 安装，Altitude `370160`）：

1. 维护**一个受保护路径前缀**（全局宽字符串，通过用户态通信端口下发）；
2. 挂钩 `IRP_MJ_CREATE` 与 `IRP_MJ_SET_INFORMATION`；
3. 当目标文件路径命中该前缀时，**拒绝删除 / 改名 / 删除后关闭**等操作（返回 `STATUS_ACCESS_DENIED` + `FLT_PREOP_COMPLETE`）。

端口名 `\MmcProtectPort`，与 AntiHelper.dll 的 `FilterSendMessage` 完全对应。

---

## 2. 初始化与注册（DriverEntry）

```
DbgPrint("MMCProtect!DriverEntry: Entered\n")
FltRegisterFilter(DriverObject, &fltRegistration, &g_Filter)      // 失败即退出
FltStartFiltering(g_Filter)                                        // 失败 → FltUnregisterFilter
FltBuildDefaultSecurityDescriptor(&sd, 0x1F0001)                   // 端口 DACL（DACL_SECURITY_INFORMATION|...）
RtlInitUnicodeString(&name, L"\\MmcProtectPort")
FltCreateCommunicationPort(g_Filter, &g_ServerPort, &objAttr, /*Cookie*/0,
                           ConnectNotify    = FUN_140001800 / 0x4015b0,   // NPMiniConnect
                           DisconnectNotify = FUN_140001840 / 0x4015d0,   // NPMiniDisconnect
                           MessageNotify    = FUN_140001870 / 0x4015f0,   // NPMiniMessage
                           MaxConnections   = 1)
FltFreeSecurityDescriptor(sd)
```

- `OBJECT_ATTRIBUTES`：`Length=0x30`、`ObjectName=L"\\MmcProtectPort"`、`SecurityDescriptor=sd`、`Attributes=0x240`（`OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE`）。
- 未在驱动内写 Altitude——`370160` 由 AntiHelper 安装时写入注册表 `Services\mmcprotect\Instances\…\Altitude`。

**操作注册表**（`FLT_OPERATION_REGISTRATION[]`，条目 0x20 字节，终止项 `MajorFunction=0x80`）：

| MajorFunction | Flags | PreOperation | PostOperation |
|---|---|---|---|
| `IRP_MJ_CREATE`(0x00) | 0 | `FUN_140001080` / `0x401060` | `FUN_1400010d0` / `0x401090` |
| `IRP_MJ_SET_INFORMATION`(0x06) | 0 | `FUN_140001000` / `0x401000` | — |
| `0x80`（终止） | 0 | — | — |

**卸载** `FUN_140005000` / `0x404...`：`DbgPrint("MMCProtect!MMCProtectUnload")` → `FltCloseCommunicationPort(g_ServerPort)` → `FltUnregisterFilter(g_Filter)`。

---

## 3. 通信端口回调（受保护路径的唯一入口）

| 回调 | 函数 | 行为 |
|---|---|---|
| Connect | `FUN_140001800` | `DbgPrint("[mini-filter] NPMiniConnect")`；保存 client port |
| Disconnect | `FUN_140001840` | `FltCloseClientPort(g_Filter,&clientPort)` |
| Message | `FUN_140001870` | 见下 |

`FUN_140001870`（NPMiniMessage）：

```c
DbgPrint("[mini-filter] NPMiniMessage");
if (buf == NULL || len == 0) {
    memset(g_ProtectedPath, 0, 0x1FE);          // 空消息 = 复位（清除受保护前缀）
} else {
    memset(g_ProtectedPath, 0, 0x1FE);
    copy(g_ProtectedPath, buf, len);             // 写入新的受保护路径（宽字符串）
    DbgPrint("Path:%ws,%d\n", g_ProtectedPath, len);
}
return 0;
```

- 全局缓冲 `g_ProtectedPath`（x64 `DAT_140003050` / x86 `DAT_00403010`），大小 `0x1FE` 字节 = **255 个宽字符**。
- 消息载荷 = 宽字符串 NT 路径前缀；空消息用于复位。
- 与 AntiHelper.dll 的 `SetProtectDirectory`（下发 NT 路径）/ `ResetProtectDirectory`（空串）一一对应。

---

## 4. 拦截逻辑（核心）

共同判定函数（`FUN_1400014e0` / `FUN_1400016ac`）：

```c
if (wcslen(g_ProtectedPath) == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;   // 未设保护
FltGetFileNameInformation(Cbd, 0x101, &nameInfo);        // 0x101 = FLT_FILE_NAME_OPENED|QUERY_DEFAULT
FltParseFileNameInformation(nameInfo);
RtlInitUnicodeString(&prefix, g_ProtectedPath);
if (!RtlPrefixUnicodeString(&prefix, &nameInfo->Name, caseInsensitive))  // 路径前缀匹配
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 命中：
Cbd->IoStatus.Status = 0xC0000022;   // STATUS_ACCESS_DENIED
Cbd->IoStatus.Information = 0;
return FLT_PREOP_COMPLETE(4);        // 直接拒绝，不再下发
```

### 4.1 `IRP_MJ_SET_INFORMATION` 预操作 `FUN_140001000`

按 **FileInformationClass** 分派（`Iopb->Parameters` 偏移处的信息类）：

| 信息类 | 名称 | 处理 |
|---|---|---|
| `0x0A`(10) | `FileRenameInformation` | `FUN_1400016ac` → 命中即拒绝改名 |
| `0x41`(65) | `FileRenameInformationEx` | `FUN_1400016ac` |
| `0x0D`(13) | `FileDispositionInformation` | `FUN_1400014e0` → 命中即拒绝删除 |
| `0x40`(64) | `FileDispositionInformationEx` | `FUN_1400014e0` |
| 其它 | — | `FLT_PREOP_SUCCESS_NO_CALLBACK` |

- `FUN_1400014e0` 额外检查"是否真的删除"：`FileDispositionInformation` 读 `FILE_DISPOSITION_INFORMATION.DeleteFile` 字节；`…Ex` 读 `FILE_DISPOSITION_INFORMATION_EX.Flags` 低位。**仅当删除标志为真才拒绝**。
- `FUN_1400016ac` 用于改名类。

### 4.2 `IRP_MJ_CREATE`

- 预操作 `FUN_140001080`：若 `CreateOptions & FILE_DELETE_ON_CLOSE(0x1000)` → 走 `FUN_1400016ac`（命中即拒绝"删除后关闭"式的打开）。
- 后操作 `FUN_1400010d0`（`myFilter!myFilterPostOperation`）：
  - 成功（`Status>=0` 且非 `STATUS_REPARSE=0x104`）时，`get-or-create` 目标文件的**流上下文**，并把 `"是否为删除类操作"`（`CreateOptions & FILE_DELETE_ON_CLOSE`）写入上下文偏移 `+0x22`。

---

## 5. 上下文机制

| 函数 | 作用 |
|---|---|
| `FUN_140001230` / `0x401182` | 按类型取上下文：`2`=Instance、`8`=Stream、`0x20`=Transaction（否则 `STATUS_INVALID_PARAMETER`） |
| `FUN_140001428` / `0x4012e2` | 按类型设上下文（`FltSet{Instance,Stream,Transaction}Context`） |
| `FUN_1400011b4` / `0x40112e` | `FltAllocateContext` 分配（大小 `0x28`，清零） |
| `FUN_1400012bc` / `0x4011e0` | get-or-create：不存在（`STATUS_NOT_FOUND`）则分配→设置；事务类型额外 `FltEnlistInTransaction` |
| `FUN_1400010d0` | 后操作中写入"删除类"标志位 |

用途：为受操作的文件/流/事务记录保护状态（供后续判断或统计），并按需把事务登记进过滤管理器。

---

## 6. 闭环：MMPC → AntiHelper → mtdrpt

```
MMPC.exe
 └─ AntiHelper.dll DllMain(PROCESS_ATTACH)
      └─ 安装并启动服务 mmcprotect（mtdrpt.sys）      ← 本驱动（微过滤器）
           ├─ FltRegisterFilter / FltStartFiltering
           ├─ 挂钩 IRP_MJ_CREATE + IRP_MJ_SET_INFORMATION
           └─ 创建端口 \MmcProtectPort（MaxConnections=1）
 └─ SetProtectDirectory("C:\受保护目录")
      └─ AntiHelper 转成 NT 路径 → FilterSendMessage("\MmcProtectPort", ntpath)
           └─ mtdrpt: 存入 g_ProtectedPath
 └─ 之后对该目录的删除/改名/delete-on-close 打开 → STATUS_ACCESS_DENIED
 └─ ResetProtectDirectory()
      └─ FilterSendMessage("\MmcProtectPort", L"")  → g_ProtectedPath 清空，解除保护
```

---

## 7. 关键函数索引

| x86 | x64 | 职责 |
|---|---|---|
| 0x401000 | 0x140001000 | `IRP_MJ_SET_INFORMATION` 预操作（按信息类分派） |
| 0x401060 | 0x140001080 | `IRP_MJ_CREATE` 预操作（DELETE_ON_CLOSE） |
| 0x401090 | 0x1400010d0 | `IRP_MJ_CREATE` 后操作（写流上下文） |
| 0x40112e | 0x1400011b4 | 分配上下文 |
| 0x401182 | 0x140001230 | 取上下文 |
| 0x4011e0 | 0x1400012bc | get-or-create 上下文（+事务 Enlist） |
| 0x4012e2 | 0x140001428 | 设上下文 |
| 0x401350 | 0x1400014e0 | 拒绝"删除"（disposition） |
| 0x4014aa | 0x1400016ac | 拒绝"改名"（rename） |
| 0x4015b0 | 0x140001800 | NPMiniConnect |
| 0x4015d0 | 0x140001840 | NPMiniDisconnect |
| 0x4015f0 | 0x140001870 | NPMiniMessage（设置受保护路径） |
| 0x405000 | 0x140005000 | 卸载（关端口 + 注销过滤器） |
| 0x405120 | 0x1400061a0 | entry / DriverEntry |

---

## 8. 字符串 / 常量表

| 内容 | 用途 |
|---|---|
| `\MmcProtectPort` | 通信端口名 |
| `[mini-filter] NPMiniConnect / NPMiniDisconnect / NPMiniMessage` | 端口回调日志 |
| `Path:%ws,%d` | 收到受保护路径时打印 |
| `myFilter!myFilterPostOperation: Entered` | 后操作日志 |
| `MMCProtect!DriverEntry / MMCProtectUnload: Entered` | 加载/卸载日志 |
| `g_ProtectedPath`（`DAT_140003050` / `DAT_00403010`） | 受保护路径前缀（255 宽字符） |
| `0x101` | `FltGetFileNameInformation` 标志（OPENED\|QUERY_DEFAULT） |
| `0xC0000022` | 命中时返回的状态（`STATUS_ACCESS_DENIED`） |

---

## 9. 未决项

1. 受保护路径前缀匹配是否**只支持单个目录**（全局单串），多目录保护是否靠上层反复多次下发/串联，待运行态验证。
2. `FltGetFileNameInformation` 用 `0x101`（OPENED 名）而非 NORMALIZED，前缀比较的边界（卷挂载点/短名）需实机确认。
3. 后操作写入的上下文标志位 `+0x22` 的后续消费方（是否有其它组件读取）未在驱动内发现。
4. Altitude `370160` 的实际过滤链位置与其它微过滤器的相对次序需实机 `fltmc filters` 查看。

---

*本文覆盖：文件指纹（双架构）、微过滤器初始化与端口（`\MmcProtectPort`）、受保护路径前缀（端消息下发/空消息复位）、`IRP_MJ_CREATE` + `IRP_MJ_SET_INFORMATION` 拦截（改名 0x0A/0x41、删除 0x0D/0x40、delete-on-close）、上下文机制、卸载、MMPC→AntiHelper→mtdrpt 闭环、函数与常量索引。*