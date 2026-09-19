# OeNetLimit.sys 组件深度逆向（NDIS LWF + WFP 网络管控驱动）

> 样本：`samples/os-easy/OeNetLimit.sys`（44568 字节，x64 驱动，MD5 `ca2dab65bdd5956b5d3d8f29d155f3be`）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/oenetlimit-analysis`（OeNetLimit.sys，52 函数）
> 反编译存档：`/root/ghidra/mmpc/oenetlimit_all.txt`（同 `OeNetLimit_run_x64.txt`）
> 家族报告：`x86/OeNetlimit_dll.md`、`x86/NetLimitInterface_dll.md`（用户态库）、`OeNetLimit_inf.md`、`OeNetLimitSetup_exe.md`
> 同源 x86 架构驱动见 `driver-install/OeNetLimit_sys.md`（安装程序内置副本，42520B，PDB `…objfre_win7_x86\i386\…`）
> 分析日期：2026-09-18（重组 2026-09-19）

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 44568 字节 |
| MD5 | `ca2dab65bdd5956b5d3d8f29d155f3be` |
| SHA-256 | `25b75af685377d79f7b809964d5022273022cbc57d14cbbc774aaabcfb0d6046` |
| 格式 | PE32+ 内核驱动（`pei-x86-64`） |
| ImageBase / 入口 | `0x10000` / `0x28064` |
| 导入 | `ntoskrnl`、`HAL`、**`NDIS.SYS`**、**`fwpkclnt.sys`** |
| PDB | `z:\win_drv\new_drv\network\wfpsample\objfre_win7_amd64\amd64\OeNetLimit.pdb` |

> 内嵌 PDB 的源码树目录名为 **`wfpsample`**（微软 Windows Filtering Platform "inspect" 示例工程），印证本驱动由 WFP 示例工程改造而来。

---

## 1. 角色概述

`OeNetLimit.sys` 是 Os-Easy 的**网络管控驱动（NDIS 轻量过滤器 + WFP 过滤）**，对进程做**基于白名单的网络放行/阻断与限速**：

- 注册 **WFP callout/filter**（Inbound/Outbound IPv4 + ALE 资源分配/释放）；
- 用 **PsSetCreateProcessNotifyRoutine** 监控进程创建，记录进程名/PID/父 PID；
- 从 `\SystemRoot\WhiteProcessPath.txt` 载入**白名单**（另含 4 个内置默认）；
- 暴露设备 `\\.\OeNetLimit`，接受上层 `SpeedControl` 配置（开关/限速）。

用户态封装见同级 `x86/OeNetlimit_dll.md`（14 个网络限制 API + CArpMgr）、`x86/NetLimitInterface_dll.md`（C++ 适配层）。

---

## 2. 安装形态

- 以 **NDIS 轻量过滤器（LWF）网络服务** 形态安装（`Class=NetService`、`FilterClass=compression`、`FilterRunType=1`、`LoadOrderGroup=NDIS`）；
- 同时注册为 `SERVICE_KERNEL_DRIVER`、`StartType=1`，`ServiceBinary=%12%\OeNetLimit.sys`；
- 目录签名 `OeNetLimitX86.cat` / `OeNetLimitX64.cat`（随包 `oenetlimitx64.cat`）；
- INF 逐行解析与 NDI 参数见 `OeNetLimit_inf.md`；安装/建服务流程见 `OeNetLimitSetup_exe.md`。

---

## 3. DriverEntry `FUN_000117f0`

```
DbgPrint("OE DriverEntry DriverObject %wZ")
保存自身镜像路径；_DAT_00026a50 = ExAllocatePool(0x1FA0)
DriverObject->MajorFunction:
   IRP_MJ_CREATE (0x70)  = FUN_00011480   // 直接完成
   IRP_MJ_CLOSE  (0x80)  = FUN_00011480
   IRP_MJ_DEVICE_CONTROL (0xE0) = FUN_00011b10
   IRP_MJ_CLEANUP(0x100) = FUN_00011480
   DriverUnload (0x68)   = FUN_00012338
RtlInitUnicodeString(L"\\Device\\OeNetLimit")
RtlInitUnicodeString(L"\\DosDevices\\OeNetLimit")
IoCreateDevice(driver, 0, L"\\Device\\OeNetLimit", FILE_DEVICE_NETWORK(0x12), 0, 0, &devObj)
devObj->Flags |= DO_BUFFERED_IO(4)
IoCreateSymbolicLink(L"\\DosDevices\\OeNetLimit", L"\\Device\\OeNetLimit")
DAT_00026718 = ExAllocatePool(0, 0x601C)                 // 白名单/进程表池
FUN_00013b1c(DAT_00026718)                               // InitWhiteProcessList（读 WhiteProcessPath.txt）
初始化进程链表 DAT_00026a80（头结点自环）
FUN_00013d08 加入默认白名单： StormPlayer.exe / acad.exe / LMU.exe / SLDWORKS.exe
FUN_00011ccc()                                           // InitWfp → FwpmEngineOpen0
PsSetCreateProcessNotifyRoutine(FUN_00011730, 0)         // 进程创建监控
若失败 → 回滚（FUN_00011f88 停 WFP、FUN_00011c6c 删符号链接/设备、释放池）
```

**卸载 `FUN_00012338`**：`FUN_00011f88()`（停 WFP）→ `FUN_00011c6c()`（删符号链接+设备）→ 释放池 → `PsSetCreateProcessNotifyRoutine(FUN_00011730,1)` → 释放进程链表。

---

## 4. 设备接口与 IOCTL `FUN_00011b10`（IRP_MJ_DEVICE_CONTROL）

设备 `\\.\OeNetLimit`（`FILE_DEVICE_NETWORK=0x12`，`DO_BUFFERED_IO`）。分发逻辑：

| IOCTL | 方向 | 长度 | 行为 |
|---|---|---|---|
| `0x122048` | 输入 | `0xF534` | **SET SpeedControl**：`memcpy(&DAT_000171e0, SystemBuffer, 0xF534)`；日志 `IOCTL_SET_SpeedControl` |
| `0x122044` | 输出 | `0xF534` | **GET SpeedControl**：`memcpy(SystemBuffer, &DAT_000171e0, 0xF534)` |
| 其它 | — | — | `STATUS_INVALID_DEVICE_REQUEST(0xC0000001)` |

- IOCTL 编码：DeviceType `0x12`、Function `0x811`/`0x812`、`METHOD_BUFFERED`、`FILE_WRITE_ACCESS`。
- `SpeedControl` 结构体 **大小 0xF534**（= 62868 字节），常驻全局 `DAT_000171e0`。
  关键字段（相对基址 `DAT_000171e0`）：
  - `+0x02`：`isDownLimit`（下行限速标志）
  - `+0x3F`：`disableNet`
  - `+0x40`：`disableInternet`
  - 当二者非空时清空某个 0x324 字节的列表（`FUN_00014020(&DAT_00026720,0,0x324)`）
  - 日志：`OE_NET IOCTL_SET_SpeedControl disableInternet:%d disableNet:%d isDownLimit:%d`

> **本驱动 IRP 分发只认 `0x122044`/`0x122048` 两条 SpeedControl**；用户态 `OeNetlimit.dll` 里出现的 `0x122004~0x122030` 在当前配套驱动下走默认分支返回 `0xC0000001`（见 `x86/OeNetlimit_dll.md` §11）。

---

## 5. WFP 过滤（核心）

### 5.1 引擎 `FUN_00011ccc`

`FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT(10), NULL, &session)` → `DAT_000171d8` 引擎句柄。

### 5.2 回调注册 `FUN_0001245c` / `FUN_000123b0`

```
FwpmCalloutAdd0(engine, WfpSampleInboundIPV4CalloutName, ...)      // 入站 IPv4
FwpmCalloutAdd0(engine, WfpSampleOutboundIPV4CalloutName, ...)     // 出站 IPv4
若存在 ALE 资源类型：
FwpmCalloutAdd0(engine, WfpSampleAleResourceAssignmentCalloutName,...)
FwpmCalloutAdd0(engine, WfpSampleAleResourceReleaseCalloutName,...)
```
（`FUN_000123b0` 是 `FwpsCalloutRegister1` 的封装。）

### 5.3 子层与过滤器 `FUN_000126d8`

```
FwpmSubLayerAdd0(engine, WfpSampleSubLayerName, ...)
FwpmFilterAdd0(engine, WfpSampleFilterInboundIPV4Name, ...)    // 挂入站 callout
FwpmFilterAdd0(engine, WfpSampleFilterOutboundIPV4Name, ...)   // 挂出站 callout
FwpmFilterAdd0(engine, WfpSampleFilterAleResourceAssignmentName, ...)
FwpmFilterAdd0(engine, WfpSampleFilterAleResourceReleaseName, ...)
```
过滤器权重字段=`0x5003`。命名整体沿用微软 **WFP "inspect" 示例**（`WfpSample*`），在此基础上套用白名单策略。

> 即：**WFP ALE 层按"发起进程 + 目标地址"匹配，白名单进程放行，其余按 SpeedControl 开关阻断（上下行分别处理）**。

---

## 6. 进程监控与白名单

### 6.1 进程创建回调 `FUN_00011730`

```
路径 = FUN_000114a8(pid)          // ZwOpenProcess + ZwQueryInformationProcess(class=0x1B ProcessImageFileName)
文件名 = FUN_00011678(路径)        // wcsrchr('\\'/'/') 取 basename
DbgPrint("OE process start:%wZ")
FUN_00013d08(进程表, 文件名, pid, ..., '1')  // 记录/更新进程项
```

### 6.2 白名单文件 `FUN_00013b1c`

```
RtlInitUnicodeString("\SystemRoot\WhiteProcessPath.txt")
ZwOpenFile(READ, ...) → ZwQueryInformationFile(FileStandardInformation) → ExAllocatePool → ZwReadFile
FUN_00013794(buffer, 白名单数组)   // 解析为白名单
```

- 路径固定为 `%SystemRoot%\WhiteProcessPath.txt`；解析进 `DAT_00026718`（0x601C 池）。
- 另在 DriverEntry 内置 4 个默认白名单进程：**`StormPlayer.exe`、`acad.exe`、`LMU.exe`、`SLDWORKS.exe`**（教学机房常见软件）。
- 匹配支持**通配**（`FUN_00012b3c` 对最多 0x78 条模式做 `*` 通配匹配）。

### 6.3 进程表 `FUN_00013d08`

链表（`DAT_00026a80` 头结点）维护进程项：`名称 +0x10`、`PID`、`父 PID`、`超时`；`SLDWORKS.exe` 超时被特判为 `120000ms`，其余 `20000ms`。日志 `OE Add Delay process:%ws,%d,%d`、`OE update process:%ws,%d,%d`、`OE match parent process:...`。

### 6.4 DNS/IP 白名单

`g_DnsIpWhiteList`（`AddDnsWhiteListIp ... is full`），配合 `\??\C:` 卷路径解析，用于网络白名单 IP 列表。

---

## 7. 家族调用链（概要）

```
DeviceControl.exe
  └─ NetLimitInterface.dll   →  x86/NetLimitInterface_dll.md
        └─ OeNetlimit.dll    →  x86/OeNetlimit_dll.md
              └─ 打开 \\.\OeNetLimit，发送 IOCTL 0x122048/0x122044（SpeedControl 0xF534）
                    └─ OeNetLimit.sys（本驱动：WFP/NDIS 过滤 + 进程白名单）
安装：OeNetLimitSetup.exe + OeNetLimit.inf（NetService）→ 注册 NDIS 过滤服务 + 启动驱动
```

> 各层细节拆到同级对应报告，本文只聚焦驱动本体。

---

## 8. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x28064 | entry |
| 0x117f0 | **DriverEntry**（建设备、挂 IRP、WFP 初始化、进程监控、白名单） |
| 0x12338 | DriverUnload |
| 0x11480 | IRP_MJ_CREATE/CLOSE/CLEANUP 处理（直接完成） |
| **0x11b10** | **IRP_MJ_DEVICE_CONTROL**（SpeedControl GET/SET） |
| 0x11c6c | 删符号链接/设备 |
| 0x11ccc | InitWfp（FwpmEngineOpen0） |
| 0x1245c | WfpAddCallouts |
| 0x123b0 | FwpsCalloutRegister1 封装 |
| 0x126d8 | WfpAddFilters（+SubLayer） |
| 0x11f88 | 停 WFP（删 callout/filter/sublayer + 关引擎） |
| 0x11730 | **进程创建回调** |
| 0x114a8 | 取进程镜像路径（ZwQueryInformationProcess 0x1B） |
| 0x11678 | 从路径取文件名 |
| 0x13b1c | InitWhiteProcessList（读 WhiteProcessPath.txt） |
| 0x13794 | 解析白名单文本 |
| 0x13d08 | 进程表增/改（超时、父子匹配） |
| 0x12b3c | 白名单通配匹配（最多 0x78 条） |
| 0x13ec8 | 栈 Cookie 失败 → `KeBugCheckEx(0xF7)` |

---

## 9. 字符串 / 常量表

| 内容 | 用途 |
|---|---|
| `\Device\OeNetLimit` / `\DosDevices\OeNetLimit` | 设备名 / 符号链接（用户态 `\\.\OeNetLimit`） |
| `0x122044` / `0x122048` | GET / SET SpeedControl |
| `0xF534` | SpeedControl 结构大小 |
| `\SystemRoot\WhiteProcessPath.txt` | 白名单文件 |
| `StormPlayer.exe` / `acad.exe` / `LMU.exe` / `SLDWORKS.exe` | 内置默认白名单 |
| `WfpSampleInboundIPV4CalloutName` / `WfpSampleOutboundIPV4CalloutName` | WFP callout |
| `WfpSampleAleResourceAssignmentCalloutName` / `WfpSampleAleResourceReleaseCalloutName` | WFP ALE callout |
| `WfpSampleSubLayerName` / `WfpSampleFilter{Inbound,Outbound}IPV4Name` / `WfpSampleFilterAleResource{Assignment,Release}Name` | WFP 子层/过滤器 |
| `OE DriverEntry…`、`OE ProcessCreateMon…`、`OE WfpAdd…`、`OE_NET IOCTL_SET_SpeedControl…` | DbgPrint 日志 |
| `AddDnsWhiteListIp … is full` | DNS/IP 白名单满 |

---

## 10. 未决项

1. **WFP ALE 分类回调的实现**（放行/阻断判定、限速如何作用于包）需进一步反编译 `FUN_00012be8/…14xxx` 系列分类函数并结合 `SpeedControl` 字段。
2. `SpeedControl`(0xF534) 与用户态 `NET_LIMIT_INFO`(0x3350) 的字段全貌需逐字段对照 `x86/OeNetlimit_dll.md` / `x86/NetLimitInterface_dll.md`。
3. OeNetLimit.sys 同时以 **NDIS LWF** 与 **WFP** 形态生效，二者分工（限速 vs 阻断）待运行态验证。

---

*本文覆盖：OeNetLimit.sys 文件指纹与安装形态、DriverEntry（设备/IRP/WFP/进程监控/白名单）、IOCTL 0x122044/0x122048 与 0xF534 SpeedControl、WFP callout/sub-layer/filter 全清单、进程创建监控与 WhiteProcessPath.txt 白名单（含内置 4 项）、家族调用链概要、函数与常量索引。*
