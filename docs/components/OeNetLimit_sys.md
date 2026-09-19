# OeNetLimit.sys 组件深度逆向（附 NetLimitInterface.dll / OeNetlimit.dll 家族）

> 样本：
> - `samples/os-easy/OeNetLimit.sys`（44568 字节，x64 驱动，MD5 `ca2dab65bdd5956b5d3d8f29d155f3be`）
> - **同源 x86 架构**样本 `samples/di_flat/OeNetLimit.sys`（42520 字节，MD5 `10668397e1ca3b56e77bbc53aef742a6`，PDB `…objfre_win7_x86\i386\…`），独立分析见 `driver-install/OeNetLimit_sys.md`
> - `samples/os-easy/OeNetLimitSetup.exe`（98344）、`OeNetLimit.inf`、`oenetlimitx64.cat`
> - `samples/os-easy/x64| x86 / OeNetlimit.dll`（488592 / 372368）
> - `samples/os-easy/x64| x86 / NetLimitInterface.dll`（172544 / 145408）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/oenetlimit-analysis`（OeNetLimit.sys，52 函数）
> 反编译存档：`/root/ghidra/mmpc/oenetlimit_all.txt`
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 文件 | 大小 | MD5 | SHA-256 |
|---|---|---|---|
| `OeNetLimit.sys` | 44568 | `ca2dab65bdd5956b5d3d8f29d155f3be` | `25b75af685377d79f7b809964d5022273022cbc57d14cbbc774aaabcfb0d6046` |
| `OeNetLimitSetup.exe` | 98344 | `e6cf914bf13d5c72fc007ba57e4979bf` | — |
| `x86/OeNetlimit.dll` | 372368 | `0914ffa0abac65e1aecad7e10c5d0d9f` | — |
| `x86/NetLimitInterface.dll` | 145408 | `95e68d1b7d0a30db0c918d4d0bb666b0` | — |

**OeNetLimit.sys**：PE32+ 内核驱动，ImageBase `0x10000`，入口 `0x28064`；导入 `ntoskrnl`、`HAL`、**`NDIS.SYS`**、**`fwpkclnt.sys`**。内嵌 PDB：`z:\win_drv\new_drv\network\wfpsample\objfre_win7_amd64\amd64\OeNetLimit.pdb`（源码树目录名即 wfpsample，印证源自微软 WFP 示例工程）。

---

## 1. 角色概述

`OeNetLimit.sys` 是 Os-Easy 的**网络管控驱动（NDIS 轻量过滤 + WFP 过滤）**，对进程做**基于白名单的网络放行/阻断与限速**：

- 注册 **WFP callout/filter**（Inbound/Outbound IPv4 + ALE 资源分配/释放）；
- 用 **PsSetCreateProcessNotifyRoutine** 监控进程创建，记录进程名/PID/父 PID；
- 从 `\SystemRoot\WhiteProcessPath.txt` 载入**白名单**（另含 4 个内置默认）；
- 暴露设备 `\\.\OeNetLimit`，接受上层 `SpeedControl` 配置（开关/限速）。

---

## 2. 安装形态（`OeNetLimit.inf`）

- `Class = NetService`，`ClassGUID = {4D36E974-E325-11CE-BFC1-08002BE10318}`，`Characteristics = 0x40008`；
- NDI：`Service="OeNetLimit"`、`FilterClass="compression"`、`FilterType=0x2`、`FilterMediaTypes="ethernet"`、`FilterRunType=1` → **作为 NDIS 轻量过滤器（LWF）网络服务安装**；
- 服务：`ServiceType=1(SERVICE_KERNEL_DRIVER)`、`StartType=1`、`ErrorControl=1`、`ServiceBinary=%12%\OeNetLimit.sys`、`LoadOrderGroup=NDIS`；
- 目录：`CatalogFile` = `OeNetLimitX86.cat` / `OeNetLimitX64.cat`（`oenetlimitx64.cat` 随包）。
- 安装由 `OeNetLimitSetup.exe`（NetCfg 安装器，`InstallEx`/`txfw` 逻辑）完成。

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

## 7. 家族调用链

```
DeviceControl.exe
  └─ NetLimitInterface.dll（导出 CNetLimitInstance / SetWhiteRule / NET_LIMIT_INFO）
        └─ 依赖 systemoper.dll；引用 OeNetlimit.dll       // 用户态封装
              └─ OeNetlimit.dll（x86/x64，导入 WS2_32/SensApi/USER32/ADVAPI32）
                    └─ 打开 \\.\OeNetLimit，发送 IOCTL 0x122048/0x122044（SpeedControl 0xF534）
                          └─ OeNetLimit.sys（本驱动：WFP 过滤 + 进程白名单）
安装：OeNetLimitSetup.exe + OeNetLimit.inf（NetService）→ 注册 NDIS 过滤服务 + 启动驱动
```

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
2. `NET_LIMIT_INFO`(0x3350) 与 `SpeedControl`(0xF534) 的字段全貌：前者是 DeviceControl↔NetLimitInterface 的用户态结构，后者是驱动侧结构，需逐字段对照 `NetLimitInterface.dll`/`OeNetlimit.dll`。
3. `NetLimitInterface.dll`→`OeNetlimit.dll`→驱动 的精确调用（哪个模块、哪种 IOCTL）需继续逆向 `OeNetlimit.dll`（x86/x64 各 0.37–0.49MB）。
4. OeNetLimit.sys 同时以 NDIS LWF 与 WFP 形态生效，二者分工（限速 vs 阻断）待运行态验证。

---

*本文覆盖：OeNetLimit.sys 文件指纹与安装形态（NetService/NDIS LWF + WFP）、DriverEntry（设备/IRP/WFP/进程监控/白名单）、IOCTL 0x122044/0x122048 与 0xF534 SpeedControl、WFP callout/sub-layer/filter 全清单、进程创建监控与 WhiteProcessPath.txt 白名单（含内置 4 项）、家族调用链（DeviceControl→NetLimitInterface→OeNetlimit→驱动）、函数与常量索引。*