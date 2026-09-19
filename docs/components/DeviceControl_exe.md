# DeviceControl（_x64 / _x86）组件深度逆向

> 样本：`samples/os-easy/x64/DeviceControl_x64.exe`（535040 字节）、`samples/os-easy/x86/DeviceControl_x86.exe`（420864 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/devctl-analysis`（x86）
> 反编译存档：`/root/ghidra/mmpc/dc_funcs1.txt`、`dc_funcs2.txt`、`dc_funcs3.txt`、`dc_strxref.txt`、`dc_refs*.txt`
> 分析日期：2026-09-18

---

## 0. 样本信息

| 项 | x64 | x86 |
|---|---|---|
| 大小 | 535040 字节 | 420864 字节 |
| MD5 | `fff190ae29ef3bdc581d163a637ee986` | `89176b2a345c1291885afdf2df0aa37d` |
| SHA-256 | `f602617b02ed4d8604a548abe85e04047bf0cc0cf0906d442fc0e522a28f4587` | `9432cbc3a6ab1695bb44d8378cdb6f632b6d098fdf0e0e147d082baca33a51bf` |
| 格式 | PE32+ 控制台程序（`pei-x86-64`） | PE32 控制台程序（`pei-i386`） |
| ImageBase | `0x140000000` | `0x400000` |
| 入口点 | `0x1400506fc` | `0x44cae9` |
| PDB | `D:\dmt\master\10.9\Source\DeviceControl\bin\DeviceControl.pdb` | 同源 |

**依赖**：`WS2_32`、`IPHLPAPI`、`ADVAPI32`、`USER32`、`OLEAUT32`、`dbghelp`（崩溃转储）、`VERSION`、**`NetLimitInterface.dll`**（`CNetLimitInstance`：`SetWhiteRule` / `NET_LIMIT_INFO`）。
**库/协议**：**JsonCpp**（`Json::Value`）、**boost**（filesystem/format）、**LISS SDK**（`LISS_SDK_*`，动态加载）。
**别的 DLL/进程**：`easyusbctrl.dll`（`EasyUsb_StartWorking/StopWorking`）、`LISSNetInfoSniffer\LISSNetInfoSniffer.exe`、`skin\core.conf`、`skin\res.config`、`general.conf`、`user.conf`、`keywords.json`。

---

## 1. 角色概述

DeviceControl 是 **设备/网络管控代理**（MMPC 的 `npd-auto` 命令启动它并守护其 PID）。它是一个 **监听本机回环 UDP 的服务**，接收上层（控制台/教师侧）下发的 JSON 指令，落地为：

- **网络开关**（经 `NetLimitInterface.dll` → `OeNetLimit.sys` 驱动）；
- **应用程序限制 / 白名单 / 黑名单**（按进程路径）；
- **键盘过滤（KC / Keyfilter）**、**DUOC**；
- **进程挂起/恢复**（`ZwSuspendProcess` / `ZwResumeProcess`）；
- **USB 管控**（`easyusbctrl.dll`）；
- **关键字监控 / 文件路径监控**（`keywords.json`、LISS SDK）。

---

## 2. 传输与监听（UDP 回环）

### 2.1 入口与初始化 `FUN_00426c30`（x64 对应同源函数）

```
entry(0x44cae9) → ___security_init_cookie → FUN_0044c967 → FUN_00426c30
FUN_00426c30:
  FUN_00419250(L"DeviceControlEvent")     // 事件/单实例对象
  if (FUN_0041e380()) return;             // 已在运行则退出
  FUN_00420080("DeviceControl")           // 载入配置相关
  FUN_0041e2a0(1)                          // 初始化（日志等）
  FUN_0041b4d0 / FUN_0041ff10 / FUN_0041b430   // 校验 LISS 是否存在（否则 "Liss is not exist!"）
  _DAT_00464698 = 0xBC000000               // 默认 CtrlCode 初值
  FUN_00419b00(listener)                   // 构造监听对象
  ipProto = FUN_00401fd0("IpProto")        // 读取配置项 IpProto（6=IPv6）
  if (ipProto == 6)  FUN_0040c950(listener, "::1",   0x2106)    // 监听 [::1]:8454
  else               FUN_0040c950(listener, "127.0.0.1", 0x2106) // 监听 127.0.0.1:8454
  callback = wrap(FUN_00421b30)
  FUN_0040cdf0(listener)                   // 接收循环（阻塞）
```

- **监听端口 `0x2106 = 8454`**（UDP，回环，IPv4 `127.0.0.1` 或 IPv6 `::1`，由配置 `IpProto` 决定）。
- 监听对象布局（x86）：`+0x04` socket、`+0x08` 地址串、`+0x20` 端口、`+0x22` 停止标志、`+0x30` 回调（std::function）、`+0x50` 最近接收串。

### 2.2 绑定与接收

| 函数 | 作用 |
|---|---|
| `FUN_0040c950` | 构造监听对象：写端口/地址、socket 置 `-1`、清停止标志 |
| `FUN_0040c370` | `socket(AF_INET/AF_INET6, SOCK_DGRAM)` + `bind(addr, port)`（端口取对象 `+0x20`） |
| `FUN_0040cdf0` | **接收循环**：`select` + `recvfrom`（32KB 缓冲）→ 存入对象 `+0x50` → 触发回调 `FUN_00421b30` |
| `FUN_00401fd0` | 读取整型配置项（如 `IpProto`） |
| `FUN_0040c540` | 通用配置读取（跨多处配置节，特判 `FtpServerCachePath`） |

### 2.3 主动查询（UDP 请求/应答）

`FUN_00420770` 是 **同步 UDP 请求**：`socket→sendto(127.0.0.1:8454)→select→recvfrom`（按端口匹配），返回应答字符串。使用它的命令构造器：

| 函数 | 发送的 JSON（`type`） | 用途 |
|---|---|---|
| `FUN_0041e780` | `{"type":"check-liss-sdk"}` | 查询 LISS SDK 是否可用 |
| `FUN_0041e8a0` | `{"type":"start-lissNet","ip":..,"mac":..,"filepath":..}` | 启动 LISS 网络信息嗅探 |
| `FUN_0041ea40` | `{"type":"stop-device-control","stopnetworktraffic":..,"stopnetwork":..,"stopdevice":..,"stopprocess":..}` | 停止各管控 |
| `FUN_0041ec40` | `{"type":"support-use-device-control","networktraffic":..,"network":..,"device":..,"process":..}` | 查询各管控支持位 |

（`FUN_0041e3d0` 为崩溃处理：拼 `DeviceControl_x86/x64.exe` + `MiniDumpWriteDump`。）

---

## 3. 指令模型（入站命令）

入站 JSON 由 `FUN_00421b30` 解析并分派，再调 `FUN_0041efd0` 处理 `CtrlCode`/`apps`/`cites`。

`FUN_0041efd0` 读取字段：

| 字段 | 含义 |
|---|---|
| `CtrlCode` | **整型位掩码**（管控开关，见 §4） |
| `apps` | 数组，元素 `{ "app":<名>, "exec":<路径>, "type":<串> }` |
| `cites` | 数组（引用/站点列表，用于网络白名单） |
| `serverIp` | 服务器 IP（网络配置） |
| `LissKey` / `LissValue` | LISS 路径等键值 |
| `LissApp` | LISS 应用项 |

处理动作：遍历 `apps` 调 `FUN_00425b30` 写入应用表；扫描 LISS 目录（`<path>\*.exe`）匹配进程；日志 `LISS path:%s`、`LISS exe:%s`、`LISS dir  is null`。

---

## 4. `CtrlCode` 位掩码（`FUN_0041b960`）

| 位 | 置位时 | 清零时 | 落地 |
|---|---|---|---|
| `0x00000001` | **Disable NetWork** | **Enable NetWork** | 构造 `NET_LIMIT_INFO`(0x3350) → `FUN_0041e720`（`CNetLimitInstance::SetWhiteRule`） |
| `0x00000002` | **Enable KC**（键盘过滤） | **Disable Keyfilter** | 构造 `{windowName:"UIStudentMainWnd", keys:[{key:..}]}` + `keywords.json` |
| `0x00000010` | **Enable Application Limit** | **Disable Application Limit** | `FUN_00429720(&DAT_00464674,3/…)` |
| `0x00100000` | **Enable Application White Mode** | **Enable Application Black Mode** | 按 `type=="0"/"1"` 逐项 `FUN_00429600(路径)`（进程限制/挂起），再 `FUN_00429720(...,1/2)` |
| `0x00001000` | **Enable DUOC** | **Disbale DUOC** | `FUN_0042a000` / `FUN_0042a0f0(&DAT_004646d8)` |

网络部分细节（`0x1` 位）：
- Disable：`FUN_0044bfc9(0x3350)` 分配 `NET_LIMIT_INFO`，`type=2`；把当前 IP/`cites` 填入结构（`Ip:%s`、`Cites:%s`）。
- Enable：`type=3`（放开）。
- 最终经 `FUN_0041e720` 下发到 `NetLimitInterface.dll`（→ `OeNetLimit.sys`）。

应用限制（`0x100000` 位）：白/黑模式二选一，逐项 `FUN_00420380(路径)` → `FUN_004242c0` 转宽串 → `FUN_00429600`（配合 `ZwSuspendProcess/ZwResumeProcess` 实现"禁止运行/挂起"）。

---

## 5. 外部依赖与协作

| 依赖 | 接口 | 作用 |
|---|---|---|
| `NetLimitInterface.dll` | `CNetLimitInstance()` / `~` / `SetWhiteRule(NET_LIMIT_INFO*)` | 网络限速/开关，最终到 `OeNetLimit.sys` |
| `easyusbctrl.dll` | `EasyUsb_StartWorking` / `EasyUsb_StopWorking` | USB 管控（日志 `Call EasyUsb_StartWorking`…） |
| LISS SDK | `LISS_SDK_InitIntance`/`FreeIntance`/`IsSupportMMCStrategy`/`SendBroadcastTypeInternal`/`SendMMCMonitorKeywordFilePath`/`SendMMCStopStrategy`/`IsLoginUiGoingToShow` | 与 LISS 客户端协作（关键字监控、策略下发、广播） |
| `LISSNetInfoSniffer.exe` | 命令行 `"<ip>" "<mac>" "<filepath>"` | 网络信息嗅探（`start-lissNet`） |
| `dbghelp.dll` | `MiniDumpWriteDump` | 崩溃转储 |

网络能力探测（`[SupportUseDeviceControl] process:%d device:%d network:%d traffic%d`、`[CanUseDeviceControl] ret:%d,support:%d`）说明各管控类别有独立"支持位"。

---

## 6. 与 MMPC 的联动

```
MMPC.exe  ──(UDP 9030, type="npd-auto"/"start npd")──▶ MMPC 自身
   ├─ 启动 x64\x64\DeviceControl_x64.exe（或 x86\DeviceControl_x86.exe）   [FUN_00437ae0]
   └─ AddProcessPid(DeviceControl 的 PID) 保护其不被结束                  [AntiHelper→mtpcpt]
DeviceControl.exe
   └─ 监听 127.0.0.1:8454（UDP，JSON）← 上层控制指令
        └─ CtrlCode → 网络/应用/键盘/USB/进程 管控
```

同时 DeviceControl 会向 `127.0.0.1:8454` **反查**自身/对端能力（`check-liss-sdk`、`support-use-device-control` 等）。

---

## 7. 关键函数索引（x86）

| 地址 | 职责 |
|---|---|
| 0x44cae9 | entry |
| 0x44c967 | 主流程入口 |
| 0x426c30 | 初始化 + 建监听（端口 0x2106/8454） |
| 0x40c950 / 0x40c370 / 0x40cdf0 | 构造监听 / bind / recvfrom 循环 |
| 0x401fd0 / 0x40c540 | 读配置（IpProto 等） |
| 0x420770 | UDP 同步请求/应答 |
| 0x41e780 / 0x41e8a0 / 0x41ea40 / 0x41ec40 | check-liss-sdk / start-lissNet / stop-device-control / support-use-device-control |
| **0x421b30** | **入站命令解析/分派** |
| 0x41efd0 | `CtrlCode`+`apps`+`cites` 处理 |
| 0x41b960 | `CtrlCode` 位掩码 → 落地动作 |
| 0x41e720 | NetLimit 下发（SetWhiteRule） |
| 0x429600 | 进程限制/挂起 |
| 0x420380 | 路径→宽串处理 |
| 0x41e3d0 | 崩溃处理（MiniDumpWriteDump） |

---

## 8. 字符串 / 常量表

| 内容 | 用途 |
|---|---|
| `0x2106`（8454） | 监听/通信 UDP 端口 |
| `DeviceControlEvent` | 事件/单实例对象 |
| `CtrlCode` / `apps` / `cites` / `serverIp` / `LissKey` / `LissValue` / `LissApp` | 指令字段 |
| `IpProto` | 配置项（6=IPv6 回环 `::1`） |
| `Enable/Disable NetWork`、`Enable/Disable Application Limit`、`Enable Application White/Black Mode`、`Enable KC`/`Disable  Keyfilter`、`Enable DUOC`/`Disbale DUOC` | 管控状态串（日志/界面） |
| `UIStudentMainWnd` / `windowName` / `keywords.json` | 键盘过滤（KC） |
| `skin\core.conf`、`skin\res.config`、`general.conf`、`user.conf` | 配置文件 |
| `Liss is not exist!`、`[SupportUseDeviceControl] …`、`[StopDeviceControl] …` | 日志 |
| `ZwSuspendProcess` / `ZwResumeProcess` | 进程挂起/恢复 |

---

## 9. 未决项

1. **入站指令的发送方**：监听在回环 8454，实际下发命令的组件（教师/控制台/LISS/StudentLogic）需运行态抓包确认。
2. 收敛"网络开关"到 `OeNetLimit.sys` 的 `NET_LIMIT_INFO`(0x3350) 结构与 `SetWhiteRule` 语义，需结合 `NetLimitInterface.dll`（IDV/网络限制）单独逆向。
3. `CtrlCode` 其余位（如 `0x100000` 之外的高位）与 `apps[].type` 的完整取值枚举未穷尽。
4. `FUN_0040c370` 中 socket 选项（`Ordinal_21`，疑似 `SO_REUSEADDR`/超时）与 IPv6 分支细节需进一步确认。

---

*本文覆盖：文件指纹（双架构）、回环 UDP 服务（127.0.0.1/::1 : 8454，JsonCpp 协议）、客户端同步查询（check-liss-sdk / start-lissNet / stop-device-control / support-use-device-control）、`CtrlCode` 位掩码与 `apps/cites/serverIp` 指令模型、网络/应用/键盘/USB/进程管控落地、外部依赖（NetLimitInterface、easyusbctrl、LISS SDK、dbghelp）、与 MMPC 的联动、函数与常量索引。*