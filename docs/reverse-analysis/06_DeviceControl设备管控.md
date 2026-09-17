# 06 DeviceControl 设备管控程序完整分析

> 数据源：样本 `DeviceControl_x64.exe`（535040 字节）、`DeviceControl_x86.exe`、`easyusbctrl.dll`、`LISSNetInfoSniffer.exe`（513024 字节）、`LISSClientSDK.dll`，均为 PE 静态分析（字符串 / 导入表 / 导出表 / PE 头）。

## 一、程序定位

| 文件 | 架构 | PE 子系统 | 说明 |
|---|---|---|---|
| `DeviceControl_x64.exe` | PE32+ | **=3 GUI（窗口程序）** | 设备管控主程序（x64） |
| `DeviceControl_x86.exe` | PE32 | **=3 GUI（窗口程序）** | 设备管控主程序（x86） |

- 编译路径：`D:\dmt\master\10.9\Source\DeviceControl\bin\DeviceControl.pdb`
- Manifest：`<requestedExecutionLevel level='asInvoker' uiAccess='false' />`（普通权限，非管理员）
- **本体是 GUI 窗口程序，本身不会弹出黑色控制台窗口**（黑窗口来源见 §二）。
- 定位：**行为管控在用户态的统一执行器（薄调度层）**。真正的活干在三处：
  1. 内核驱动（OeNetLimit / ProcFireWall / easyusbflt / KbFilter）
  2. `LISSClientSDK.dll`（接收教师端指令的宿主 SDK）
  3. 子进程 `LISSNetInfoSniffer.exe`（网络嗅探，见 §五）

## 二、启动链与宿主依赖

```
Teacher.exe（教师端主程序）
   └─ MMPC.exe（守护进程，kill-deviceControl 指令杀它）
        └─ DeviceControl_x64.exe
             ├─ [initLissHelper] 加载 LISSClientSDK.dll  ← 强依赖
             ├─ 读注册表 SOFTWARE\LISSClient\liss  (LissApp / LissKey / LissValue)
             ├─ 读 C:\ProgramData\LISSClient\sslkey.log（TLS 解密密钥日志）
             ├─ SetEnvironmentVariable(SSLKEYLOGFILE, ...)  ← 让子进程能解 HTTPS
             └─ CreateProcessA → LISSNetInfoSniffer\LISSNetInfoSniffer.exe  ← 控制台子进程（黑窗口）
```

### 2.1 宿主上下文检查（关键）

字符串日志模板直接暴露依赖检查链：

```
[initLissHelper] lissPath:%s
[initLissHelper] hMod SUCCESS          ← LISSClientSDK.dll 加载成功
[initLissHelper] hMod failed[%d]!      ← 加载失败
Liss is not exist!                      ← 找不到 Liss 宿主
LISS dir is null
LISS exe:%s
LissSdk exist
[SupportUseDeviceControl] No LissSDK   ← 无 SDK
[StopDeviceControl] No LissSDK
[SendKeywordFilepath] No LissSDK
```

**结论**：DeviceControl 强依赖 Liss 宿主。教师端正常启动时会先初始化 LissSDK、写好 `sslkey.log`、填好注册表 `liss` 键，再拉起 DeviceControl。

### 2.2 单独双击 exe 的后果（黑窗口根因）

用户结束进程后**直接双击 `DeviceControl_x64.exe`**：
1. 无 Liss 宿主 → `Liss is not exist!` / `No LissSDK`（功能失效）
2. 但程序仍会执行硬编码的 `CreateProcessA` 拉起 `LISSNetInfoSniffer.exe`
3. `LISSNetInfoSniffer.exe` 是 **CONSOLE 子系统（PE 头 subsystem=2）** → **黑色命令窗口弹出**
4. 因无认证/无 SDK，子进程空转

> ⚠️ DeviceControl 本体是 GUI（=3），**黑窗口来自它的控制台子进程 `LISSNetInfoSniffer.exe`**，不是 DeviceControl 自己。

## 三、能力探测（四维）

```
[CanUseDeviceControl] ret:%d,support:%d
[SupportUseDeviceControl] process:%d device:%d network:%d traffic%d
```

四个能力维度：**process（进程）/ device（设备/USB）/ network（网络）/ traffic（流量）**。
`support-use-device-control` 指令用于查询当前环境支持哪些管控维度。

## 四、指令全集（按功能）

### 4.1 网络控制
| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable NetWork` | 启用网络 | OeNetLimit.sys |
| `Disable NetWork` | 禁用网络（断网） | OeNetLimit.sys |

### 4.2 应用限制
| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable/Disable Application Limit` | 应用限制开关 | ProcFireWall.sys |
| `Enable Application White/Black Mode` | 白/黑名单模式 | ProcFireWall.sys |

### 4.3 设备 / USB 控制
| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable DUOC` | 设备使用控制 | easyusbflt.sys |

### 4.4 键盘控制
| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable KC` / `Disable Keyfilter` | 键盘控制 | KbFilter.sys |

### 4.5 停止指令
`stop-device-control`、`stopnetworktraffic`、`stopnetwork`、`stopdevice`、`stopprocess`

### 4.6 进程管控（直接系统调用）
| 函数 | 作用 |
|---|---|
| `ZwSuspendProcess` | 挂起进程 |
| `ZwResumeProcess` | 恢复进程 |
| `CreateProcessA` / `OpenProcess` / `TerminateProcess` / `IsWow64Process` | 进程操作 |
| `K32GetProcessImageFileNameW` | 取进程映像名 |

字符串 `Need DisableProcess %s, pid:%d` + 名单 `dismhost.exe`、`setuphost.exe`、`localbridge.exe`、`hxtsr.exe` → 针对特定系统进程做禁用/防护。

## 五、网络嗅探子进程 LISSNetInfoSniffer.exe（黑窗口元凶）★ 重点

`DeviceControl` 通过 `CreateProcessA` 硬编码拉起 `LISSNetInfoSniffer\LISSNetInfoSniffer.exe`。
编译路径：`E:\DMS\tags\DMS5.2.8_standard_1\client\src\LISSNetInfoSniffer\*.cpp`

### 5.1 这是一个 libpcap 实时抓包 + TLS 解密 + 搜索词/敏感词监控程序

| 模块（源文件名） | 能力 | 关键字符串 |
|---|---|---|
| `PcapReader.cpp` | libpcap 网卡实时抓包 | `pcap_findalldevs_ex`、`pcap_open`、`pcap_next_ex`、`Arpcap://`、`GetAdapterByMac`、`Start to monitor adapter: {}, mac: {}` |
| `TlsStreamDecryption.cpp` | **TLS/HTTPS 流量解密** | `SERVER_HANDSHAKE_TRAFFIC_SECRET`、`SSLKEYLOGFILE`、`ServerHello`、`PRI * HTTP/2.0` |
| `SSLKeyFileReader.cpp` | 读 TLS 密钥日志 | `sslkey.log`、`FirstReadFile`、`SetSSLKeyEnvValue` |
| `LibCurlHttpFinder.cpp` | HTTP 请求提取 | `https://`、`http://`、`GET %s HTTP/1.1`、`Accept-Encoding: gzip` |
| `LISSNetInfoSniffer.cpp` | 核心采集逻辑 | `StartCollect`、`StartMMCThread`、`SendNetKeywordInfoToMMC`、`ReportNetworkKeywordInfo` |
| `LISSNetInfoSnifferIpcInterface.cpp` | IPC 接口（收关键词/状态） | `UpdateMonitorKeyword`、`UpdateNetworkSensitiveMonitorStatus`、`OnRecvMMCMonitorNetKeywordFilePath` |

### 5.2 监控目标：搜索引擎关键词 + 敏感词

硬编码搜索 URL（识别学生访问了哪些搜索/内容站）：
```
https://www.baidu.com/s      https://www.baidu.com/baidu
https://cn.bing.com/search   https://www.so.com/s
https://www.sogou.com/web
```

上报数据结构（JSON）：
```json
{"completeUrl":"%s","url":"%s","title":"%s","queryContent":"%s","userAgent":"%s","keywords":%s}
```
→ `ReportNetworkKeywordInfo strCompleteUrl / strUrl / strTitle / strQueryContent`

**含义**：捕获学生**实际输入的搜索关键词**（`queryContent`/`keywords`），做**上网行为审计**，匹配教师端下发的关键词/敏感词清单（`keywords.json`、`UpdateMonitorNetKeyword`、`SensitiveWordMonitorStatus`）。

### 5.3 上报通道

- IPC 队列（Boost.Interprocess message_queue，与 LISS 主程序通信）：
  `LISSNetInfoSnifferQueue`、`LISSServiceNetInfoSnifferRequest`、`LISSServiceRecvNetworkLogReport`、`LISSServiceRecvNetworkKeywordReport`
- 日志：`logs/LISSNetSnifferLog.txt`
- 数据库：`ConnectToDb failed`（存在 DB 写入路径）
- 日志库：spdlog 1.9.2（`LISSNetSnifferLogger`）

### 5.4 与 DeviceControl 主程序的协作

```
Teacher → DeviceControl
            ├─ SetEnvironmentVariable(SSLKEYLOGFILE → C:\ProgramData\LISSClient\sslkey.log)
            ├─ CreateProcessA(LISSNetInfoSniffer.exe)
            └─ 通过 LISSClientSDK.dll / IPC 队列下发关键词清单
LISSNetInfoSniffer.exe（CONSOLE，黑窗口）
            ├─ pcap 抓本机网卡流量（按 MAC 选适配器）
            ├─ 用 sslkey.log 解密 HTTPS
            ├─ 提取搜索 URL + 关键词
            └─ 命中关键词 → SendNetKeywordInfoToMMC → 队列上报
```

> ⚠️ 这是**本地流量解密审计**，需要 `sslkey.log`（由 LiSS 客户端在 TLS 握手时写出的密钥日志）才能解密。这是它能还原 HTTPS 搜索词的原理。

## 六、USB 控制（easyusbctrl.dll）

`easyusbctrl.dll` 导出 11 个函数，DeviceControl 调用：

| 函数 | 作用 |
|---|---|
| `EasyUsb_StartWorking` | 启动 USB 管控 |
| `EasyUsb_StopWorking` | 停止 USB 管控 |

加载失败日志：`load libray easyusbctrl.dll failed!error:%d`。
配合内核 `easyusbflt.sys`（`Enable DUOC`）。

## 七、配置与注册表

| 项 | 位置 | 说明 |
|---|---|---|
| `LissApp` / `LissKey` / `LissValue` | 注册表 `SOFTWARE\LISSClient\liss` | Liss 宿主身份/密钥 |
| `InstallPath` / `FtpServerCachePath` | 配置 | 安装路径 / FTP 缓存 |
| `sslkey.log` | `C:\ProgramData\LISSClient\sslkey.log` | TLS 解密密钥日志 |
| `SSLKEYLOGFILE` | 环境变量 | 指向 sslkey.log，供 Sniffer 解密 |
| `keywords.json` | 本地 | 监控关键词/敏感词清单 |
| `skin/core.conf`、`user.conf`、`general.conf`、`skin/res.config` | 本地 | 通用配置 |

## 八、LISS SDK 接口（接收教师端指令）

```
LISS_SDK_InitIntance / LISS_SDK_FreeIntance
LISS_SDK_IsLoginUiGoingToShow
LISS_SDK_IsSupportMMCStrategy          // 是否支持 MMC 策略
LISS_SDK_SendMMCStopStrategy           // 发送 MMC 停止策略
LISS_SDK_SendBroadcastTypeInternal     // 发送广播类型
LISS_SDK_SendMMCMonitorKeywordFilePath // 下发监控关键词文件路径
```

## 九、指令分发函数（Ghidra 符号）

| 函数 | 职责 |
|---|---|
| `FUN_140021bd0` | 指令分发主入口（参数含 `NET_LIMIT_INFO` 网络限制结构） |
| `FUN_140029310` | 辅助分发 |
| `FUN_140025830` | 停止类指令（stop-*） |
| `FUN_140025aa0` | `support-use-device-control` 能力查询 |
| `FUN_140032e30` | `ZwSuspendProcess` 封装 |
| `FUN_140032aa0` | `ZwResumeProcess` 封装 |
| `FUN_140033730` | `EasyUsb_StartWorking` 封装 |
| `FUN_140033850` | `EasyUsb_StopWorking` 封装 |

## 十、总结

DeviceControl 是行为管控的**用户态统一执行器**，但它**不只是"控设备"**——它实际承担三条线：

1. **驱动管控**：把教师端逻辑指令映射到内核驱动（网络 OeNetLimit / 应用 ProcFireWall / USB easyusbflt / 键盘 KbFilter），支持进程挂起/恢复。
2. **网络行为审计**：拉起控制台子进程 `LISSNetInfoSniffer.exe`，用 **libpcap 抓包 + sslkey.log 解密 HTTPS**，提取学生**搜索关键词**做敏感词审计上报。
3. **Liss 宿主依赖**：强依赖 LISSClientSDK.dll + 注册表 + sslkey.log，单独运行会失效并弹出控制台黑窗口。

> **对注入工具的意义**：要复刻"网络行为审计"，需要同时具备 ① 网卡抓包（Npcap/WinPcap）② TLS 密钥导出（`SSLKEYLOGFILE` 或代理 MITM）③ 搜索引擎关键词提取 ④ 关键词匹配上报。比单纯"断网/锁键"复杂得多——这是 Os-Easy 最隐蔽的能力之一。

---
*分析日期：2026-09-15 · 基于样本 PE 静态分析（字符串 / 导入表 / 导出表 / PE 头）*