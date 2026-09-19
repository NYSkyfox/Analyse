# MainLogic.dll 组件深度逆向（教师端逻辑核心库）

> 样本：`samples/os-easy/MainLogic.dll`（1684480 字节，PE32 i386 DLL）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`，`x86:LE:32:default`）+ objdump + strings
> 工程：`/projects/mainlogic`
> 反编译存档：`/root/ghidra/mmpc/mainlogic_x86.txt`（14313 函数，7.7MB）
> 关联：`Teacher_exe.md`（宿主）、`MultiClient_exe.md`（学生端，本库的 WebSocket 对端）、`DeviceControl_exe.md`（落地）、`MMPC_exe.md`（学生端根服务）
> 分析日期：2026-09-18

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 1684480 字节 |
| MD5 | `022b8f1be58b9c02a0d4f0022d038f0f` |
| SHA-256 | `781bd0878cc5b16bd6084715f3295ebf3b14c825a851d6f0ca2554155e9e60cf` | — |
| 格式 | PE32 DLL（`pei-i386`） |
| ImageBase / 入口 | `0x10000000` / `0x1013602a` |
| C++ 运行时 | MSVC14（`MSVCP140.dll` / `VCRUNTIME140.dll` / `api-ms-win-crt-*`） |

**导入 DLL**：
- 网络：`WS2_32`、`MSWSOCK`、**`libcurl.dll`**（`curl_easy_init/_setopt/perform/cleanup`，HTTP/HTTPS 客户端）
- 自定义：`MmcImplBase.dll`（MMC 实现基类）
- 系统：`KERNEL32`、`USER32`、`ADVAPI32`、`ole32`、`OLEAUT32`
- **静态库符号**：`boost.asio`（`win_iocp_socket_service`）、**`boost.beast`**（`websocket`/`http`，`A WebSocket protocol violation occurred`）→ **WebSocket 服务端**

---

## 1. 角色概述

`MainLogic.dll` 是**教师端（`Teacher.exe`）的逻辑核心库**——把 UI 动作翻译成对学生端的下发，覆盖两大块：

1. **教学交互**：屏幕广播/远程观看、远程控制、电子白板、考试（发卷/收卷/暂停/标准答案）、文件传输、举手/点名、排行榜/奖励、语音对讲。
2. **管控下发**：黑屏肃静（BlackSilent）、键盘锁定（`SetKeyBoardLock`）、断网/限速（`Limit`）、设备管控（`DeviceQuery`/`CanUseDeviceControl`）、运行看板（`ControlRunningBoard`）。

**网络拓扑**：MainLogic 是 **WebSocket 服务端**（`Buid WebSocket Server port:%d`），学生端 `MultiClient.exe` 是它的**客户端**（对端 boost.beast websocket）。教师指令经 WS 下发；另有 **libcurl HTTP 通道**（`http://host:port/channel_register`）用于 VDI 虚拟桌面/信道注册。

> 注意区分：`MainLogic` 是**教师端**逻辑（下发方）；`StudentLogic.dll` 才是学生端逻辑。学生端真正的设备管控**落地**在 `DeviceControl.exe`（回环 UDP 8454 → 各驱动），MainLogic/MultiClient 只负责"决策 + 下发"。

---

## 2. 导出 API（教师端接口，约 60 个）

按功能归类（被 `Teacher.exe` 调用，经内部事件投递 `FUN_10008a00` 触发实现）：

### 屏幕 / 远程 / 看板
| 导出 | 含义 |
|---|---|
| `StartRemoteControlToAll` / `StopRemoteControlToAll` | 对全体学生**远程控屏**开/停 |
| `SetRemoteCommand` / `StartRemoteCommand` | 下发远程控制命令 |
| `RemoteWatch` | 远程观看（截屏/监控学生屏） |
| `ControlRunningBoard` | 运行看板 |
| `SendFixedPosition` / `SendTSapceFuncMsg` / `GetTSpaceDesktopIpVector` / `GetVirtualDesktopipMap` | 固定位置 / TSpace 桌面 IP 向量 / 虚拟桌面 IP 映射 |

### 屏幕广播 / 黑屏肃静 / 语音
| 导出 | 含义 |
|---|---|
| `BlackSilent` / `StopBlackScreen` | **黑屏肃静**开/停（`BLACKLOCK mainlogic lock:%d`） |
| `TalkbackServerCast` / `AudioTalkSwitch` | 语音广播/对讲 |
| `SendImageFile` / `BroadCastRect` | 图像广播/广播区域 |

### 电子白板 / 画笔
| 导出 | 含义 |
|---|---|
| `SwitchOnWhiteboard` | 开启电子白板 |
| `PainterBardIsRuning` | 画笔是否运行 |

### 考试
| 导出 | 含义 |
|---|---|
| `ExamTchStart/Pause/Continue/End/Delay/Resend/Standard` | 考试 开始/暂停/继续/结束/延时/重发/标准答案 |
| `ExamSendFile` / `ExamFileTransferStart/End` / `GetExamFileTransferIps` | 发卷 / 收发文件 / 考试传输 IP |
| `AcceptFileSubmitRequst` / `AutoSumbitFile` | 接收/自动提交答卷 |
| `StartElectronicAnswer` | 电子答题 |

### 文件 / 通知
| 导出 | 含义 |
|---|---|
| `NotifyFile` / `SendMsgToWebClient` / `UpdateProgass` | 文件通知 / 给 Web 端发消息 / 更新进度 |
| `ReceiveFileFailed` | 收文件失败回调 |
| `SendCallSignToNewStudent` / `SendToCallSign` / `GetAttention` | 点名 / 呼叫 / 引起注意 |

### 管控
| 导出 | 含义 |
|---|---|
| `SetKeyBoardLock` | **键盘锁定** |
| `SetLockAfterNetWorkBroken` / `lockedAfterNetBroken` | 断网后锁定策略 |
| `Limit` | 断网/限速 |
| `DeviceQuery` / `CheckFilter` / `GetFilterMap` | 设备查询 / 过滤检查 |
| `LimitFileSize` | 文件大小限制 |

### 教学管理 / 生命周期
| 导出 | 含义 |
|---|---|
| `PublishRankingList` / `RewardFlower` / `UpdataStudentSign` / `SendStudentParaConfig` | 发排行榜 / 奖励小红花 / 更新学生标识 / 下发学生参数配置 |
| `GetConnectedTerminMacIp` / `GetUnique` / `GetOwner` | 获取终端 MAC/IP / 唯一标识 / 属主 |
| `Load` / `UnLoad` / `Assign` / `SetUiEx` / `SetTimeServerIP` / `Message` / `Quit` | 加载/卸载 / 分配 / UI 扩展 / 时间服务器 / 消息 / 退出 |
| `StartMusical` | 音乐 |

---

## 3. 网络通道

### 3.1 WebSocket 服务端
- `Buid WebSocket Server port:%d`（`FUN_...` @0x...207196 区）——boost.beast 建 **WS 服务端**，监听某端口，等待学生端 `MultiClient.exe` 连入。
- 协议与 MultiClient 对端一致（TLS + `sslkey.log`），承载广播/远程/管控/考试等全部下行指令与上行状态。

### 3.2 libcurl HTTP（VDI/信道注册）
```
config: RegisterServerIp + VdiChannelServerPort
POST/GET  http://<ip>:<port>/channel_register    （FUN_10008790 组 URL）
body:     ip=%s&channel=%d
```
- `CurlImpl::PostData`（`curl_easy_init/_setopt/perform`）封装；
- `[GetHttpsData] filepath :%s!`：HTTPS 数据获取；
- `Access-Control-*` 一组：CORS/预检头（说明有跨域 Web 交互）。

---

## 4. 指令下发模型

```
Teacher.exe UI 按钮
  → 调用 MainLogic 导出（如 StartRemoteControlToAll / SetRemoteCommand / BlackSilent）
  → FUN_10008a00（加锁 + 投递 std::function 到内部工作线程/事件）
  → 内部实现（FUN_100756d0 / FUN_10075c20 / FUN_10075df0 ...）
  → 组装下行消息（CtrlCode/type/start + 目标 ips[id]）
  → WebSocket 服务端广播/单发到学生端 MultiClient
     （学生端 MultiClient 收到 → 127.0.0.1 回环 → DeviceControl.exe → 各驱动落地）
```

- **多目标**：`[MainLogic][StartRemoteControlToAll][ip:%s][id:%d][type:%d]`、`SendToNewStudentPreCommand[xsys0/xsys1/ykzb][ips:%s][id:%d][type:%d]`——`type` 即指令码，`ips` 为批量学生。
- **广播类型**：`[MMPCSendBroadcastType] type:%s start:%d`、`[CanBroadcast %d] ret:%d show:%d`、`LISS_SDK_SendBroadcastTypeInternal`。
- **设备管控**：`[CanUseDeviceControl] ret:%d,support:%d`、`LISS_SDK_IsSupportMMCStrategy`、`LISS_SDK_SendMMCMonitorKeywordFilePath`（关键词监控）、`LISS_SDK_SendMMCStopStrategy`（停止策略）。
- 安全锁：`OE_CreateLock`/`OE_DeleteLock`/`OE_SafeLockIsBoolValueTrue`/`OE_SafeLockSetBoolValue`（线程安全锁封装）。

## 5. 关联子进程（教师端部署的媒体/渲染）

串中引用（教师端侧渲染/媒体进程）：`MultiRender.exe`、`MediaFileSender.exe`、`AudioRepeater.exe`/`AudioSender.exe`/`AudioDirectRepeater.exe`/`AudioFrom`、`BkAudioVirtualDevice`、`AudioUdpVerityPort`/`LocalAudioPort`/`MacUdpVerityPort`（UDP 语音校验/本地/网段端口）。

## 6. 配置 / 日志

- 配置：`GetPrivateProfileStringW` / `GetProfile` / `ProfileObject`（INI/配置文件），字段如 `RegisterServerIp`、`VdiChannelServerPort`、`ConnectPort`/`controller_port`/`controller_host`、`ChannleScanPort`、`fileTransferPort`/`FileNodeManagerPort`、`MacroPort`。
- 日志：`FUN_1000d5e0`（printf 式，`[MainLogic][...]` 前缀）。

## 7. 关键函数/字符串索引（x86）

| 地址/串 | 职责 |
|---|---|
| `0x10019d10` `StartRemoteControlToAll` | 远程控屏开（导出） |
| `0x10019d70` `StopRemoteControlToAll` | 远程控屏停（导出） |
| `0x10019d40` `StopBlackScreen` / `BlackSilent` | 黑屏肃静 |
| `0x10019d80` `SwitchOnWhiteboard` | 电子白板 |
| `FUN_10008a00` | 事件投递（加锁 + std::function） |
| `FUN_100756d0`/`0x10075c20`/`0x10075df0` | 远程/黑屏 内部实现 |
| `0x101181` 区 | `channel_register`（libcurl，VDI 信道注册） |
| `0x207196` 区 | `Buid WebSocket Server port:%d`（WS 服务端） |
| `FUN_10008790` | URL 格式化（`http://%s:%d/channel_register`） |
| `CurlImpl::PostData` | libcurl POST 封装 |
| `IdpScreenClient::DealSendLogic::<lambda>` | 屏幕逻辑处理 |

## 8. 与体系的关系

```
教师端 Teacher.exe（UI）
  → MainLogic.dll（本组件：教师端逻辑核心，~60 个教学+管控 API）
      ├─ WebSocket 服务端（boost.beast）⇄ 学生端 MultiClient.exe（客户端，TLS/sslkey.log）
      ├─ libcurl HTTP：/channel_register（VDI 虚拟桌面信道注册）
      └─ 指令组装（CtrlCode/type/start + ips[id]）
              ↓ 下行（经 MultiClient 回环）
          学生端 DeviceControl.exe（UDP 8454）→ easyusb/OeNetlimit/KbFilter/FbdATS/…（落地）
      教师端媒体进程：MultiRender/MediaFileSender/AudioRepeater/…（渲染/语音）
```

## 9. 未决项

1. **WebSocket 下行帧格式**（指令码 `type` 枚举、屏幕帧/控制帧编码）——需结合 `sslkey.log` 解密抓包，或逆向 MultiClient 端解析（两端对拍）。
2. `channel_register` 的完整请求/响应与 VDI 信道语义（`VdiChannelServerPort` 服务端归属）。
3. 各导出内部实现的**线程模型**（`FUN_10008a00` 投递到哪个工作线程/队列，与 WS 服务端线程的同步）。
4. `CtrlCode` 位定义与 `DeviceControl.exe` 的 `CtrlCode` 位掩码（`0x1`网络/`0x2`键盘/`0x10`应用/`0x100000`白黑名单/`0x1000`DUOC）的映射关系。
5. 电子白板/画笔（`SwitchOnWhiteboard`/`PainterBardIsRuning`）与 `drawRangle/`（样本目录）的关系。

---

*本文覆盖：MainLogic.dll 指纹与技术栈（boost.beast WS 服务端 + libcurl + MmcImplBase）、角色（教师端逻辑核心）、~60 个导出 API 全归类、WebSocket/HTTP 通道、指令下发模型、关联媒体子进程、配置/日志、函数索引、与学生端 MultiClient/DeviceControl 的体系关系。*