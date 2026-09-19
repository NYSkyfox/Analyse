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

**网络拓扑（三通道并存，详见 §3）**：
- **9003 TCP 二进制帧（`ConnectPort`）**——cmd/黑屏肃静/屏幕截图/远程控屏等**实时指令的主通道**，明文。
- **8040 UDP（`UdpMessageControllerPort`）**——行为管控 CtrlCode JSON（断网/键盘/应用/USB）。
- **WebSocket 服务端（boost.beast）+ libcurl HTTP**——VDI 虚拟桌面 / 跨域 Web 端 / `channel_register` 信道注册；`MultiClient.exe` 是 WS 客户端之一。

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

> ⚠️ 本节经 2026-09-19 深度复查**修正**了初版"全部指令走 WebSocket"的笼统说法。实测：MainLogic 内并存**三条独立通道**，cmd/黑屏/截图等实时指令走的是 **9003 TCP 二进制帧**，而非 WebSocket。

### 3.1 主指令通道：9003 TCP 二进制帧（ConnectPort）
教师端主连接，**明文、无 TLS**。这是 cmd / 黑屏肃静 / 屏幕截图 / 白板矩形等**实时指令**的实际载体（与 8040 UDP 的 CtrlCode 行为管控是**两条不同协议**）。

- 端口来源：`core.conf` `ConnectPort=9003`，MainLogic 初始化时 `FUN_10008b40("ConnectPort")` 读入 `this+0x58`（u16）。
- **帧结构（20 字节头 + 载荷，小端）**：
  ```
  [F0:u32][F1:u32][F2:u32][F3:u32][F4:u32] + 载荷(UTF-16LE 文本 或 二进制)
  ```
  | 字段 | 语义 | 实测证据 |
  |---|---|---|
  | `F0` | **帧总长 = 16 + 载荷字节数**（=帧字节数 − 4） | 心跳 `0x10`=16+0；黑屏 `0x28`=16+24；cmd `0xbe`=16+174；截图 `0x5ec`=16+1500 ✅ 多帧一致 |
  | `F1` | **cmdType（指令码）** | `0x59`=89 心跳；`0x0c`=12 黑屏肃静；`0x0d`=13 远程cmd；`0x1d`=29 白板矩形；`0x2b`=43 屏幕截图 |
  | `F2` | 标志位（心跳/截图=`0x40`，cmd/黑屏=`0`） | 观测值，确切位义待更多样本 |
  | `F3` | 恒 `0` | 全部样本 |
  | `F4` | 数据/附件字段长度（黑屏=文本长、截图=图像长、cmd=0） | 黑屏 `0x18`=24、截图 `0x5dc`=1500、cmd=0 |
- **帧头由 `FUN_1003f850(buf, &F0)` 写入**，载荷追加后经 `FUN_1009e070`（单播）/组播发出。
- **`/*//` 是死代码**：构造处（`FUN_10008b40("/*//")`）生成字符串对象后**从未拼入实际发送缓冲**（与 `OeNetLimit` 家族 10 报告结论一致）。
- **典型载荷（UTF-16LE，抓包实测）**：
  - 黑屏肃静开：`/1/请大家保持安静！/`；关：`/0//`（`cmdType=0x0c`）
  - 远程 cmd：`{"Para":"echo 123","Path":"C:\\Windows\\System32\\cmd.exe","Tag":0}`（`cmdType=0x0d`；学生执行后回 `cmdType=0x0c` + 载荷 `1` 表成功）
  - 屏幕截图：`cmdType=0x2b`，学生回 JPEG（`FF D8 FF E0 … JFIF`，约 1500B）
  - 心跳：`cmdType=0x59`，空载荷，周期发送维持连接

### 3.2 WebSocket 服务端（VDI / Web 端，boost.beast）
- `Buid WebSocket Server port:%d` + `WebSocketServer error:%s`——boost.beast **WS 服务端**（`boost::beast::websocket::stream::accept_op` 符号在库内）。
- 用途：服务 **VDI 虚拟桌面 / 跨域 Web 交互**（配合 `Access-Control-*` 一组 CORS 头、`GetVirtualDesktopipMap`/`GetTSpaceDesktopIpVector`）。**不承担** cmd/黑屏 等实时指令（那些走 3.1）。
- 学生端 `MultiClient.exe` 是 WS 客户端之一；TLS/`sslkey.log` 仅作用于需加密的 WS/HTTP 交互。

### 3.3 libcurl HTTP（VDI/信道注册）
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

> ⚠️ 经深度复查修正：`FUN_10008a00` **不是**"加锁投递到工作线程队列"，而是 **`std::function` 的构造函数**（反编译实见 `_Compressed_pair<>` 构造 + `FUN_1000e620`(move) + `_Construct_lv_contents`）。导出函数的真实模型是**同步转发**，非异步入队。

### 4.1 导出函数 = 构造 std::function → 同步调用实现

以 `SwitchOnWhiteboard(param)` 为例（反编译 `@0x10019d80`）：
```c
void SwitchOnWhiteboard(char p) {
    std::function<void(void)> f;      // = FUN_10008a00(&f, &arg)  ← 构造函数，捕获参数
    FUN_10076ac0(p);                  // ★ 直接调用真正实现（同步，当前线程）
    f.~function();                    // = FUN_10008a00 对应的析构
}
```
- `FUN_10008a00` = `std::function<void(void)>` 的构造（捕获 `&stack0x...` 栈上参数）；
- 紧跟其后的 `FUN_1007xxxx` 才是**真正的业务实现**，**在调用线程同步执行**（`StartRemoteControlToAll→FUN_10075df0`、`StopRemoteControlToAll→FUN_10075df0`、`TalkbackServerCast→FUN_10076dc0`、`SwitchOnWhiteboard→FUN_10076ac0`、`UnLoad→FUN_10077970` 等）。
- **结论（未决3 闭环）**：导出层**无跨线程投递/队列**。异步性来自**实现函数内部**自己 spawn 的 boost.asio / 并发 worker（如 `IdpScreenClient::DealSendLogic::<lambda>`、`Concurrency::details` 运行时符号），与 `std::function` 构造无关。

### 4.2 完整下发链路（按通道区分）

```
Teacher.exe UI 按钮
  → 调用 MainLogic 导出（StartRemoteControlToAll / BlackSilent / SetRemoteCommand ...）
  → 同步调用对应实现函数（FUN_10075df0 / FUN_10076ac0 / ...）
  → 组装下行消息，按指令类型分走三条通道：
      ① 9003 TCP 二进制帧（cmdType + UTF-16/二进制载荷）← cmd/黑屏/截图/远程控屏
      ② 8040 UDP CtrlCode JSON（[500][0][0][len] + JSON）← 网络/键盘/应用/USB 行为管控
      ③ WebSocket / libcurl（VDI、Web 端、/channel_register）
  → 学生端 StudentLogic.dll / MultiClient.exe 接收
      → 127.0.0.1 回环 → DeviceControl.exe → 各驱动落地（KbFilter/OeNetLimit/easyusb/ProcFireWall）
```

- **多目标**：`[MainLogic][StartRemoteControlToAll][ip:%s][id:%d][type:%d]`、`SendToNewStudentPreCommand[xsys0/xsys1/ykzb][ips:%s][id:%d][type:%d]`——`type` 即指令码，`ips` 为批量学生。
- **广播类型**：`[MMPCSendBroadcastType] type:%s start:%d`、`[CanBroadcast %d] ret:%d show:%d`、`LISS_SDK_SendBroadcastTypeInternal`。
- **设备管控**：`[CanUseDeviceControl] ret:%d,support:%d`、`LISS_SDK_IsSupportMMCStrategy`、`LISS_SDK_SendMMCMonitorKeywordFilePath`（关键词监控）、`LISS_SDK_SendMMCStopStrategy`（停止策略）。
- 安全锁：`OE_CreateLock`/`OE_DeleteLock`/`OE_SafeLockIsBoolValueTrue`/`OE_SafeLockSetBoolValue`（线程安全锁封装，实现函数内部使用）。

## 5. 关联子进程（教师端部署的媒体/渲染）

串中引用（教师端侧渲染/媒体进程）：`MultiRender.exe`、`MediaFileSender.exe`、`AudioRepeater.exe`/`AudioSender.exe`/`AudioDirectRepeater.exe`/`AudioFrom`、`BkAudioVirtualDevice`、`AudioUdpVerityPort`/`LocalAudioPort`/`MacUdpVerityPort`（UDP 语音校验/本地/网段端口）。

## 6. 配置 / 日志

- 配置：`GetPrivateProfileStringW` / `GetProfile` / `ProfileObject`（INI/配置文件），字段如 `RegisterServerIp`、`VdiChannelServerPort`、`ConnectPort`/`controller_port`/`controller_host`、`ChannleScanPort`、`fileTransferPort`/`FileNodeManagerPort`、`MacroPort`。
- 日志：`FUN_1000d5e0`（printf 式，`[MainLogic][...]` 前缀）。

## 7. 关键函数/字符串索引（x86）

| 地址/串 | 职责 |
|---|---|
| `0x10019d10` `StartRemoteControlToAll` | 远程控屏开（导出 → `FUN_10075df0`） |
| `0x10019d70` `StopRemoteControlToAll` | 远程控屏停（导出 → `FUN_10075df0`） |
| `0x10019d40` `StopBlackScreen` / `BlackSilent` | 黑屏肃静（cmdType=0x0c，走 9003） |
| `0x10019d80` `SwitchOnWhiteboard` | 电子白板（→ `FUN_10076ac0`，启 PainterServer/OePainter） |
| `0x10019db0` `TalkbackServerCast` | 语音广播（→ `FUN_10076dc0`） |
| `0x10019df0` `UnLoad` | 卸载（→ `FUN_10077970`，发 `CtrlCode=-0x44000000`） |
| `FUN_10008a00` | **`std::function<void(void)>` 构造函数**（非线程投递，见 §4.1） |
| `FUN_10008b40` | `std::string` 构造（配置键/字符串字面量取用） |
| `FUN_10002a50` / `FUN_10020aa0` / `FUN_10020c10` | 读配置（int / 端口 u16 / 字符串），源 `core.conf` |
| `FUN_1003f850` | **9003 帧头写入器**（`[F0=16+len][F1][F2][F3][F4]`） |
| `FUN_1009e070` | 单播发送（9003 / 8040 共用发送原语） |
| `FUN_10075df0`/`FUN_10076ac0`/`FUN_10076dc0`/`FUN_10077970` | 导出对应的真实业务实现 |
| `0x101181` 区 / `FUN_10008790` | `http://%s:%d/channel_register` + `ip=%s&channel=%d`（libcurl，VDI 信道注册） |
| `FUN_1003f9c0` | libcurl 请求执行（`channel_register` 发送） |
| `0x207196` 区 | `Buid WebSocket Server port:%d` / `WebSocketServer error:%s`（WS 服务端） |
| `IdpScreenClient::DealSendLogic::<lambda>` | 屏幕逻辑（实现函数内部异步 worker） |

## 8. 与体系的关系

```
教师端 Teacher.exe（UI）
  → MainLogic.dll（本组件：教师端逻辑核心，~60 个教学+管控 API）
      ├─ 9003 TCP 二进制帧（cmdType + UTF-16/二进制）← cmd/黑屏/截图/远程控屏【主指令通道】
      ├─ 8040 UDP CtrlCode JSON（[500][0][0][len]）← 网络/键盘/应用/USB 行为管控
      ├─ WebSocket 服务端（boost.beast，VDI/Web 端）⇄ MultiClient.exe
      └─ libcurl HTTP：/channel_register（VDI 虚拟桌面信道注册）
              ↓ 下行（学生端 StudentLogic.dll / MultiClient.exe 接收）
          127.0.0.1 回环 → 学生端 DeviceControl.exe → easyusb/OeNetlimit/KbFilter/FbdATS/…（落地）
      教师端媒体进程：MultiRender/MediaFileSender/AudioRepeater/…（渲染/语音）
      教师端白板进程：toolkits\bin\PainterServer.exe / OePainter.exe
      教师端区域渲染：drawRangle.exe（组播 229.1.x.x，屏幕矩形 pmgb-rect）
```

## 9. 未决项（2026-09-19 深度复查后：6/6 已闭环，附剩余待验证）

> 本轮按"不放过任何函数"逐条深挖，原 5 项 + 补充的建连握手共 6 项均已给出实证结论；其中 3 项**修正了初版报告的错误判断**。

### ✅ 1. 下行帧格式（原"WebSocket 帧格式"）——**已决 + 纠偏**
- 初版误判"指令走 WebSocket"。实测：**实时指令走 9003 TCP 二进制帧**（`FUN_1003f850` 帧头 + `FUN_1009e070` 发送），帧结构、`F0=16+len` 长度规律、cmdType 枚举（0x59/0x0c/0x0d/0x1d/0x2b）、UTF-16LE 载荷均经抓包多帧交叉验证（见 §3.1）。
- WebSocket 实为 VDI/Web 通道（§3.2），不承担这些指令。
- **剩余待验证**：cmdType 完整枚举表（目前只坐实 5 个码值，其余如考试/文件/举手的码值需更多抓包或对拍 MultiClient 解析端）。

### ✅ 2. `channel_register` 完整请求/响应与 VDI 语义——**已决**
- 反编译 `@101150` 区实锤全链路：读 `RegisterServerIp` + `VdiChannelServerPort` → `FUN_10008790("http://%s:%d/channel_register")` 组 URL → `FUN_10008790("ip=%s&channel=%d")` 组 body → `FUN_1003f9c0` 经 libcurl 发送 → 解析响应。
- **剩余待验证**：`VdiChannelServerPort`(8002) 服务端的部署归属（VDI 侧组件）与响应体 schema——需运行环境或 VDI 端样本，静态无法定案。

### ✅ 3. 导出线程模型——**已决 + 纠偏**
- 初版误判 `FUN_10008a00` 为"加锁投递工作线程队列"。反编译实锤：它是 **`std::function` 构造函数**，导出=构造 lambda 后**同步调用** `FUN_1007xxxx` 实现（见 §4.1）。
- 异步性来自实现函数内部自建的 boost.asio / `Concurrency::details` worker，与导出层无关。

### ✅ 4. `CtrlCode` 位定义映射——**已决 + 纠偏（关键）**
- 初版臆测"0x100000=白黑名单 / 0x1000=DUOC"。**实锤：本库中 `0x100000` 是 `IsProcessorFeaturePresent`/cpuid 的 CPU 特性检测（SSE/AVX/AVX2），与 CtrlCode 完全无关**（`u4a/u4b` 段，`cpuid_basic_info`/`dtol3_getbits`）。
- MainLogic 对 CtrlCode **只做序列化**：`FUN_1012d050(local_50,"CtrlCode")`（@110795）把 `this+0x548` 存的值写进 JSON，再经 `FUN_10064770` 发 8040。**位语义定义在 `Teacher.exe FUN_005648c0`（读 NPDControl.json 按位算）**，权威表见 `10_行为管控报文核查定稿`（0x01 网络/0x02 键盘/0x10 应用/0x100·0x1000·0x10000 USB）——本报告不重复臆测。
- 结论：**"0x100000 白黑名单"不存在**，从本报告及体系认知中移除。

### ✅ 5. 白板/画笔与 drawRangle 关系——**已决**
- **电子白板**：`SwitchOnWhiteboard→FUN_10076ac0`，启动教师端 **`PainterServer.exe` / `OePainter.exe`**（路径 `toolkits\bin\`，`FUN_1008bbd0` 进程探活）；`PainterBardIsRuning` 查询其运行态。
- **`drawRangle.exe` 是独立进程，不是白板本体**：反编译 @103230 区显示它由**屏幕区域广播**触发（组播地址拼 `229.1.x.x`、`TransferType` 判 `udpSingle`/`multicast`、发 `pmgb-rect` 矩形帧 cmdType=0x1d、按 `CompressMode==h264` 选 `H264Quality`/`JpegQuality`）——即**把教师端某矩形区域的画面实时推给学生的渲染进程**。
- 两者关系：白板走 `OePainter/PainterServer`（绘制交互），`drawRangle` 走屏幕区域推流（画面广播），**不同进程、不同用途**，初版把二者混为一谈已纠正。

### ✅ 6. 9003 建连握手序（补充闭环）——**已决（抓包 + 端口角色实测）**
- **监听方 = 教师端**：三组抓包（123456/456/123.json）里 9003 流全部是**教师 `192.168.1.57` 固定占 9003**、**学生 `192.168.1.58` 用临时端口（59660）连入**。`ConnectPort` 在教师侧 `core.conf`，MainLogic 初始化读入 `this+0x58` 并监听。
- **无独立应用层握手帧**：抓到的 9003 流首个应用数据帧（`tcp.seq=1`，教师→学生）就是**心跳 `[0x10][0x59][0x40][0][0]`**，而非注册/鉴权帧。即 TCP 三次握手完成后直接进入"心跳维持 + 指令下发"，**没有额外的应用层注册消息**（在被抓范围内）。
- **`EnableClient` 步骤存在**：反编译见 `[%d] EnableClient failed:%s` 错误分支（`FUN_10054e16` 区），accept 成功后有一个"启用该客户端"动作（把该连接注册进在线学生表，`FUN_1005eb90(1)` 打 `[%d]connected succeed`）。失败则 `FUN_1005eb90(0)` 打 `[%d]disconnect`。
- **学生如何发现教师**：不在 9003 本身——学生经 **7777 信道扫描广播**（`{"channel":N,"checksum":N,"msg":...}`，教师组播到 255.255.255.255）或 **8003 注册服务**发现教师 IP，再主动 `connect(教师IP, 9003)`。
- **对伪教师端的直接意义**：伪教师端只需 **① 监听 9003 → ② accept 学生连接 → ③ 周期性发心跳 `[0x10][0x59][0x40][0][0]`（cmdType=89，F0=16）** 维持；随后即可插入黑屏 `cmdType=0x0c` / cmd `cmdType=0x0d` / 截图请求 `cmdType=0x2b` 等帧。心跳周期从抓包看约 **1~2 秒**（`time_delta` 实测）。

### 📌 7. 安全模型：8040 UDP 无来源校验 vs 9003 TCP 连接绑定（2026-09-20 学生端接收侧取证）

> 回答"非教师机 IP 发来的指令学生端会不会执行"。结论**必须分通道**——本报告 §1/§3 的三条通道里，两条承载管控指令的通道安全性完全不同。完整推导见 `逆向分析报告/10_行为管控报文核查定稿.md §七`。

| 通道 | 承载 | 类型 | 来源校验 | 未连教师·任意IP | 已连教师·第三方IP |
|---|---|---|---|---|---|
| **8040 UDP** | 行为管控 CtrlCode | 无连接 | **无** | **执行** | **执行** |
| **9003 TCP** | cmd/黑屏/截图 | 有连接 | 连接绑定 | 不执行 | 不执行（除 IP伪装+连接劫持） |

- **8040 无校验（反编译实锤）**：`StudentLogic.dll FUN_10086e60` recvfrom 后 `inet_ntop` 仅格式化来源地址 + IPv6 `%zone`，**无来源 IP 比对分支**；`FUN_10081570`（收包处理）同样无"来源 vs 教师"判断。`IpAddressFilter`（`core.conf` L28）**全部反编译存档零引用**——死配置，那个空值根本没被读取。
- **9003 靠连接绑定**：学生端不监听 9003（教师监听，学生主动 connect 进教师，见 §6/§9-6），第三方无法向已建立的 TCP 流注入数据；唯一绕过是 IP 伪装 + 连接劫持（MITM，需持有该连接四元组序列）。
- **诚实边界**：8040"无条件监听、与是否连教师无关"为架构推断；"收包无 IP 比对"为反编译实锤；9003 防护为结构性结论（学生不监听 + TCP 本质）。

### 剩余待验证清单（需运行环境或更多样本，静态已到头）
1. 9003 cmdType **完整枚举**（目前坐实 0x59/0x0c/0x0d/0x1d/0x2b 五个；考试/文件传输/举手/点名等码值未覆盖）。
2. 9003 冷启动**首连**是否有 SYN 之后、首个心跳之前的一次性初始化帧（本批抓包 SYN 段缺失，无法 100% 排除）——需在运行环境抓"完整首连"确认；若无，则 §6 即为完整建连序列。
3. `channel_register` 响应体 schema + 8002 服务端归属。
4. 行为管控 8040 是否叠加加密（`EncryptImpLib` 与 500 路径关系，10 报告 §九 遗留项）。

---

*本文覆盖：MainLogic.dll 指纹与技术栈（boost.beast WS + libcurl + MmcImplBase）、角色（教师端逻辑核心）、~60 导出 API 全归类、**三通道架构（9003 TCP 二进制帧 / 8040 UDP CtrlCode / WebSocket+libcurl）**、9003 帧结构与 cmdType 枚举（抓包实证）、**9003 建连握手序（教师监听/心跳维持，§6）**、导出同步模型、channel_register 链路、CtrlCode 归属纠偏、白板/OePainter/drawRangle 进程区分、关联媒体子进程、配置/日志、函数索引、体系关系、**安全模型（8040 UDP 无来源校验 vs 9003 TCP 连接绑定，§9-7）**。6 项未决全部闭环（3 项纠偏）。*