# MultiClient.exe 组件深度逆向（学生端多媒体/交互客户端）

> 样本：`samples/os-easy/MultiClient.exe`（1189376 字节，PE32 i386）
> 配套日志：`samples/os-easy/MultiClient.txt`（运行时 `Lock.cpp` 键盘锁日志）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`，`x86:LE:32:default`）+ objdump + strings
> 工程：`/projects/multicl`
> 反编译存档：`/root/ghidra/mmpc/multicl_x86.txt`（9710 函数，5.59MB）
> 关联：`DeviceControl_exe.md`（本地管控落地层）、`MMPC_exe.md`（根服务）、`MMCHelper`/LISS SDK
> 分析日期：2026-09-18

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 1189376 字节 |
| MD5 | `b8bb9b809e8f45918f6759d4cb51f5b0` |
| SHA-256 | `c04f76349cc95b92cea33d9ae3ed2a7a402b46004aa80a31c587a6e13c4c79a9` |
| 格式 | PE32 EXE（`pei-i386`） |
| ImageBase / 入口 | `0x400000` / `0x4dc97a`（`entry`） |
| C++ 运行时 | MSVC14（`MSVCP140.dll` / `VCRUNTIME140.dll` / `api-ms-win-crt-*`） |

**导入 DLL**：`KERNEL32`、`USER32`、`SHELL32`、`OLEAUT32`、`WS2_32`、`IPHLPAPI`、`MSVCP140`、`VCRUNTIME140`、CRT。
**静态库（模板符号）**：`boost.asio`（`win_iocp_socket_service`）、**`boost.beast::websocket`**（`stream`/`handshake_op`/`idle_ping_op`/`http`）——**基于 boost.beast 的 WebSocket 客户端**。
**运行时动态加载**：`LISS*SDK*.dll`（`initLissHelper`）、`LockKeyboard.dll`。

---

## 1. 角色概述

`MultiClient.exe` 是**学生端的"多媒体 + 交互"客户端**，承担四块职责：

1. **与教师端建立 WebSocket 长连接**（boost.beast 异步协程），接收教师指令、上报状态；
2. **屏幕广播**（接收教师屏幕帧，全屏/窗口渲染，`StartCheckDesktop`/`FullScreen`）；
3. **键盘/鼠标锁定**（本地 `LockKeyboard.dll` + 驱动设备，`MouseAndKeyBoardLock` 等）；
4. **LISS（TCloud 平台）集成**：登录 UI 探测、MMC 策略、广播类型下发、关键词监控、停止策略。

它**不是**本地管控落地层——设备类管控（网络/USB/应用）由 `DeviceControl.exe`（回环 UDP 8454）落地；MultiClient 收到教师 WebSocket 指令后，把"广播类型/设备控制"这类指令**转发到本机回环**（`127.0.0.1`）交给 DeviceControl/MMPC 处理。

---

## 2. WebSocket 通道（boost.beast）

- 库：`boost.beast::websocket::stream<basic_stream_socket<tcp,asio>>`，`win_iocp_socket_service`（IOCP 异步）。
- 协程式读写（`coro_handler`）：日志串 `[%d]websocket read coroutine failed:%s`、`[%d]websocket resolve coroutine failed:%s`、`[%d]WebSocket write error: %s`、`A WebSocket protocol violation occurred`。
- **TLS**：设置 `SSLKEYLOGFILE`，密钥记录到 **`C:\ProgramData\LISSClient\sslkey.log`**（`[SetLissSslKey] failed` / `SSLKEYLOGFILE`）——即 WebSocket 走 TLS，并落 TLS 密钥日志。
- 连接目标（教师端地址/端口）**不硬编码在字符串中**，由 LISS SDK / 运行配置动态解析（见 §5）。

## 3. 屏幕广播

- `[DataLogic][StartCheckDesktop][FullScreen][%d]`：启动桌面检查 + 全屏标志。
- `dmt_screen_open` / `dmt_screen_close`：屏幕打开/关闭（多处调用，含全屏与窗口两种形态）。
- `fullscreen`、`GetConsoleWindow`：全屏切换与窗口定位。
- 音频广播：引用 **`AudioRender.exe`**（教师端语音/媒体渲染进程）。

## 4. 键盘 / 鼠标锁定

- 用户态开关：`MouseAndKeyBoardLock Enable()/Disable()`、`KeyBoardLock Enable()/Disable()`、`MouseLock Disable()`、`DisableKeyboard` / `EnableKeyboard`（日志 `Lock.cpp:60/113/52/58/104/111`）。
- 加载 **`LockKeyboard.dll`**（宽串 `dLockKeyboard.dll`）执行锁定。
- 驱动设备探测：`CreateFileW(path, 8, 7, NULL, 3, 0x2200000)` → `DeviceIoControl(h, 0x900A8, NULL,0, out, 0x4000, &n, NULL)`，读 0x4000 字节，前 4 字节为状态（`-0x5ffffff4`/`-0x5ffffffd` 判定"已锁定"）。
- 日志显示 `DisableKeyboard_CreateFile1 Failed! Error:2`（设备不存在）时仍打印 `Lock keyboard success`——即**锁定以"尽力而为"方式执行**，设备缺失不视为失败。

## 5. 广播类型控制 + DeviceControl 联动（核心转发）

`FUN_00418d80`（发送广播类型）：
```c
obj = { "type": <type>, "broadcasttype": <bt>, "start": <start> };   // JSON
sendTo("127.0.0.1", json);   // FUN_0040d4b0(…, "127.0.0.1") + FUN_004d59c0(…)
```
- 日志串：`[MMPCSendBroadcastType] type:%s start:%d`、`[CanBroadcast %d] ret:%d show:%d`、`can-broadcast`。
- 通过 **LISS SDK** 下发：`LISS_SDK_SendBroadcastTypeInternal`、`LISS_SDK_IsSupportMMCStrategy`。
- 设备控制联动：`[CanUseDeviceControl] ret:%d,support:%d`、`[StopDeviceControl] No LissSDK`、`[SupportUseDeviceControl] No LissSDK`、`LISSNetInfoSniffer\LISSNetInfoSniffer.exe`。

即：MultiClient 作为**教师 WebSocket 指令 → 本机回环（DeviceControl/MMPC）的桥**，把"能否广播/广播类型/设备控制"转成回环消息。

## 6. LISS（TCloud 平台）集成

`initLissHelper` 动态加载 LISS SDK（`lissPath:%s` / `hMod SUCCESS` / `hMod failed[%d]`），使用函数：

| 函数 | 用途 |
|---|---|
| `LISS_SDK_InitIntance` / `LISS_SDK_FreeIntance` | 初始化/释放实例 |
| `LISS_SDK_IsLoginUiGoingToShow` | 登录 UI 是否即将显示 |
| `LISS_SDK_IsSupportMMCStrategy` | 是否支持 MMC 策略 |
| `LISS_SDK_SendBroadcastTypeInternal` | 下发广播类型 |
| `LISS_SDK_SendMMCMonitorKeywordFilePath` | 上报关键词监控文件路径（`[SendKeywordFilepath] No LissSDK`） |
| `LISS_SDK_SendMMCStopStrategy` | 下发停止策略 |

配套：`C:\ProgramData\LISSClient\sslkey.log`（TLS 密钥）、`LISSNetInfoSniffer\LISSNetInfoSniffer.exe`（网络信息嗅探）。

## 7. 日志

- 文件：`MultiClient.txt`（与 exe 同目录），格式 `[YYYY-MM-DD HH:MM:SS][ERROR][.\Lock.cpp,NN] msg`。
- 日志器：`FUN_00418820`（printf 式）、`FUN_0040d4b0`（带目标/参数）。

## 8. 关键函数索引（x86）

| 地址 | 职责 |
|---|---|
| `0x4dc97a` | `entry` |
| `0x418c90` | 键鼠锁启停（`MouseAndKeyBoardLock Enable/Disable`） |
| `0x418d80` | **发广播类型**（JSON `type/broadcasttype/start` → `127.0.0.1`） |
| `0x418ed0` | 广播相关处理 |
| `0x41af60` / `0x41ba30` | 广播类型发送/刷新 |
| `0x4187d0` | 广播前置准备 |
| `0x4bbf60` 区 | 驱动设备状态查询（`CreateFileW` + `DeviceIoControl 0x900A8`） |
| `0x40d4b0` | 发送（带目标 `127.0.0.1`） |
| `0x418820` | 日志（printf 式） |
| — | `initLissHelper`（LISS SDK 动态加载，字符串定位） |

## 9. 与体系的关系

```
教师端（MainLogic.dll / TCloud LISS）
  ↕ WebSocket(TLS, sslkey.log)
MultiClient.exe（本组件：屏幕广播 + 键鼠锁 + 广播类型 + LISS 集成）
  ├─ 设备/广播类型类指令 → 127.0.0.1（回环）→ DeviceControl.exe（UDP 8454）
  │                                            → easyusbctrl/OeNetlimit/…（落地管控）
  ├─ 屏幕帧 → 全屏/窗口渲染（dmt_screen_open/close, FullScreen）
  ├─ 键鼠锁 → LockKeyboard.dll + 驱动设备(0x900A8)
  └─ 语音 → AudioRender.exe
MMPC.exe（根服务，守护 MultiClient/DeviceControl 等）
```

## 10. 未决项

1. **WebSocket 连接目标**（教师端 host:port）的确定方式——由 LISS SDK/运行配置解析，需运行态或 LISS SDK 逆向确认具体字段。
2. WebSocket 帧协议（消息类型、指令码、屏幕帧编码/压缩格式）——需结合 `sslkey.log` 解密抓包（用户工作区已有 `netctrl_capture.py`/`oseasy_pure_capture.py` 抓包脚本可复用）。
3. 键鼠锁驱动设备的**确切设备名**（`CreateFileW` 的 `param_1` 由调用方传入，需回溯上游）；`0x900A8` 的完整语义。
4. LISS SDK 各函数的入参结构（`SendBroadcastTypeInternal` 等）。
5. `dmt_screen_*` 屏幕协议与教师端渲染端（`ScreenRender.exe`/`ScreenRender_Y.exe`）的关系。

---

*本文覆盖：MultiClient.exe 指纹、技术栈（boost.beast WebSocket + LISS SDK + VC14）、WebSocket 通道与 TLS 密钥日志、屏幕广播、键鼠锁（LockKeyboard.dll + 驱动设备 0x900A8）、广播类型控制与 DeviceControl 回环联动、LISS 平台集成、日志、函数索引、与体系的关系。*