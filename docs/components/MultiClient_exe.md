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

### 3.1 命令分发：全屏广播 vs 窗口广播（2026-10 补充，字节坐实）

**核心结论：教师端的"全屏屏幕广播"与"窗口广播"是两条相互独立的代码路径，不存在同一个函数内的 `if(fullscreen) lock else no_lock` 分支。**

命令分发器 `FUN_0040F790`（文件偏移 `0xEB90`，size 0x44F）解析教师端命令后按类型调用不同子函数：

| 命令 | 分发器调用点 (off) | 目标函数 | 行为 |
|---|---|---|---|
| **全屏屏幕广播** | `0xEF69` | `FUN_00419100`（off `0x18500`） | **锁鼠标 + 锁键盘 + 启动全屏 ScreenRender** |
| **窗口广播** | 独立分支 | 不经过 `0x18500` | 不锁键鼠 + 启动窗口 ScreenRender |

证据：
- `0x18500`（全屏广播+锁）的 **EIP 相对 call 引用全文件唯一**，就在分发器 `0xEF69`，且该 call **无条件**（无 fullscreen 标志门控）。
- `0x18500` 内部含鼠标锁 call：`0x185DE: call 0x41AE10`（鼠标锁执行器，见 §4）。
- 全文件扫描 `[reg+0x34]` 读/写：**0x18xxx（锁键鼠区）没有任何读取**——锁键鼠不受 fullscreen 标志控制。
- `[ecx+0x34]` 写入点 `0x2B1A3`（`mov [ecx+0x34],eax`，见 §3.2）位于"recv fullscreen"函数 `FUN_0042B8C0`（off `0x2ACC0`）内，**只写 ScreenRender 的全屏标志，不触发锁**。

### 3.2 fullscreen 标志 `struct+0x34`（2026-10 补充）

```asm
; "recv fullscreen" 函数 FUN_0042B8C0 (off 0x2ACC0)
; off 0x2B198:  mov eax, [ebp-0x41C]     ; eax = 教师端 fullscreen 值 (1=全屏/0=窗口)
; off 0x2B19E:  mov ecx, [ebp-0x450]     ; ecx = 内部状态结构体
; off 0x2B1A3:  mov [ecx+0x34], eax      ; ← 写 fullscreen 标志（唯一写入点）
; off 0x2B1AD:  push 0x4EFE8C            ; "recv fullscreen: %d"
```

该结构体字段 `+0x34` 后续被 `FUN_0042B444`（off `0x2A844`，`[DataLogic][StartCheckDesktop][FullScreen][%d]` 日志函数）读取，用于决定 `ScreenRender.exe` 以 `#fullscreen#:1` 还是 `#fullscreen#:0` 启动。**它不门控键鼠锁**（§3.1 已证）。

`ScreenRender.exe` 启动处 `FUN_0041A3B0`（off `0x197B0`），命令行模板字符串 `"ScreenRender.exe "` @ `0x4EDB88`，`fullscreen` 键名 @ `0x4EDBD8`。

## 4. 键盘 / 鼠标锁定

- 用户态开关：`MouseAndKeyBoardLock Enable()/Disable()`、`KeyBoardLock Enable()/Disable()`、`MouseLock Disable()`、`DisableKeyboard` / `EnableKeyboard`（日志 `Lock.cpp:60/113/52/58/104/111`）。
- 加载 **`LockKeyboard.dll`**（宽串 `dLockKeyboard.dll`）执行锁定。
- 驱动设备探测：`CreateFileW(path, 8, 7, NULL, 3, 0x2200000)` → `DeviceIoControl(h, 0x900A8, NULL,0, out, 0x4000, &n, NULL)`，读 0x4000 字节，前 4 字节为状态（`-0x5ffffff4`/`-0x5ffffffd` 判定"已锁定"）。
- 日志显示 `DisableKeyboard_CreateFile1 Failed! Error:2`（设备不存在）时仍打印 `Lock keyboard success`——即**锁定以"尽力而为"方式执行**，设备缺失不视为失败。

### 4.1 锁的触发链路（2026-10 补充，字节坐实）

**键鼠锁只在"全屏屏幕广播"路径触发**（§3.1 `0x18500`），窗口广播路径不触发。锁分两部分：

**鼠标锁（MultiClient 自身执行）**
- 执行器 `FUN_0041AE10`（文件偏移 `0x1A210`，RVA `0x1AE10`），序言 `55 8b ec 6a ff 68 c6 f7`。
- 4 个 EIP 相对调用者：`0x185D7` / `0x18630` / `0x189B4` / `0x2CFA3`。其中 `0x185DE`（全屏广播函数 `0x18500` 内）即广播触发点。
- 调用者附近**不读** `[reg+0x34]`（fullscreen 标志）→ 鼠标锁不是由 fullscreen 值门控，而是由"是否走全屏广播路径"决定。

**键盘锁（MultiClient 发 IPC → StudentLogic 执行）**
- MultiClient 字符串 `MouseAndKeyBoardLock` @ `0x4EBA04`，push 引用在 off `0x188D1`（`0x18xxx` 全屏广播区内）→ 组装 `MouseAndKeyBoardLock` 命令经回环 IPC 下发给 `StudentLogic.dll`。
- 由 StudentLogic 真正调 `LockKeyboard.dll` / `KbFilter.sys`（见 `StudentLogic_dll.md`、`KbFilter_sys.md`）。

**为什么键盘锁不在 MultiClient 直接执行、而发给 StudentLogic：**
- `KbFilter.sys` 为 **x64 内核驱动**，`KbDriver.exe` 亦 x64；`LockKeyboard.dll` 标称 x86 但需经 IOCTL 驱动操作。
- 将键盘锁集中到 StudentLogic（Student.exe 宿主内）统一执行，便于管理键盘锁生命周期（锁/解锁/异常恢复），避免 MultiClient（纯网络/分发角色）崩溃后键盘锁死。
- 职责分离：**MultiClient 负责"说"（组装+下发锁命令），StudentLogic 负责"做"（驱动级执行）**。

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
| `0x40F790` | **命令分发器**（全屏/窗口广播分叉，off `0xEB90`） |
| `0x419100` | **全屏广播启动**（含鼠标锁 + 键盘锁 IPC + 全屏 ScreenRender，off `0x18500`） |
| `0x41AE10` | **鼠标锁执行器**（off `0x1A210`，4 个调用者） |
| `0x42B8C0` | "recv fullscreen" 命令处理（写 `struct+0x34`，off `0x2ACC0`） |
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