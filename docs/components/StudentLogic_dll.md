# StudentLogic.dll 组件深度逆向（学生端逻辑核心库）

> 样本：`samples/os-easy/StudentLogic.dll`（2887680 字节，PE32 i386 DLL，学生端最大 DLL）
> 反编译：Ghidra 12.1.3 headless，13160 函数 / 544017 行，存档 `/root/ghidra/mmpc/studentlogic_x86.txt`

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/StudentLogic.dll` |
| 大小 | 2887680 字节（学生端最大 DLL） |
| 架构/类型 | PE32 i386 DLL（学生端逻辑核心库） |
| MD5 | `0b79c3f65fff8c74ca74776fc730af76` |

## 1. 定位与职责

**学生端（Student.exe）的逻辑核心库**，与教师端 `MainLogic.dll` 对称但职责更重：除教学交互外，**独占了屏幕捕获/编码/推流**（教师端由 MultiRender 等独立进程做，学生端把这条链做进了 DLL）。

宿主关系：`Student.exe(UI) → LoadLibrary StudentLogic.dll → 21 个业务 API（Load/UnLoad 生命周期 + 各教学动作）`。

## 2. 技术栈（导入 + 静态库）

| 依赖 | 用途 |
|---|---|
| WS2_32 / MSWSOCK + **boost.beast（静态，IOCP+协程）** | WebSocket 服务端 |
| **GDI32 / GDI+** | 屏幕捕获（BitBlt SRCCOPY / GdipCreateBitmapFromScan0 / GdipBitmapLockBits / GdipSaveImageToStream / GdipGetImageEncoders） |
| **FFmpeg（avcodec-57 / avutil-55 / swscale-4）** | 屏幕编码（`av_frame_alloc` 等） |
| libcurl | HTTP 请求（配置/上报） |
| MmcImplBase | MMC/平台基础接口 |
| IPHLPAPI | 网络信息 |
| ADVAPI32 / SHELL32 / ole32 / OLEAUT32 | 注册表/Shell/COM |
| MSVCP140 / VCRUNTIME140 / api-ms-win-crt | VC14 运行时 |
| 静态库：**OpenSSL**（HMAC/Elgamal/CryptoMaterial）、**CxImage**、**jsoncpp**、boost | 加密/图像处理/配置解析 |

## 3. 导出 API（54 个 = 20 业务 + 34 CxImage 再导出）

### 3.1 业务 API（20 个，供 Student.exe 调用）

| API | 功能域 |
|---|---|
| `Load` / `UnLoad` | 生命周期（初始化/释放整个逻辑库） |
| `SetUiEx` | UI 扩展接口绑定 |
| `Message` / `SendMsgToWebClient` / `SendToWeb` | 消息/网页客户端通知 |
| `Barrage` | 弹幕 |
| `RequestHandUp` | 举手 |
| `RespondSignIn` | 点名应答 |
| `GetAttention` | 引起注意（举手/求助） |
| `ControlRunningBoard` | 运行板/答题板控制 |
| `ElectronicAnswer` | 电子答题 |
| `ExamNotifyTeacher` | 考试状态通知教师 |
| `RequestSubmitFile` / `SendFile` / `SubmitBlock` / `SubmitErrorCode` | 考试文件提交/分块/错误上报 |
| `ReturnCommandCall` | 命令回调返回 |
| `NotifyUpdateAudiostatus` | 音频状态更新 |
| `WillCompleted` | 完成前通知 |

### 3.2 CxImage 再导出（34 个）

`CxFile`/`CxIOFile`/`CxMemFile`/`CxImage` 的构造/析构/赋值/vftable/Open/Read/Write/Seek/Tell/Size/GetS/PutC/Scanf/Close/Error/Flush 等——**StudentLogic 把 CxImage 的符号再导出去**，即 Student.exe 的图像 API 实际链接到本 DLL（符号共享，避免 Student.exe 直接带 CxImage.dll）。

## 4. 核心机制（均为教师端 MainLogic 的学生侧对偶）

### 4.1 屏幕捕获 + 编码推流（本 DLL 独有）

- 捕获：`FUN_1008cb70` 内 `BitBlt(hdc,0,0,w,h,src,0,0,0x40cc0020)`（SRCCOPY）全屏抓取 → GDI+ Bitmap 封装；
- 编码推流：`FUN_10088ca0`（日志 `ScreenRender()` / `error ScreenRender:%s`）——**启动 `ScreenRender` 子进程**做编码推流，命令行含：
  `--mouse %d --protocol %s --bindip %s --bindport %d --remote %s --port %d --encoderType %s --quality %d --waitseconds %d --width %d --height %d`
  即教师端远程监视/屏幕广播时，学生端把本屏编码后回推；FFmpeg 库用于帧处理（`av_frame_alloc`）。
- 桌面枚举：`OpenInputDesktop` / `GetThreadDesktop` / `CloseDesktop`（`Get desktop:%s` / `desktop-type`）——可跨桌面（含服务桌面）抓取。

### 4.2 WebSocket 服务端（对 MultiClient 的补充通道）

- `FUN_100e7330`：`Build WebSocket Server port:%d`——**学生端也内嵌 WS 服务端**（与教师端 MainLogic 的 WS 服务端互为反向/辅助通道，供媒体进程回连本机）；
- `FUN_100f7540`：连接管理，日志 `[%d] websocket connected` / `websocket read/write coroutine failed`（boost.beast IOCP 协程式读写）。

### 4.3 键盘/鼠标锁（接收侧）

- `bLockKeyBorad start/stop:%d`、`KeyBoardLock` / `MouseLock` / `MouseAndKeyBoardLock Enable/Disable`、`DisableKeyboard` / `EnableKeyboard`；
- 实际锁键落地走 `LockKeyboard.dll`（MultiClient 已确认），本 DLL 负责状态管理与驱动设备探测联动。

### 4.4 设备管控 / LISS 平台（TCloud）

- `FUN_10073480`：`[CanUseDeviceControl] ret:%d,support:%d`——探测本机 DeviceControl 可用性；
- `FUN_100a0f50`：`initLissHelper` 动态加载 LISS 库并 `GetProcAddress` 全部 `LISS_SDK_*`（InitIntance/FreeIntance/IsLoginUiGoingToShow/IsSupportMMCStrategy/SendBroadcastTypeInternal/SendMMCMonitorKeywordFilePath/SendMMCStopStrategy）；
- MMC 监控关键词：`keywords.json`（`SendMMCMonitorKeywordFilePath`）——教师端下发监控关键词文件，学生端做屏幕/进程关键词检测。

### 4.5 黑屏肃静 / 音频 / 考试文件传输

- 黑屏：本 DLL 负责**拉起/结束 `BlackSlient.exe`**（见 BlackSlient_exe.md），黑屏中安全码解除后进程自退；
- 音频：管理 `AudioPlayRender.exe` / `AudioRecordSender.exe` / `AudioSender.exe` 生命周期 + `AudioTalkingCmd`（`LIMITTALK`/`EXITAUDIOTALK` 广播类型）；
- 考试：`Recv EXAMFILETRANSFER, start/close Client_console`——考试文件传输的客户端会话管理（`ExamNotifyTeacher` 上报状态，`RequestSubmitFile`/`SubmitBlock` 上行文件块）。

## 5. 体系位置（学生端闭环）

```
Student.exe (UI)
  └→ StudentLogic.dll (逻辑核心)
       ├─ WS 服务端 (本机端口, 媒体进程回连)
       ├─ 屏幕捕获(BitBlt/GDI+) → ScreenRender.exe (FFmpeg 编码推流 → 教师端)
       ├─ 键鼠锁 (LockKeyboard.dll / 驱动)
       ├─ 音频子进程 (AudioPlayRender / AudioRecordSender / AudioSender)
       ├─ 黑屏 (BlackSlient.exe 进程生命周期)
       ├─ 考试文件传输 (EXAMFILETRANSFER)
       └─ LISS/TCloud 平台 SDK (initLissHelper)
Teacher.exe (UI)
  └→ MainLogic.dll (WS 服务端 + ~60 API) ⇄ WS(TLS) ⇄ MultiClient.exe(学生端客户端)
       └→ 127.0.0.1 回环 → DeviceControl.exe → 各驱动
```

学生端两条教师通道并行：**MultiClient（WS 客户端，多媒体/交互指令）+ StudentLogic（WS 服务端，媒体回推/辅助）**；屏幕广播 = 教师端推流 → MultiClient 渲染（下行），远程监视 = StudentLogic 捕获编码 → ScreenRender 推流（上行）。

## 6. 配置/日志

- `ScreenRender` 命令行参数（见 4.1）；`keywords.json`（MMC 监控）；`BlackSlient.json`/`lockConfig.json`（黑屏配置，见 BlackSlient_exe.md）；
- 日志：`MultiClient.txt`（Lock.cpp）、`C:\ProgramData\LISSClient\sslkey.log`（TLS 密钥日志，MultiClient 侧）；YAML/JSON 双配置解析。

## 7. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `0x100e7330` | WebSocket 服务端构建（`Build WebSocket Server port:%d`） |
| `0x100f7540` | WS 连接/读写协程（`websocket connected`） |
| `0x10088ca0` | ScreenRender 推流启动（`ScreenRender()` / `error ScreenRender:%s`） |
| `0x1008cb70` | 屏幕 BitBlt 捕获 |
| `0x10073480` | DeviceControl 可用性探测（`[CanUseDeviceControl]`） |
| `0x100a0f50` | LISS SDK 加载（`LISS_SDK_*` GetProcAddress） |
| `0x2ee70~0x2f170` | 20 个业务导出（Barrage…WillCompleted） |
| `0x66ad0~0x900c0` | 34 个 CxImage 再导出 |

## 8. 未决项

1. 学生端 WS 服务端的具体下行/上行帧格式（与教师端 MainLogic 的帧对拍，需实抓）；
2. ScreenRender 推流协议细节（`--protocol` 取值、`--remote` 目标地址来源）；
3. 键鼠锁驱动设备确切名 + `0x900A8` IOCTL 语义（MultiClient 侧同未决）；
4. `ElectronicAnswer`/`ControlRunningBoard` 的具体数据格式；
5. LISS 各函数入参结构。