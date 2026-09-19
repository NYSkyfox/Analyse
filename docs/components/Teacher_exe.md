# Teacher.exe 组件深度逆向（教师端主程序 / UI 宿主）

> 样本：`samples/os-easy/Teacher.exe`（3732480 字节，PE32 i386 GUI，教师端最大 PE）
> 反编译：Ghidra 12.1.3 headless，20530 函数，存档 `/root/ghidra/mmpc/teachexe_x86.txt`

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/Teacher.exe` |
| 大小 | 3732480 字节（教师端最大 PE） |
| 架构/类型 | PE32 i386 GUI（教师端主程序 / UI 宿主） |
| MD5 | `7b999b972ea50b540c44800be1e4e465` |
| SHA-256 | `e55c79fd0f0470a6269d22d0fc1c56aee2d01c5bab68a5b697b1b32092b9e143` | — |

## 1. 定位与职责

**教师端主程序 = UI 宿主薄壳**。它本身几乎不含业务逻辑，职责是：
1. 承载 **DuiLib UI 主界面**（`GClassRoomDlg`，布局 `dMainInterface.xml` / `ClassRoomWnd.xml` / `ClassRoomDesk.xml` / `BigDesk.xml` / `DefineDesk.xml` 等 100+ 个内嵌 XML）；
2. **动态加载 `MainLogic.dll`**（教师端逻辑核心，见 MainLogic_dll.md），UI 按钮 → GetProcAddress 取 API → 调用（~60 个教师端 API 的调用面都在本进程）；
3. **初始化 LISS/TCloud 平台 SDK**（`LISSClientSDK.dll`）；
4. **拉起/管理教师端辅助子进程**（录屏、弹幕、对讲、文件传输、配置备份、学生端辅助等）。

导入特征：MFC140u + gdiplus + WS2_32 + libcurl + bcrypt + MmcImplBase + dbghelp（崩溃转储）。无 FFmpeg（教师端屏幕采集/推理由独立进程 MultiRender 等承担）。

## 2. 启动/初始化链

```
wWinMain → DuiLib UI 框架 → GClassRoomDlg(主界面)
  ├─ LoadLibraryW("MainLogic.dll")   (FUN_004157d0 路径封装; 多处调用: 67741/67885/69548/89903/145516/170065)
  │    → GetProcAddress × ~60 (StartRemoteControlToAll / BlackSilent / ExamTchStart / SetKeyBoardLock / ...)
  ├─ initLissHelper (FUN_005a1xxx @~293133)
  │    → GetCurrentDirectoryW 切换 → LoadLibraryW("LISSClientSDK.dll") → 还原目录
  │    → GetProcAddress: LISS_SDK_InitIntance/FreeIntance/IsLoginUiGoingToShow/
  │                      IsSupportMMCStrategy/SendBroadcastTypeInternal/
  │                      SendMMCStopStrategy/SendMMCMonitorKeywordFilePath
  │    → (*LISS_SDK_InitIntance)()
  │    → 日志: [initLissHelper] lissPath:%s / hMod SUCCESS / hMod failed[%d]!
  │    → 路径解析: sdk\x86\ 或 sdk\x64\ ; 注册表 HKLM\SOFTWARE\LISSClient\liss
  └─ 子进程管理 (CreateProcessW: FUN_004d3200 / FUN_00456d10)
```

## 3. UI 布局面（内嵌 XML，按功能域归纳）

| 功能域 | 布局 |
|---|---|
| 主界面/机房 | `dMainInterface.xml`、`ClassRoomWnd.xml`、`ClassRoomDesk.xml`、`BigDesk.xml`、`DefineDesk*.xml` |
| 认证/授权 | `AuthManager*.xml`、`AuthApply.xml`、`AuthMenu.xml`、`AuthManagerLogin.xml` |
| 课堂管理 | `CallSignWnd-{General,Higher}Education.xml`、`ClassSitesManager*.xml`、`ChannelMenuWnd.xml` |
| 教学互动 | `BroadCast.xml`、`BroadCastRect.xml`、`DemoRemoteControl.xml`、`DemoFromStu.xml` |
| 考试 | `Exam*.xml`（出题/判分/历史成绩） |
| 通信 | `CommMessageBox*.xml`、`ChannelListElement.xml` |
| VDI 适配 | `AboutWnd-{PC,VDI}.xml`（PC 机房 / VDI 虚拟桌面双形态） |

界面元素名（宽串）：`GClassRoomDlg`、`ChannelMenuWnd`、`ClassRoomList`、`lab_liss_text`/`lab_liss_warning`（LISS 登录状态标签 + 警告图 `skin/liss-warning.png`）。

## 4. 教师端 API 调用面（UI → MainLogic.dll）

Teacher.exe 字符串中出现的 MainLogic 导出（对应 MainLogic_dll.md §3 清单的调用侧）：
`StartRemoteControlToAll`、`BlackSilent`、`StopBlackScreen`、`SwitchOnWhiteboard`（`DefineWnd.cpp_Whiteboard`）、`SendImageFile`、`ExamTch{Start,Continue,Delay,Pause,End,Standard}`、`RewardFlower`、`PublishRankingList`、`SetKeyBoardLock`、`Limit`/`LimitFileSize`、`DeviceQuery`、`SendStudentParaConfig`、`RegisterServerIp/Port/BindingMac`、`SumbitFile.ExceedLimitSize`。

UI 按钮 handler → 这些 API → MainLogic 的 WS 服务端广播 → 学生端。Teacher 侧还叠加了：VDI 信道注册显示（`RegisterServerIp`）、学生参数配置下发、考试编辑工具（`ExameditingTool.exe`）联动。

## 5. 子进程清单（Teacher 直接拉起）

| 子进程 | 用途 |
|---|---|
| `ScreenRecord.exe` | 课堂录屏（`DefineWnd.cpp_ScreenRecord` / `ScreenRecordPlayBack`；UI `skin/ScreenRecord*.xml`） |
| `toolkits\bin\Barrage.exe` / `toolkits\qt\Barrage.exe` | 弹幕工具（按 Qt/Win 双版本分发，`FindWindow BarrageUI` 校验启动成功） |
| `toolkits\{bin,qt}\VoiceIntercom.exe` | 语音对讲 |
| `toolkits\bin\ExameditingTool.exe` | 考试编辑（`MmcExameditingTool` 窗口） |
| `FileTransferApp.exe` | 文件传输 |
| `ConfBackupRestore.exe` | 配置备份/恢复 |
| `LISSNetInfoSniffer\LISSNetInfoSniffer.exe` | LISS 平台网络信息嗅探 |
| `StudentScreenHelper.exe` | 学生屏幕辅助（教师侧控制端） |
| `cmd.exe`（`C:\Windows\System32\cmd.exe`） | 辅助批处理 |

日志特征：`%s SmartBarrage Exec Failed:%d`、`%s VoiceIntercom Exec Failed:%d`、`Current Desktop name is :%s`（跨桌面枚举）。

## 6. 设备管控状态面板

Teacher 侧字符串 `[SupportUseDeviceControl] ret:%d support:%d` / `process:%d device:%d network:%d traffic%d` / `[StopDeviceControl] %d:%d:%d:%d` / `[CanUseDeviceControl] ret:%d,support:%d`——教师端 UI 显示三类管控能力（进程/设备/网络）的支持状态，经 MainLogic 的 `DeviceQuery`/`CheckFilter` 查询学生端 DeviceControl 能力位。

## 7. 体系位置

```
Teacher.exe (UI 宿主: DuiLib GClassRoomDlg + 认证 + 考试编辑 + VDI 适配)
  ├─→ MainLogic.dll (逻辑核心: WS 服务端 + ~60 API + libcurl VDI 注册)
  │       ⇄ WebSocket(TLS) ⇄ 学生端 MultiClient.exe
  ├─→ LISSClientSDK.dll (TCloud 平台: 登录 UI 探测 + MMC 策略/关键词下发)
  └─→ 子进程: ScreenRecord / Barrage / VoiceIntercom / ExameditingTool /
             FileTransferApp / ConfBackupRestore / LISSNetInfoSniffer / StudentScreenHelper
教师端媒体进程（由 MainLogic 拉起，非 Teacher 直接）: MultiRender / MediaFileSender / AudioRepeater
```

## 8. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `0x4157d0` | `L"MainLogic.dll"` 路径封装（LoadLibrary 前置） |
| `~0x5a1xxx`（293133 行） | initLissHelper（LISSClientSDK.dll 加载 + 7 SDK 函数 + InitIntance） |
| `0x4d3200` / `0x456d10` | 子进程 CreateProcessW 封装 |
| `0x456d10` 附近 | Barrage/VoiceIntercom 启动 + `FindWindow` 校验 |

## 9. 未决项

1. MainLogic.dll API 的精确调用点逐一映射（~60 个 API 与 UI handler 的一一对应，本报告按字符串面归纳）；
2. VDI 模式下 `RegisterServerIp`/`VdiChannelServerPort` 与 libcurl `channel_register`（MainLogic 内）的交互时序；
3. `dMainInterface.xml` 完整控件树（内嵌资源，与 BlackSlient 同法可提取）；
4. 登录/授权流程（AuthManager 布局）的后端接口（libcurl 目标 URL 多在 MainLogic/配置侧）。