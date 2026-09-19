# Student.exe 组件深度逆向（学生端主程序 / UI 宿主）

> 样本：`samples/os-easy/Student.exe`（2161152 字节，PE32 i386 GUI）
> 反编译：Ghidra 12.1.3 headless，12090 函数，存档 `/root/ghidra/mmpc/studentexe_x86.txt`

## 1. 定位与职责

**学生端主程序 = UI 宿主薄壳**（与教师端 Teacher.exe 完全对称的角色）。本身几乎不含业务逻辑，职责：
1. 承载 **DuiLib UI 主界面**（100+ 内嵌 XML：考试 `Exam*.xml`、答题 `aStuAnswerResultWnd.xml`、榜单 `bStudentRankingList.xml`、音乐 `bStuMusicalWnd.xml`、文件接收 `CheckRecvFileWnd.xml`、音视频广播 `AudioOrVideoBroadcastDlg` 等）；
2. **动态加载 `StudentLogic.dll`**（学生端逻辑核心，见 StudentLogic_dll.md），`FUN_004084a0(L"StudentLogic.dll")` 路径封装 + GetProcAddress 取 20 个业务 API；
3. **拉起/管理学生端全部子进程**（媒体/交互/管控辅助，见 §5）；
4. 退出时**统一清理所有子进程**（`FUN_004a0050`）。

导入特征：MFC140u + gdiplus + WS2_32 + PSAPI（进程枚举）+ MmcImplBase + dbghelp。**无 FFmpeg**（屏幕编码/推流全在 StudentLogic.dll 与 ScreenSender/ScreenRender 子进程里）。

## 2. 启动/初始化链

```
wWinMain → DuiLib UI 框架 → 学生主界面
  ├─ LoadLibrary("StudentLogic.dll")  (FUN_004084a0 路径封装; 多处: 11531/53997/105965/107046/119241...)
  │    → GetProcAddress × 20 (Barrage / RequestHandUp / RespondSignIn / ElectronicAnswer /
  │       ExamNotifyTeacher / SendFile / SubmitBlock / Load / UnLoad / ...)
  ├─ 拉起子进程: MultiClient.exe (WS 客户端) + LissHelper.exe (TCloud 平台)
  │    + 按需: ScreenSender/ScreenRender/音频四件套/client_console 等
  └─ 退出: FUN_004a0050 逐个杀 20 个子进程 → TerminateProcess(自身)
```

## 3. UI 布局面（内嵌 XML，按功能域）

| 功能域 | 布局 |
|---|---|
| 考试（核心，最多） | `ExamAddByType/Mul/Single*.xml`、`ExamCorrectWnd.xml`、`ExamHistoryGradeWnd.xml`、`ExamFunctionMenu.xml`、`bExamTableItemTitle.xml`、`aStuAnswerResultWnd.xml`、`\exam\exam.xml` |
| 课堂互动 | `bCongratulations.xml`、`bStudentRankingList.xml`（奖励/榜单）、`bStuMusicalWnd.xml`（音乐）、`ecircleButton.xml` |
| 文件/通信 | `CheckRecvFileWnd.xml`、`eFileTransferTipWnd.xml`、`CommMessageBox*.xml` |
| 音视频广播 | `AudioOrVideoBroadcastDlg`（源码串 `_allfile/_fileexist/_videofile/_voicefile` 校验） |
| 系统 | `AboutWndStu-PC.xml`、`AboutWnd-VDI.xml`（PC/VDI 双形态） |

加密资源名（运行时解密使用）：`eMultiClient.exe`、`RStudentLogic.dll`、`explorer.exe`、`RICHED20.dll`——子进程/库名做了**前缀字符混淆**，防止字符串直接匹配。界面元素：`NLocalIp`/`RemoteIp`/`hl_remoteip`/`menu_ip`（本机/远程 IP 显示）、`ehandsup`（举手）、`StudentExportBtn`。

## 4. 与 StudentLogic.dll 的调用面

Student.exe 字符串出现的 StudentLogic 导出（对应 StudentLogic_dll.md §3.1）：`NotifyUpdateAudiostatus` 等 20 个业务 API 的调用侧。UI 按钮 → API → StudentLogic 内部 WS/子进程/驱动落地。

## 5. 学生端子进程清单（`FUN_004a0050` 退出清理表 = 完整清单）

| 子进程 | 用途 |
|---|---|
| `MultiClient.exe` | **WS 客户端**（连教师端，多媒体/交互指令，见 MultiClient_exe.md） |
| `LissHelper.exe` | TCloud/LISS 平台辅助（独立进程形态，见 LissHelper 报告） |
| `LISSNetInfoSniffer.exe` | LISS 网络信息嗅探 |
| `ScreenSender.exe` | 屏幕**编码+UDP 推流**（上行，教师端监视，见 ScreenSender 报告） |
| `ScreenRender.exe` | 屏幕**解码+SDL2 渲染**（下行，教师端广播/远程，见 ScreenRender 报告） |
| `ScreenShot.exe` | 屏幕截图 |
| `AudioPlayRender.exe` | 音频播放渲染 |
| `AudioRecordSender.exe` | 音频录制上行 |
| `AudioRender.exe` | 音频渲染 |
| `AudioSender.exe` | 音频上行 |
| `MultiRender.exe` | 多媒体渲染 |
| `MacRender.exe` | Mac 风格渲染（兼容形态） |
| `Barrage.exe` | 弹幕 |
| `client_console.exe` | 考试文件传输客户端会话（`EXAMFILETRANSFER`） |
| `ExameditingTool.exe` | 考试编辑 |
| `CSimulateMouse.exe` | 模拟鼠标（远程演示/广播鼠标） |
| `DiffSharedDesktop.exe` / `SharedDesktop.exe` | 共享桌面（差分/全量） |
| `OePainter.exe` | 绘图（电子白板/黑板） |
| `MicrIcon.exe` | 麦克风图标/状态 |

进程管理：`FUN_004b1e90` = `CreateToolhelp32Snapshot`+`Process32FirstW/NextW`+`_wcsicmp` 按名判存活；`FUN_004a0160` = `TerminateProcess(GetCurrentProcess())` 自杀。

## 6. 体系位置（学生端闭环）

```
Student.exe (UI 宿主: DuiLib + 考试界面 + 举手/榜单 + PC/VDI 双形态)
  ├─→ StudentLogic.dll (逻辑核心: WS 服务端 + 屏幕捕获编码 + 键鼠锁 + 考试文件 + LISS SDK)
  ├─→ MultiClient.exe (WS 客户端 ⇄ 教师端 MainLogic.dll 的 WS 服务端)
  ├─→ LissHelper.exe + LISSNetInfoSniffer.exe (TCloud 平台)
  ├─→ 媒体子进程: ScreenSender(上行编码推流) / ScreenRender(下行解码渲染) /
  │               AudioPlayRender/AudioRecordSender/AudioRender/AudioSender /
  │               MultiRender / SharedDesktop
  └─→ 工具: Barrage / client_console / ExameditingTool / CSimulateMouse / OePainter / ScreenShot
教师端: Teacher.exe → MainLogic.dll ⇄ WS(TLS) ⇄ MultiClient/StudentLogic
```

## 7. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `0x4084a0` | `L"StudentLogic.dll"` 路径封装（LoadLibrary 前置） |
| `0x4a0050` | 退出清理：逐个杀 20 个子进程 |
| `0x49ff70` | 单子进程清理（枚举→判断→终止） |
| `0x4b1e90` | 进程按名判存活（Toolhelp Snapshot + `_wcsicmp`） |
| `0x4a0160` | `TerminateProcess(自身)` |
| `0x456xxx`/`0x4d3xxx` | CreateProcessW/A 子进程启动封装 |

## 8. 未决项

1. 子进程**启动**命令行的逐条参数（ScreenSender/ScreenRender 参数已在 StudentLogic 侧确认，其余音频/桌面进程参数待抓）；
2. `dMainInterface`/学生主界面控件树完整映射；
3. PC vs VDI 双形态的分支逻辑（`AboutWnd-{PC,VDI}.xml`）；
4. `SharedDesktop`/`DiffSharedDesktop` 的差分桌面协议（与 ScreenSender/ScreenRender 的关系）。