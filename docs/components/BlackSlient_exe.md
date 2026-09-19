# BlackSlient.exe 组件深度逆向（黑屏肃静学生端进程）

> 样本：`samples/os-easy/BlackSlient.exe`（881152 字节，PE32 i386 GUI，注意官方拼写 "Slient"）
> 反编译：Ghidra 12.1.3 headless，1864 函数 / 143461 行，存档 `/root/ghidra/mmpc/blackslient_x86.txt`

## 1. 定位与职责

**学生端"黑屏"覆盖显示进程**。教师端 `MainLogic.dll` 导出 `BlackSilent` / `StopBlackScreen`（见 MainLogic_dll.md），经 WebSocket 广播 → 学生端 `MultiClient.exe` → 由学生端主程序/DeviceControl **启动或结束本进程**：进程运行 = 全屏黑屏（可选肃静提示），进程被杀 = 解除。

关键事实：
- **零网络导入**（无 WS2_32/socket/任何网络 API）——纯本地进程，不与教师端直接通信；
- 无共享内存、无命名管道、无 PostThreadMessage——所有控制都来自**进程启动/终止**本身与**本地配置文件**；
- "肃静"（禁言/静音）部分由音频组件（AudioVolumnControl.dll 等）承担，本进程只负责**黑屏覆盖 + 安全码解锁 UI**。

## 2. 技术栈

| 组件 | 用途 |
|---|---|
| MFC140u / MSVCP140 / VCRUNTIME140 | 运行时 |
| **DuiLib**（静态链接） | UI 框架（`CWindowWnd`/`CPaintManagerUI`，XML 布局 `StuLockWnd.xml` 内嵌资源） |
| **CryptoPP**（静态链接） | `HMAC<SHA1>` + HexDecoder + BaseN —— 安全码本地校验 |
| **jsoncpp**（静态链接） | 解析 `BlackSlient.json` / `lockConfig.json` |
| GDI+ / GDI32 | 背景/图形渲染 |

## 3. 启动链

```
entry(0x41de94) → FUN_0041dd18 (CRT 初始化)
  → get_wide_winmain_command_line()  // 取命令行（仅传入主窗口作参数/日志，无参数解析分派）
  → FUN_0041d100(hInstance, 0, cmdLine)  // 主窗口，唯一业务入口
  → 退出时 exit(返回值)
```

## 4. 主窗口 `FUN_0041d100`（黑屏覆盖机制）

1. 日志初始化（`BlackSilent` / `LogLevel`，日志落 APPDATA 下 `*.log`）；
2. **`ShowCursor(0)`** 隐藏鼠标光标；
3. `CoInitialize(NULL)`；
4. 资源路径 = 可执行目录 + `Skin`（`SetResourcePath`），加载内嵌 `StuLockWnd.xml`（`FUN_0040b6e0(this, "StuLockWnd.xml")`）+ `Student.ico`；
5. `new 0x5d8` 创建窗口对象（类 `BStuLockDlg`/`DMTWnd`，DuiLib `CWindowWnd` 派生，带 `DuiShadowWnd` 阴影）；
6. 抢占前台：`GetForegroundWindow()` → `AttachThreadInput(当前线程, 前台线程, TRUE)` →
   `SetWindowPos(hwnd, HWND_TOP, 0, 0, SM_CXSCREEN, SM_CYSCREEN, 0)` **全屏置顶** → `SetForegroundWindow(hwnd)` → `AttachThreadInput(..., FALSE)`；
7. `CoCreateInstance(IID DAT_004873c0, ...)` 创建 COM 组件并调用 3 个接口方法（细节未完全解析，推断为消息/焦点辅助）；
8. `ShowModal()` **模态死循环**——窗口不关进程不退。

黑屏效果 = 全屏置顶窗口（XML 中背景黑色）+ 隐藏光标。**它是普通 Win32 顶层窗口，非内核/DWM 层面拦截**：任务管理器结束进程、或任何置顶更高层级的窗口都能破坏覆盖。

## 5. 配置文件（全部本地）

| 文件 | 作用 |
|---|---|
| `BlackSlient.json` | 主配置，root 键 `"BlackSlient"`；含 `Password`（安全码期望摘要）等字段。存在则读，不存在则用默认并生成 |
| `lockConfig.json` | 锁配置（不存在时记录 "isExist false" 并写默认值） |
| `general.conf` / `user.conf` | INI 式通用/用户配置 |
| `FtpServerCachePath` | 素材缓存路径（提示图/背景来自教师端下发的缓存文件） |
| `Skin\res.config`、`skin` 目录 | DuiLib 皮肤资源 |
| `%APPDATA%` 下 `*.log` | 运行日志 |

读取代码：`FUN_00411b00`（日志）、`FUN_00410e20`（general.conf）、16317 附近（user.conf）、15422 附近（FtpServerCachePath）。

## 6. UI 控件（StuLockWnd.xml，内嵌资源）

从应用段字符串与事件代码提取的控件名：
- `LabelText` / `Labeltemp` / `LabelLock` / `LabelErorr`（提示文字/临时文字/锁定文字/错误文字）
- `InputStudentSecuritycode`（**学生安全码输入框**，默认隐藏）
- `InputPwd`（密码输入框）
- 按钮（`this+0x51c/0x520/0x524` 三个控件指针槽）

## 7. 键盘/控件事件 `FUN_00411e50`（this = 窗口对象）

`param_2` 为键码/通知码，`param_4` 为"已处理"标志：

| 码 | 行为 |
|---|---|
| `0x0d` | 主交互路径：调 `FUN_004118d0(this-0x24)` 校验安全码；**成功** → `ShowWindow(隐藏)` + 日志 `"exit"`/`"exit ..."` → 进程退出（黑屏解除）；**失败/控件不可用** → 日志 `"NetworkBroken"`、`FUN_00410850` 格式化宽串消息 → 设 `LabelLock` 文字、**显示 `InputStudentSecuritycode` 输入框**、日志 `"unlock"` |
| `0x11` | 置状态位 `this+0x52c` = 1/0（进入/离开输入态） |
| `0x1b` (Esc) | 清除状态位、隐藏输入框、恢复提示，日志 `"lock"` |
| `0x20` | 标记已处理 |
| `0x7a` (Z) | 日志 `"NetworkBroken"`；若状态位已置 → 显示 `InputStudentSecuritycode`（再次唤起输入框） |

交互模型：**学生按特定键（Z）唤起输入框 → 输入教师告知的安全码 → 回车/点击（0x0d）校验 → 正确则进程退出，黑屏消失**。`NetworkBroken` 日志词表明存在"教师会话已断"状态分支（状态来自配置/启动参数，非实时探测）。

## 8. 安全码校验 `FUN_004118d0`（核心）

```
FindControl("InputStudentSecuritycode") → GetText()          // 学生输入的明文
FUN_0041cb80(local_5c, 明文)
"Password"                                                     // JSON 字段名
FUN_0040feb0(local_44)                                         // HMAC-SHA1 计算
FUN_00402080(local_5c, local_44) → 比较结果
```

`FUN_0040feb0`（15202 行）内部：
- `CryptoPP::HMAC<CryptoPP::SHA1>` 构造（vftable 39588 行处）；
- **key = 硬编码常量 `PTR_s_1e7b44beea882d13636bc0290083b24a_004c1000`**——即二进制 `.rdata` 中那串 256 位 hex（128 字节）；
- HexDecoder + 摘要输出 → 与 `BlackSlient.json["BlackSlient"]["Password"]` 存储的期望摘要比较。

**结论：安全码是"教师告知学生的一次性口令"，学生输明文，本机 HMAC 后与配置里的期望摘要比对。key 硬编码在 exe、期望摘要在本地 json，两者都在学生端机器上**——该机制只防误操作/防普通学生乱点，不构成密码学防护（拿到二进制+配置即可算出或匹配任意口令，或直接结束进程）。

## 9. 与其他组件的关系

```
教师端 Teacher.exe → MainLogic.dll::BlackSilent / StopBlackScreen
  → WebSocket 广播（CtrlCode + ips）
  → 学生端 MultiClient.exe 接收
  → 学生端主程序/DeviceControl: StartProcess(BlackSlient.exe [参数]) / KillProcess
  → BlackSlient.exe 全屏置顶 + ShowCursor(0) + ShowModal
     └─ 学生按 Z 唤出 InputStudentSecuritycode → 输安全码
        → HMAC-SHA1(内置key) vs BlackSlient.json.Password → 通过则进程退出
```

肃静（静音）部分走音频链（AudioVolumnControl.dll / 教师端 `AudioTalkSwitch`），与本进程无关。

## 10. 函数索引（应用段，DuiLib/CryptoPP/json 库符号省略）

| 地址 | 功能 |
|---|---|
| `0x41de94` | entry |
| `0x41dd18` | CRT 启动 → 调主窗口 |
| `0x41d100` | 主窗口（黑屏覆盖 + 模态循环） |
| `0x411e50` | 键盘/控件事件分发（Z/Esc/回车） |
| `0x4118d0` | 安全码校验（FindControl→HMAC→比较） |
| `0x40feb0` | HMAC-SHA1 计算（内置 key） |
| `0x402080` | 字符串比较 |
| `0x410e20` | general.conf 读取 |
| `0x411b00` | 日志输出 |
| `0x40b6e0` | DuiLib 窗口对象构造（XML 布局） |
| `0x410850` | 宽串消息格式化 |
| `0x412e40` | 退出处理/日志 |
| `0x4103e0/0x4104d0/0x410600` | 模块路径/皮肤路径拼接 |

## 11. 未决项

1. `CoCreateInstance(DAT_004873c0)` 的具体 COM 接口与三个方法语义（不影响主结论）；
2. `StuLockWnd.xml` 完整 UI 树（内嵌资源 UTF-16 提取受资源目录解析干扰，控件名已从代码侧全部拿到）；
3. `BlackSlient.json` 除 `Password` 外其余字段（背景图/提示语/布局参数）的精确清单；
4. `0x11/0x20` 通知码的确切来源（DuiLib 自定义 uiMsg 或键码）；
5. 学生端具体由哪个进程（Student.exe 主程序 or DeviceControl）负责 Start/Kill 本进程——待 Student.exe 逆向确认。
