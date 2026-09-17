# MMPC.exe 组件深度逆向（完整版）

> 样本：`samples/os-easy/MMPC.exe`（551424 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mmpc-analysis`（程序 `/MMPC.exe`，函数 4824 个）
> 反编译存档：`/root/ghidra/mmpc/`
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 551424 字节 |
| MD5 | `4ea4493c99b2ecb52f6ecce57048be97` |
| SHA-256 | `2588ef277a114f035e09d415d95ca8dd2038b8014696e82a2577cf0e7ee5437d` |
| 格式 | PE32，32 位 |
| 子系统 | 3 = Windows CUI |
| 编译时间 | 2023-11-17 09:14:35 |
| 链接器 | 14.20（VS2019 工具链） |
| PDB | `D:\dmt\master\10.9\Output\Release\MMPC.pdb` |
| 入口点 | `0x451bc5` |
| ImageBase | `0x400000` |
| DllCharacteristics | DYNAMIC_BASE / NX_COMPAT / TERMINAL_SERVICE_AWARE（无 CFG） |
| 导出表 | 无 |

节表：`.text` 0x66fbc / `.rdata` 0x15c2e / `.data` 0x3c00 / `.rsrc` 0x1e0 / `.reloc` 0x58bc。

依赖：`KERNEL32/USER32/ADVAPI32/ole32/OLEAUT32/MSVCP140/WS2_32/WTSAPI32/USERENV/VCRUNTIME140` + UCRT。
库：**boost.asio**（`win_iocp_io_context`、`win_iocp_socket_service<udp>`、`deadline_timer`）、**boost.log**、boost.system。

---

## 1. 运行模型

**MMPC 是 Windows 服务，服务名 `MMPC`**，同时是教学系统的守护/调度中枢。

### 1.1 启动链

```
entry 0x451bc5 → CRT(FUN_00451a43) → FUN_0042cdd0 (main)
   ├─ FUN_00415190          日志初始化（log.txt > 2MB 轮转；boost.log；启动横幅）
   ├─ 打印 "MMPC Main..."
   └─ StartServiceCtrlDispatcherA({"MMPC", FUN_004268d0})
```

### 1.2 ServiceMain `FUN_004268d0`

```
SERVICE_STATUS.type   = 0x30
SERVICE_STATUS.state  = 2 (START_PENDING) → SetServiceStatus
RegisterServiceCtrlHandlerA("MMPC", FUN_00426300)
  失败 → "RegisterServiceCtrlHandler failed:%d"；成功 → "RegisterServiceCtrlHandler success"
state = 4 (RUNNING) → SetServiceStatus
FUN_00423f70(...)      创建核心对象（实为 boost::asio win_iocp_io_context）
FUN_00435230(obj,...)  引擎初始化（角色判定 + 通道建立 + 定时器）
FUN_0042b9f0()         事件循环（阻塞）
```

### 1.3 服务控制 `FUN_00426300`

`STOP(1)` / `SHUTDOWN(5)`：

```
构造 JSON {"type":"quit"} → UDP 发往 127.0.0.1
打印 "Notify Service Stop"
state = 1 (STOPPED) → SetServiceStatus
```

### 1.4 角色判定 `TeaSide.ini`

`FUN_00435230` 读取：

| 键 | 默认 | 作用 |
|---|---|---|
| `[TeaSide] Flag` | 0 | `1` → `Teacher Side.`；否则 `Student Side.`（并调 `FUN_0043a7b0` 开自我保护） |
| `[TeaSide] WaitSeconds` | 0 | 等待秒数（下限 10） |

---

## 2. 通信面

### 2.1 UDP 9030 —— 命令通道（接收 + 应答）

- 端口来自 `FUN_00435230`：`uVar9 = 0x2346`（**9030**）→ `FUN_00434050` 配置端点。
- 打开/绑定：`FUN_0043dfa0(obj+0x3c, ..., obj+4, ...)` → 日志 `bind error:%s` / `bind success!`。
- **异步接收**：`FUN_00430010(sock=obj+0x3c, buf=obj+0x168, len=0x400, handler=FUN_00439ab0)`。
- **接收完成 `FUN_00439ab0`**：

```c
if (ok && n>0 && n<0x400) {
    buf[n] = 0;                       // NUL 结尾
    std::string s = buf;              // 一条消息 = 一个 NUL 结尾 JSON
    FUN_00438b70();                   // → 命令分发
}
FUN_00430010(...);                    // 重新挂接收
```

→ **命令格式：以 `\0` 结尾的 JSON 文本，单条 ≤ 1023 字节，UDP 送到 9030**。

- 应答：`FUN_00430170(sock, payload, (short*)obj+8, handler)`（异步发送回源地址），用于 `terminal-mac`/`desktop-type` 等分支回包。
- 发送 JSON（`FUN_0043a660`）：

```json
{"vender_id":"oseasy.mmc.udp","id":"stop-deamon-multiclient","stop":<int>}
```

### 2.2 命名管道 `\\.\Global\com.morningcloud.tcloud.multimedia`

- MMPC **未导入 `CreateNamedPipe`** → MMPC 是**客户端**（对端为外部"morningcloud tcloud"服务）。
- 存在性检查 `FUN_00439b60`：`CreateFileW(name, GENERIC_RW, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, ...)`。
- 写请求 `FUN_0043ab20`（数据由 `FUN_0043c060` 发出）：

```json
{"method":"multimedia","args":{"teacher_ip":"<ip>","student_ip":"<ip>"},"msg_id":"", "extras":{}}
```

- `FUN_0043c060`：`CreateFileW(OPEN_EXISTING)` → `WriteFile` → `ReadFile` 等应答 → 解析应答中的 `"client_ip"` 字段并返回。
- 日志：`Wait Named Pipe:%s`、`Pipe Create Error:%s`、`Pipe Write Error:%s`、`Pipe Read Error:%s`、`Pip Return:%s`。

### 2.3 定时器

| 回调 | 周期 | 行为 |
|---|---|---|
| `FUN_00437df0` | 3 s | 学生端保活：`Student.exe` 不在则启动；按角色切学生/教师动作 |
| `FUN_00438020` | 5 s | 调 `FUN_00405d30()`（读 `add.map` 逐行登记/注入） |
| `FUN_00437bb0` | 500 ms | 监听 `LOGONUI.EXE`，检测 winlogon 桌面切换 |

`FUN_00437bb0`：

```
find = FUN_00439cb0("LOGONUI.EXE")
状态变化时：
  进入 winlogon 桌面 → FUN_00439fb0（渲染栈）+ FUN_0043a660（UDP）
                       日志 "kill student, winlogon desktop!"
  离开 winlogon 桌面 → 日志 "kill student, winlogon desktop bye!"
状态存 DAT_00481dce
```

---

## 3. 命令分发 `FUN_00438b70`

入口：校验 JSON 有 `type` 字段 → 逐项 `strcmp`。日志 `receive type:%s`。**无来源 IP 校验**。

| `type` | 行为 | 关键点 |
|---|---|---|
| `npd-auto` / `start npd` | NPD 保护：启动 DeviceControl + 守护其 PID | `FUN_00437ae0`、`FUN_00438190("DEVICECONTROL_X64.EXE")`、`FUN_00437a40(pid)`；日志 `start protect devicecontrol pid:%d` |
| `daemon` | 开启守护标志 `obj[0x118]=1` | `FUN_0043ab00(obj,1)` |
| `quit-daemon` | 关闭守护标志 | `FUN_0043ab00(obj,0)` |
| `quit` | 退出（服务停止时内部构造） | UDP |
| `uninstall` | 卸载 | `FUN_00444170` |
| `vdi` | VDI 配置 | `FUN_0043a010` |
| `multi-config` | 读 `exePath` 处理 | `FUN_0043afa0`；日志 `multiConfigPath:%s` |
| `start-teacher` | **写 `TeaSide.ini [TeaSide]Flag=1` + 启动 `Teacher.exe`**（默认桌面） | `FUN_0043b930`；日志 `start path:%s` |
| `killallproc` | 把 `cmd3`/`cmd1` 写入 `kill3.bat`/`kill1.bat` 并执行 | `FUN_0043a010` |
| `set-teaAndStu-ip` | 记录 `teaIp`/`stuIp`；若在 winlogon 桌面则 UDP+渲染栈 | 日志 `teaIp:%s,stuIp:%s`、`in winlogon desktop` |
| `start-multiclient` | 启动 `MultiClient.exe <teacherIp> <stuIp>` | 日志 `start multiclient:%s` |
| `regedit-broadcast` | **写注册表 `HKLM\SOFTWARE\OCloud!Broadcasting`(DWORD)** | `FUN_0043c460` |
| `desktop-type` | `vdi` / `non-vdi` | `FUN_00430170`（回包） |
| `terminal-mac` | 终端 MAC | `FUN_00430170` |
| `idv-terminal-mac` | IDV 终端 MAC | `FUN_00430170` |
| `set-time` | 读 `time` → `SetLocalTime` | `FUN_0043ba00` |
| `kill-deviceControl` | 杀 `DeviceControl_x64/x86.exe` | `FUN_004413b0`、`FUN_00437f80` |
| `kill-student` | 杀 `Student.exe` | `FUN_004413b0(L"Student.exe")` |
| `start-lissNet` | 读 `ip`/`mac`/`filepath` → 启动 `x86/x64\LISSNetInfoSniffer.exe` | 日志 `start-lissNet:%s` |
| `assist`(+`desktop`) | 协助连接；`kvm` 时创建 KvmChannel 对象 | `FUN_0043f080`/`FUN_00435140`；异步 `result:%s,client_ip:%s` |

`killallproc`/`start-teacher` 的批处理 `FUN_0043a010`：

```
if Win10/11 (FUN_00439ef0): 写 "kill3.bat"（内容 = 入参两串，"%s\n%s\n"）并执行
else:                        写 "kill1.bat" 并执行
执行封装 FUN_0043b8b0（CreateProcessW）
```

---

## 4. 进程启动与权限（4 种策略）

MMPC 作为 Session 0 服务，需把进程投放进交互会话/桌面，提供 4 条路径：

| 函数 | 机制 | 目标桌面 |
|---|---|---|
| `FUN_0043b8b0` | `CreateProcessW`（同会话） | 服务会话，`wShowWindow=0` |
| `FUN_0043b3a0` | 取 `EXPLORER.EXE` token → `CreateProcessAsUserW` | `winsta0\default` |
| `FUN_0043afa0` | `WTSQueryUserToken(活动会话)` + `EXPLORER.EXE` token → `CreateProcessAsUserW` | `winsta0\default` |
| `FUN_0043b510` | 取 `winlogon.exe` token（`SeDebug` + `TokenSessionId`）→ `CreateProcessAsUserW` | **`winsta0\winlogon`** |

**Token 窃取 `FUN_00438550`**：遍历进程按名匹配（限**活动控制台会话** `ProcessIdToSessionId==WTSGetActiveConsoleSessionId`），`OpenProcess(0x400)` + `OpenProcessToken(0xF01FF)` 取全权令牌。

`FUN_0043b510` 关键步骤：`LookupPrivilegeValue("SeDebugPrivilege")` → `DuplicateTokenEx(TokenPrimary)` → `SetTokenInformation(TokenSessionId)` → `AdjustTokenPrivileges` → `CreateEnvironmentBlock` → `CreateProcessAsUserW(lpDesktop="winsta0\\winlogon")`；成功日志 `StartByUserPrivilegeWinLogn ok!`。

---

## 5. 自我保护（AntiFunc / AntiHelper.dll）

`AntiHelper.dll`（44032 字节）导出 4 个函数，经 `DeviceIoControl` 与内核驱动通信：

```
AddProcessPid、DelProcessPid、SetProtectDirectory、ResetProtectDirectory
```

| 调用 | 行为 |
|---|---|
| `FUN_00437a40(pid)` | `AntiHelper!AddProcessPid(pid)`（保护进程） |
| `FUN_00437f80(pid)` | `AntiHelper!DelProcessPid(pid)`（解除保护） |
| `FUN_0043ae20(path)` | `AntiHelper!SetProtectDirectory(path)`（保护目录） |
| `FUN_0043a7b0` | **开 AntiFunc**：保护自身 PID + 设置受保护目录（`curPath:%s`），标志 `obj[0x11c]=1`，日志 `Open AntiFunc..!` |
| `FUN_00437d10` | **关 AntiFunc**：解除保护（`close curPath:%s`，密钥串 `548861465`），标志置 0，日志 `Close AntiFunc..!` |

- `protect.map` 内容 = `Student.exe`（守护对象）。
- `FUN_00437a40/FUN_00437f80` 也用于保护 `Student.exe` / `DeviceControl` 的 PID。

---

## 6. 注册表 / 配置写入

| 目标 | 函数 | 内容 |
|---|---|---|
| `HKLM\SOFTWARE\OCloud` | `FUN_0043c460` | `Broadcasting`（REG_DWORD，`regedit-broadcast`） |
| `TeaSide.ini` | `FUN_0043b930` | `[TeaSide] Flag=1`（`start-teacher`） |
| `TeaSide.ini` | `FUN_00435230`（读） | `Flag` / `WaitSeconds` |

---

## 7. 子进程与文件

### 7.1 子进程

| 进程 | 触发 | 函数 |
|---|---|---|
| `Student.exe` | 3s 保活 / 守护 | `FUN_00437df0` |
| `MultiClient.exe` | `start-multiclient` / 渲染栈 | `FUN_00438b70`、`FUN_00439fb0` |
| `AudioRender.exe`、`ScreenRender.exe`、`Barrage.exe` | 渲染栈 | `FUN_00439fb0` |
| `DeviceControl_x64/x86.exe` | NPD 保护 | `FUN_00437ae0` |
| `LISSNetInfoSniffer.exe` | `start-lissNet` | `FUN_00438b70` |
| `Teacher.exe` | `start-teacher` | `FUN_0043b930` |
| `EXPLORER.EXE` / `LOGONUI.EXE` / `winlogon.exe` | 令牌/桌面/检测 | 多处 |

### 7.2 数据文件

| 文件 | 内容 | 用途 |
|---|---|---|
| `add.map` | 24 个 exe（Student/Teacher/MultiClient/ScreenRender/…） | 5s 定时器 `FUN_00405d30` 逐行处理：先判文件/目录（`FUN_00406080`），再经 **COM 自动化 `FUN_00405740`** 注册（任务名形如 `MMC_<n>_1`） |
| `protect.map` | `Student.exe` | 守护对象 |
| `kill1.bat` / `kill3.bat` | 运行时写出（内容来自命令 `cmd1`/`cmd3`） |
| `TeaSide.ini` | 角色 |
| `log.txt` | 服务日志（>2MB 轮转） |

### 7.3 `add.map` 处理与 COM 注册

- `FUN_00405d30`（5s 定时器）逐行读取 `add.map`：
  1. `FUN_00406080(line, flag)` 判定条目是**文件还是目录**（`FUN_00408340`/`FUN_00408580`）。
  2. 对通过判定的条目调用 `FUN_00405740(name, path)`。
- `FUN_00405740` 为 **OLE/COM 自动化**：`CoInitializeEx` → `CoCreateInstance`（`{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}` / `{AF230D27-BABA-4E42-ACED-F524F22CFCE2}`）+ BSTR(`Ordinal_2`)，随后按 vtable 偏移依次设置属性并"注册"，任务名格式 `MMC_<n>_1`。
- 该调用形态与**计划任务 / 自启动注册**一致；COM 类身份待定（见 §10）。
- `FUN_00438180` 返回全局 `&DAT_00481da4`（`AntiHelper.dll` 模块句柄的存放处）；`FUN_004350d0` 为 `KvmChannel` 基类 `Channel` 的 vftable 置位。

---

## 8. 主循环与定时器

- `FUN_0042b9f0` → `FUN_0042ba30`：**asio `io_context::run`**（`FUN_00429330` 处理事件，返回非 0 继续并计数）。
- 核心对象由 `FUN_00423f70` 构造，`FUN_004244d0` 中 `*this = boost::asio::detail::win_iocp_io_context::vftable` → 说明"100 项容器"实为 **io_context**。
- 辅助判定：`FUN_00439ef0` 用 `ntdll!RtlGetNtVersionNumbers` 判 Win10（major10/minor0）。
- 进程查询：`FUN_00439bc0`（按名存在性）、`FUN_00439cb0`（按名 + 会话校验）、`FUN_00438190`（按名取 PID）。

---

## 9. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x00451bc5 | entry |
| 0x00451a43 | CRT 启动 |
| 0x0042cdd0 | main（StartServiceCtrlDispatcher） |
| 0x00415190 | 日志初始化 |
| 0x004268d0 | ServiceMain |
| 0x00426300 | ServiceCtrlHandler |
| 0x00423f70 / 0x004244d0 | 创建 io_context |
| 0x00435230 | 引擎初始化（角色/端点/接收/定时器） |
| 0x0042b9f0 / 0x0042ba30 | 事件循环 |
| **0x00438b70** | **命令分发** |
| 0x00430010 / 0x00430170 | UDP 异步接收 / 发送 |
| 0x00439ab0 | UDP 收包完成 → 分发 |
| 0x0043dfa0 / 0x00434050 | UDP 端点绑定 |
| 0x0043a660 | UDP 发送（oseasy.mmc.udp） |
| 0x00439b60 / 0x0043c060 / 0x0043ab20 | 管道存在性 / 管道请求应答 / 管道多媒体调用 |
| 0x00439fb0 | 启动渲染栈 |
| 0x00437df0 | 学生端保活定时器 |
| 0x00437bb0 | LOGONUI 监控定时器 |
| 0x00438020 / 0x00405d30 | 5s 定时器 / add.map 处理 |
| 0x00437ae0 | 启动 DeviceControl |
| 0x0043b930 | start-teacher |
| 0x0043a010 | killallproc（写 bat 执行） |
| 0x00438550 | 按名取令牌（活动会话） |
| 0x0043b510 / 0x0043b3a0 / 0x0043afa0 / 0x0043b8b0 | 4 种进程启动策略 |
| 0x00437a40 / 0x00437f80 / 0x0043ae20 | AntiHelper 保护/解除/目录 |
| 0x0043a7b0 / 0x00437d10 | 开/关 AntiFunc |
| 0x0043c460 | regedit-broadcast（OCloud） |
| 0x00439ef0 | Win10 判定 |
| 0x00439bc0 / 0x00439cb0 / 0x00438190 | 进程查询 |
| 0x0043f080 / 0x00435140 | assist / KvmChannel |

---

## 10. 未决 / 后续

1. 命名管道服务端（`com.morningcloud.tcloud.multimedia` 的创建者）——疑似外部"morningcloud/tcloud"组件。
2. `FUN_00405d30` 对 `add.map` 每行的具体处理（`FUN_00406080`/`FUN_00405740`）。
3. `assist`/`KvmChannel`（`FUN_00435140`、`FUN_004350d0`）的完整协议。
4. `FUN_00438180`（加载 `AntiHelper.dll`）的路径解析。
5. `FUN_0043f080` 中 `kvm` 分支的对象生命周期与用途。
6. `FUN_0042cf60/FUN_0042d8b0/FUN_004407a0` 这类 asio timer 配置的完整封装语义。

---

*本文覆盖：文件指纹、运行模型、通信面（UDP 9030 / 命名管道 / 定时器）、19+ 命令分发、4 种进程启动策略与令牌窃取、AntiHelper 自我保护、注册表/配置写入、子进程与文件、事件循环、函数索引。*
