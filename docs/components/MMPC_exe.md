# MMPC.exe 组件深度逆向

> 样本：`samples/os-easy/MMPC.exe`（551424 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mmpc-analysis`（程序 `/MMPC.exe`，4824 函数）
> 反编译存档：`/root/ghidra/mmpc/`（`mmpc_recon.txt`、`mmpc_funcs.txt`、`dec_round2b.txt`、`dec_round3.txt`、`dec_round5~7.txt`、`dump3/4.txt`、`vt.txt`、`insn.txt`）
> 分析日期：2026-09-18

---

## 0. 样本信息

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
- 存在性检查 `FUN_00439b60`：`CreateFileW(name, GENERIC_READ|GENERIC_WRITE=0xc0000000, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, ...)`。
- 写请求 `FUN_0043ab20`（数据由 `FUN_0043c060` 发出）：

```json
{"method":"multimedia","args":{"teacher_ip":"<ip>","student_ip":"<ip>"},"msg_id":"", "extras":{}}
```

- `FUN_0043c060`：`CreateFileW(OPEN_EXISTING)` → `WriteFile` → `ReadFile` 等应答 → 解析应答中的 `"client_ip"` 字段并返回。
  - 报文 = **长度前缀 + JSON 载荷**（`FUN_00433f00` 写入长度、`FUN_00444cf0` 追加数据后 `WriteFile`）；应答缓冲区 1024 字节。
  - 日志：`Wait Named Pipe:%s`、`Pipe Create Error:%s`、`Pipe Write Error:%s`、`Pipe Read Error:%s`、`Pip Return:%s`。
  - **服务端不在本安装包内**（对全部样本按 ASCII/UTF-16 搜索 `com.morningcloud.tcloud.multimedia`，仅 MMPC.exe 命中）→ 该管道由外部"morningcloud/tcloud"组件创建（疑似云桌面/教学云代理）。

### 2.3 定时器

| 回调 | 周期 | 行为 |
|---|---|---|
| `FUN_00437df0` | 3 s | 学生端保活：`Student.exe` 不在则启动；按角色切学生/教师动作 |
| `FUN_00438020` | 5 s | 调 `FUN_00405d30()`（读 `add.map` 逐行**登记防火墙放行规则**） |
| `FUN_00437bb0` | 500 ms | 监听 `LOGONUI.EXE`，检测 winlogon 桌面切换 |

`FUN_00437bb0`：

```
find = FUN_00439cb0("LOGONUI.EXE")
状态变化时：
  进入 winlogon 桌面 → FUN_00439fb0（结束 MultiClient/AudioRender/ScreenRender/Barrage）+ FUN_0043a660（UDP）
                       日志 "kill student, winlogon desktop!"
  离开 winlogon 桌面 → 日志 "kill student, winlogon desktop bye!"
状态存 DAT_00481dce
```

---

## 3. 命令分发 `FUN_00438b70`

入口：JSON 解析（`FUN_0044ac60`）→ 校验有 `type` 字段 → 逐项 `strcmp`（`FUN_0041dc60`）。日志 `receive type:%s`。**无来源 IP 校验**。
分支顺序（`strcmp` 出现次序）：`npd-auto`、`quit-daemon`、`daemon`、`multi-config`、`vdi`、`quit`、`uninstall`、`start-teacher`、`killallproc`、`set-teaAndStu-ip`、`start-multiclient`、`regedit-broadcast`、`desktop-type`、`terminal-mac`、`idv-terminal-mac`、`set-time`、`kill-deviceControl`、`kill-student`、`start-lissNet`；不匹配任何已知 `type` 时进入 `assist` 分支。

| `type` | 行为 | 关键点 |
|---|---|---|
| `npd-auto` / `start npd` | NPD 保护：启动 DeviceControl + 守护其 PID | `FUN_00437ae0`、`FUN_00438190("DEVICECONTROL_X64.EXE")`、`FUN_00437a40(pid)`；日志 `start npd`、`start protect devicecontrol pid:%d` |
| `daemon` | 开启守护标志（`obj[0x118]=1`、`obj[0x48]=0`） | `FUN_0043ab00(obj,1)` |
| `quit-daemon` | 关闭守护标志 | `FUN_0043ab00(obj,0)` |
| `quit` | 停止事件循环（服务停止） | `FUN_00444170(obj0)`→`FUN_0042c560`（io_context::stop，`PostQueuedCompletionStatus`） |
| `uninstall` | **清理 add.map 对应的防火墙规则** | 置 `obj[0x48]=1`；`FUN_00406230`（日志 `FireWall Uninstall`）→ 逐行 `FUN_004059c0` 删除规则 |
| `vdi` | VDI 相关（写批处理执行） | 复用批处理封装 `FUN_0043a010` |
| `multi-config` | 读 `exePath` 并**以活动会话身份启动** | `FUN_0043afa0`；日志 `multiConfigPath:%s` |
| `start-teacher` | **写 `TeaSide.ini [TeaSide]Flag=1` + 启动 `Teacher.exe`** | `FUN_0043b930`（`WritePrivateProfileStringW` + `FUN_0043afa0`）；日志 `start path:%s` |
| `killallproc` | 把 `cmd3`/`cmd1` 写入 `kill3.bat`/`kill1.bat` 并执行 | `FUN_0043a010` |
| `set-teaAndStu-ip` | 记录 `teaIp`/`stuIp`；若在 winlogon 桌面则 UDP+结束渲染栈 | 日志 `teaIp:%s,stuIp:%s`、`in winlogon desktop` |
| `start-multiclient` | 启动 `MultiClient.exe <teacherIp> <stuIp>`（winlogon 桌面） | `FUN_0043b510`；日志 `start multiclient:%s` |
| `regedit-broadcast` | **写注册表 `HKLM\SOFTWARE\OCloud` 的 `Broadcasting`(DWORD)** | `FUN_0043c460`；日志 `broadcast state:%d` |
| `desktop-type` | 回包 `vdi` / `non-vdi`（读 `obj[0x15a]`） | `FUN_00430170` |
| `terminal-mac` | 回包终端 MAC | `FUN_00430170` |
| `idv-terminal-mac` | 回包 IDV 终端 MAC | `FUN_00430170` |
| `set-time` | 读 `time` → `SetLocalTime` | `FUN_0043ba00` |
| `kill-deviceControl` | 杀 `DeviceControl_x64/x86.exe` | `FUN_004413b0`、`FUN_00437f80` |
| `kill-student` | 解除 PID 保护 + 杀 `Student.exe` | `FUN_00437f80(obj[0x162])`、`FUN_004413b0(L"Student.exe")` |
| `start-lissNet` | 读 `ip`/`mac`/`filepath` → 启动 `x86/x64\LISSNetInfoSniffer.exe "<ip>" "<mac>" "<filepath>"` | 日志 `start-lissNet:%s`；`FUN_0043b3a0` |
| `assist`(+`desktop`) | 协助连接；`assist` 值 `== "kvm"` 时创建 `KvmChannel` 并执行 | `FUN_0043f080`/`FUN_00435140`；见 §9；日志 `result:%s,client_ip:%s` |

**`uninstall` 的防火墙清理 `FUN_00406230`**：日志 `FireWall Uninstall`，逐行读 `add.map`，对通过判定的条目构造 `MMC_<文件名>` 并调 `FUN_004059c0` 删除同名防火墙规则。

**`killallproc`/批处理 `FUN_0043a010`**：

```
打印 "%s\n%s\n"（两条命令）
if Win10/11 (FUN_00439ef0): 写 "kill3.bat"（内容 = 入参两串）并执行
else:                        写 "kill1.bat" 并执行
执行封装依次为 FUN_0043b8b0（CreateProcessW）
```

---

## 4. 进程启动与权限（4 种策略）

MMPC 作为 Session 0 服务，需把进程投放进交互会话/桌面，提供 4 条路径：

| 函数 | 机制 | 目标桌面 |
|---|---|---|
| `FUN_0043b8b0` | `CreateProcessW`（同会话） | 服务会话，`wShowWindow=0` |
| `FUN_0043b3a0` | `FUN_00438550` 取 `EXPLORER.EXE` token → `CreateProcessAsUserW` | `winsta0\default` |
| `FUN_0043afa0` | 取 `winlogon.exe` token（`OpenProcess(0x2000000)` + `OpenProcessToken(0x201eb)`，`DuplicateTokenEx`+`SetTokenInformation(TokenSessionId)`+`SeDebugPrivilege`）→ `CreateProcessAsUserW` | `winsta0\default` |
| `FUN_0043b510` | 同 `FUN_0043afa0` 的令牌链，但面向 winlogon | **`winsta0\winlogon`** |

**Token 窃取 `FUN_00438550`**：遍历进程按名匹配（限**活动控制台会话** `ProcessIdToSessionId==WTSGetActiveConsoleSessionId`），`OpenProcess(0x400)` + `OpenProcessToken(0xF01FF)` 取全权令牌。

`FUN_0043b510` 关键步骤：遍历找活动会话的 `winlogon.exe` → `OpenProcess(0x2000000)` + `OpenProcessToken(0x201eb)` → `LookupPrivilegeValue("SeDebugPrivilege")` → `DuplicateTokenEx(TokenPrimary)` → `SetTokenInformation(TokenSessionId)` → `AdjustTokenPrivileges` → `CreateEnvironmentBlock` → `CreateProcessAsUserW(lpDesktop="winsta0\\winlogon")`；成功日志 `StartByUserPrivilegeWinLogn ok!`。

`FUN_0043afa0` 与 `FUN_0043b510` 的差异：桌面（`default` vs `winlogon`）与环境块来源。

---

## 5. 自我保护（AntiFunc / AntiHelper.dll）

`AntiHelper.dll`（44032 字节）导出 4 个函数，经 `DeviceIoControl` 与内核驱动通信：

```
AddProcessPid、DelProcessPid、SetProtectDirectory、ResetProtectDirectory
```

**加载方式**：`AntiHelper.dll` 经通用"模块缓存对象"（全局 `DAT_00481da4`）**按模块名 `LoadLibraryW("AntiHelper.dll")` 加载**——即走 Windows 默认搜索顺序（优先 exe 目录），非全路径。取函数地址：
`FUN_00437a40/FUN_00437f80/FUN_0043ae20/FUN_0043a9f0` → 构造 `L"AntiHelper.dll"` 与过程名 → `FUN_004318a0(&DAT_00481da4, procName)`（内部 `FUN_004410f0`→`FUN_00435d60`→`LoadLibraryW`，再 `GetProcAddress`）。

| 调用 | 行为 |
|---|---|
| `FUN_00437a40(pid)` | `AntiHelper!AddProcessPid(pid)`（保护进程） |
| `FUN_00437f80(pid)` | `AntiHelper!DelProcessPid(pid)`（解除保护） |
| `FUN_0043ae20(path)` | `AntiHelper!SetProtectDirectory(path)`（保护目录） |
| `FUN_0043a9f0()` | `AntiHelper!ResetProtectDirectory()`（复位目录保护） |
| `FUN_0043a7b0` | **开 AntiFunc**：保护自身 PID + 设置受保护目录（`curPath:%s`），标志 `obj[0x11c]=1`，日志 `Open AntiFunc..!` |
| `FUN_00437d10` | **关 AntiFunc**：解除自身 PID + 学生 PID（`obj[0x588]`）保护、`ResetProtectDirectory`、以密钥串 `548861465` 调 `SetProtectDirectory`（复位），标志置 0，日志 `Close AntiFunc..!` |

- `protect.map` 内容 = `Student.exe`（守护对象）。
- `FUN_00437a40/FUN_00437f80` 也用于保护 `Student.exe` / `DeviceControl` 的 PID。

---

## 6. 注册表 / 配置写入

| 目标 | 函数 | 内容 |
|---|---|---|
| `HKLM\SOFTWARE\OCloud` | `FUN_0043c460` | 值 `Broadcasting`（REG_DWORD，`regedit-broadcast`）；已存在则日志 `already exist` |
| `TeaSide.ini` | `FUN_0043b930` | `[TeaSide] Flag=1`（`start-teacher`，`WritePrivateProfileStringW`） |
| `TeaSide.ini` | `FUN_00435230`（读） | `Flag` / `WaitSeconds` |

---

## 7. 子进程与文件

### 7.1 子进程

| 进程 | 触发 | 函数 |
|---|---|---|
| `Student.exe` | 3s 保活 / 守护 | `FUN_00437df0`（`FUN_0043b3a0` 启动 + `FUN_00437a40` 保护） |
| `MultiClient.exe` | `start-multiclient` | `FUN_00438b70`（`FUN_0043b510`） |
| `AudioRender.exe`、`ScreenRender.exe`、`Barrage.exe`、`MultiClient.exe` | winlogon 桌面切换时**结束** | `FUN_00439fb0`（`FUN_004413b0` 逐一 TerminateProcess） |
| `DeviceControl_x64/x86.exe` | NPD 保护 | `FUN_00437ae0` |
| `LISSNetInfoSniffer.exe` | `start-lissNet` | `FUN_00438b70` |
| `Teacher.exe` | `start-teacher` | `FUN_0043b930` |
| `EXPLORER.EXE` / `LOGONUI.EXE` / `winlogon.exe` | 令牌/桌面/检测 | 多处 |

### 7.2 数据文件

| 文件 | 内容 | 用途 |
|---|---|---|
| `add.map` | 24 个 exe（含 `x64\x86\` 子目录、重复项） | 5s 定时器 `FUN_00405d30` 逐行处理 → **防火墙放行规则**（见 §7.3） |
| `protect.map` | `Student.exe` | 守护对象 |
| `kill1.bat` / `kill3.bat` | 运行时写出（内容来自命令 `cmd1`/`cmd3`） | 杀进程脚本 |
| `TeaSide.ini` | `[TeaSide] Flag` | 角色 |
| `log.txt` | 服务日志（>2MB 轮转） | 日志 |

`add.map` 实际内容（24 行）：

```
AudioOrVideoBroadcast.exe  AudioPlayRender.exe  AudioRecordSender.exe  AudioRender.exe
AudioSender.exe  AudioRepeater.exe  client_console.exe  x64\Ctsc_Multi.exe
x86\Ctsc_Multi.exe  MultiClient.exe  MultiRender.exe  ScreenRender.exe
ScreenSender.exe  SharedDesktop.exe  Student.exe  StudentScreenHelper.exe
Teacher.exe  transfer_console.exe  toolkits\bin\PainterServer.exe  VdiChannel.exe
VideoTechConsole.exe  MediaFileSender.exe  ScreenRender.exe  LissHelper.exe
```

### 7.3 `add.map` = Windows 防火墙放行规则

整条链路是 **Windows 防火墙 COM 自动化**：

- `FUN_00405d30`（5s 定时器）逐行读 `add.map`：
  1. `FUN_00406080('\0')` 判定条目是否有效文件/目录（`FUN_00408340`=文件、`FUN_00408580`=目录）。
  2. `FUN_00405c40(line)` 用 `_wsplitpath` 取**文件名**（basename）。
  3. `FUN_00408100(name)` 判断是否已登记；名字拼成 **`MMC_<basename>`**，若同一 basename 重复出现（按 map 计数）则追加 `_1` → **`MMC_<basename>_1`**。
  4. 调 `FUN_00405740(规则名, 原始行)`。
- `FUN_00405740` 的 COM 类身份（GUID 实证）：

| 用途 | CLSID | IID |
|---|---|---|
| 防火墙策略 | `{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}`（**NetFwPolicy2**） | `{98325047-C671-4174-8D81-DEFCD3F03186}`（**INetFwPolicy2**） |
| 防火墙规则 | `{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}`（**NetFwRule**） | `{AF230D27-BABA-4E42-ACED-F524F22CFCE2}`（**INetFwRule**） |

  - `FUN_00406580` 的失败日志直接写着 `CoCreateInstance for INetFwPolicy2 failed`，坐实类身份。
  - `INetFwPolicy2::get_Rules`(+0x48) 取规则集 → `INetFwRules::Item(name)`(+0x28) 查重，若不存在则 `INetFwRules::Add(rule)`(+0x20)。
  - `INetFwRule` 属性按 vtable 槽位设置：`put_Name`(+0x20)=`MMC_<basename>[_1]`、`put_Description`(+0x28)=常量 `.rdata:0x468bb4`、`put_ApplicationName`(+0x30)=**add.map 原始行**、`put_Protocol`(+0x40)=`256`（`NET_FW_IP_PROTOCOL_ANY`）、`put_Action`(+0xa8)=`1`（`NET_FW_ACTION_ALLOW`）、`put_Enabled`(+0x88)=`-1`（TRUE）。
  - 方向未显式设置 → 取默认**入站**。即：**为 add.map 列出的每个可执行文件创建一条"入站允许"防火墙规则**。

### 7.4 路径拼接辅助 `FUN_00405b00`

`GetModuleFileNameW(NULL)` → 截断到最后一个 `\` → 追加相对名 → 得到"exe 目录 + 相对路径"的绝对路径。所有本地文件（`TeaSide.ini`、`add.map`、`kill*.bat`、`Student.exe`、`Teacher.exe`、`AntiHelper.dll` 等）均以此定位。

---

## 8. 主循环与定时器封装

- `FUN_0042b9f0` → `FUN_0042ba30`：**asio `io_context::run`**（`FUN_00429330` 处理事件，返回非 0 继续并计数）。
- 核心对象由 `FUN_00423f70` 构造，`FUN_004244d0` 中 `*this = boost::asio::detail::win_iocp_io_context::vftable`。
- 辅助判定：`FUN_00439ef0` 经 `LoadLibraryW("ntdll.dll")` 取 `RtlGetNtVersionNumbers` 判 Win10（major10/minor0）；`FUN_00441200` 用 `IsWow64Process` 判 WOW64（选 x86/x64 子目录）。
- 进程查询：`FUN_00439bc0`（按名存在性）、`FUN_00439cb0`（按名 + 会话校验）、`FUN_00438190`（按名取 PID）、`FUN_004413b0`（按名 TerminateProcess）、`FUN_004412d0`（按名判在运行）。

**asio 定时器封装**——周期性任务的重挂模式：

```c
int sec = 3;                                  // 周期（秒）
auto t = FUN_0042cf60(&sec);                  // chrono::seconds 构造
FUN_0042d8b0(t);                              // 时长换算/包装
FUN_004407a0(timer);                          // timer.expires_from_now(...)
auto h = FUN_00430470(handler);               // 绑定回调（分配器）
FUN_004302c0(timer, h);                       // timer.async_wait(...)
```

- 3s：`FUN_00437df0`（学生保活/角色切换）
- 5s：`FUN_00438020` → `FUN_00405d30`（add.map → 防火墙规则）

---

## 9. `assist` / KvmChannel 协议

`assist`（且含 `desktop`）分支：

```
读 JSON["assist"]、JSON["desktop"]
FUN_00435200(obj)                 // 构造参数对象（两个 std::string 成员）
FUN_00404380(buf, &DAT_0046b7c0)  // DAT_0046b7c0 = "kvm"
ch = FUN_0043f080()               // 若入参 == "kvm" → new(8) + FUN_00435140 构造 KvmChannel
if (ch) {
    FUN_0043aec0(ch, obj)         // 把参数对象存到 ch+4
    压入 desktop、assist 两个串
    (*(ch->vptr + 4))();          // 调用唯一虚方法 = FUN_0043ab20
    日志 "result:%s,client_ip:%s"
}
```

- **类结构（vtable 实证）**：

| 类 | vtable | 成员 |
|---|---|---|
| `Channel`（抽象基类） | `0x46bf80` = `{0x437920 析构, 0x461b1d purecall}` | — |
| `KvmChannel` | `0x46c04c` = `{0x437980 析构, FUN_0043ab20}` | `+4` = 参数对象指针 |

- **KvmChannel 唯一虚方法 `FUN_0043ab20`**：
  1. 拼请求 JSON：`{"method":"multimedia","args":{"teacher_ip":"<第一个串>","student_ip":"<第二个串>"},"msg_id":"", "extras":{}}`。
  2. 管道名 = `\\.\Global\com.morningcloud.tcloud.multimedia`。
  3. `FUN_0043c060`：`CreateFileW(OPEN_EXISTING, GENERIC_RW)` → `WriteFile`（长度前缀 + JSON）→ `ReadFile` 应答 → 取 `"client_ip"`。
  4. 把 `client_ip` 写回参数对象（`+0x18`），并按结果布置 `"true"/"false"`；日志 `clientip:%s`。
- 换言之：**`assist="kvm"` 时，MMPC 通过外部多媒体命名管道请求一次 KVM 协助，返回对端 `client_ip`**。

---

## 10. 关键函数索引

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
| 0x00439fb0 | winlogon 桌面切换时结束渲染栈进程 |
| 0x00437df0 | 学生端保活定时器（3s） |
| 0x00437bb0 | LOGONUI 监控定时器（500ms） |
| 0x00438020 / 0x00405d30 | 5s 定时器 / add.map 处理 |
| 0x00406080 / 0x00408340 / 0x00408580 | add.map 条目判定（文件/目录） |
| **0x00405740** | **防火墙规则添加（INetFwRule）** |
| 0x00406580 | 创建 INetFwPolicy2 |
| 0x004059c0 / 0x00406230 | 删除规则 / uninstall 防火墙清理 |
| 0x00405b00 | exe 目录路径拼接 |
| 0x00437ae0 | 启动 DeviceControl |
| 0x0043b930 | start-teacher |
| 0x0043a010 | killallproc（写 bat 执行） |
| 0x0043b8b0 / 0x0043b3a0 / 0x0043afa0 / 0x0043b510 | 4 种进程启动策略 |
| 0x00438550 | 按名取令牌（活动会话） |
| 0x00437a40 / 0x00437f80 / 0x0043ae20 / 0x0043a9f0 | AntiHelper 保护/解除/目录/复位 |
| 0x0043a7b0 / 0x00437d10 | 开/关 AntiFunc |
| 0x004318a0 / 0x004410f0 / 0x00435d60 | GetProcAddress / 懒加载模块 / LoadLibraryW |
| 0x0043c460 | regedit-broadcast（OCloud） |
| 0x00439ef0 / 0x00441200 | Win10 判定 / WOW64 判定 |
| 0x00439bc0 / 0x00439cb0 / 0x00438190 | 进程查询 |
| 0x004413b0 / 0x004412d0 | 按名杀进程 / 按名判在运行 |
| **0x0043f080 / 0x00435140 / 0x004350d0 / 0x0043ab20** | **assist / KvmChannel 构造 / Channel 基类 / KVM 请求** |
| 0x0042cf60 / 0x0042d8b0 / 0x004407a0 / 0x00430470 / 0x004302c0 | asio 定时器封装（秒/包装/expires/绑定/async_wait） |

---

## 11. 字符串 / 常量表

| 地址 | 内容 |
|---|---|
| 0x468bb8 | 宽串 `add.map` |
| 0x468bb4 | INetFwRule `put_Description` 常量（实测为空串） |
| 0x46b7c0 | `kvm` |
| 0x46c120 | `kvm`（`FUN_0043f080` 比较用） |
| 0x468e54 / 0x468e64 | INetFwPolicy2 CLSID / IID |
| 0x468e74 / 0x468e84 | INetFwRule CLSID / IID |
| 0x469ed2 / 0x469ed3 | `kill3.bat` / `kill1.bat`（构建用常量） |
| 0x48f57 等 | `Wait Named Pipe:%s`、`Pipe Create Error:%s` 等日志串 |
| 0x48f5x | `client_ip` / `Pip Return:%s` |

---

## 12. 未决项

1. **命名管道服务端身份**：确认**不在本安装包内**（全样本扫描仅 MMPC 命中）。真实创建者需在运行环境中按会话/句柄定位（疑似 morningcloud/tcloud 云组件）。**KvmChannel 的 `teacher_ip`/`student_ip` 与 assist JSON 字段 `assist`/`desktop` 的精确对应关系**（两串的语义映射）仍待运行态验证。
2. `assist`/`desktop` 字段承载的到底是 IP 还是其它标识（当前仅确定被填入 `teacher_ip`/`student_ip`）。
3. `vdi` 分支的具体批处理内容（运行时生成，随 `cmd` 变化）。
4. `INetFwRule` 未显式设置 `Direction`/`LocalPorts` 等，实际生效方向以运行时抓 `netsh advfirewall`/注册表为准。

---

*本文覆盖：文件指纹、运行模型、通信面（UDP 9030 / 命名管道 / 定时器）、19+ 命令分发、4 种进程启动策略与令牌窃取、AntiHelper 自我保护、注册表/配置写入、add.map→防火墙规则（COM 实证）、asio 定时器封装、KvmChannel 协议、函数与常量索引。*
