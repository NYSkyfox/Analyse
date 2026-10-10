# MultiMediaConfig.exe 组件逆向

> 样本：`samples/os-easy/MultiMediaConfig.exe`（1055744 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mmconfig2`
> 反编译存档：容器内 `/scripts/bizfull.txt`（业务区 2272 个 `FUN_` 函数全量）、`/scripts/listfuncs.txt`（全量 6058 函数清单）
> 覆盖：全量业务函数反编译与分类扫描

## 样本信息

| 项 | 值 |
|---|---|
| 大小 | 1055744 字节（约 1031 KB） |
| 类型 | PE32 Windows GUI（subsystem=2） |
| 架构 | 32 位（i386，machine 0x14c） |
| MD5 | `468d672c47115fdc3d7fbb68680dc9c2` |
| SHA-256 | `951596dd78bb5101011ecb3cdfa417fb640c6a0d8a8034c8b9419cd51b5b6f56` |
| ImageBase | `0x400000` |
| 入口点（RVA） | `0x3d56d` |
| 节数 | 5 |
| 框架 | MFC140u（MSVC2015+，Unicode / UTF-16LE）+ DuiLib |

**导入依赖**（静态）：`KERNEL32`（`CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW` / `OpenProcess` / `TerminateProcess` / `WinExec` / `CreateFileW` / `ReadFile` / `WriteFile` / `DeleteFileW` / `CreateDirectoryW` / `GetModuleFileNameW` / `FindFirstFileW` / `FindNextFileW` / `LoadLibraryA` / `GetProcAddress` / `GetCurrentThreadId`）、`USER32`、`GDI32`、`MFC140u.dll`、`DuiLib.dll`。

**动态加载**：运行时 `LoadLibraryA("WS2_32.dll")` + `GetProcAddress(..., "inet_pton")`。`WS2_32` 的导出表中仅出现 `inet_pton`；`socket`/`sendto`/`recvfrom`/`bind`/`connect`/`listen`/`accept`/`setsockopt`/`WSAStartup`/`closesocket` 等名称在二进制中均不存在（`socket` 仅作为错误消息字符串 `"socket INVALID_SOCKET"` 出现）。

## 程序结构

- 32 位 MFC 对话框程序，学生端"新模式"配置界面。
- 界面由 DuiLib 渲染，`CommMessageBox.xml` / `CommMessageBoxEx2.xml` / `MultiMediaConfigDlgListElement.xml` 为界面描述 XML。
- 全量函数 6058 个，业务代码（`FUN_` 前缀）2485 个，其中跨度 ≥ 16 字节的 2272 个，分布于 `0x401000–0x4a6308`。
- 与 `MultiMediaConfigForTradition.exe` 同属"学生端配置"组件，二者为同套件的不同模式版本；本版本（新模式）在通信机制上与 ForTradition 版本有结构性差异（见"本地回环 socket 通信"）。
- 全量反编译 2272 个业务函数（`/scripts/bizfull.txt`），对全函数集按字符串/导入 API 做分类扫描。

## 功能清单

### 1. 配置读取

启动时从配置文件读取各项设置填充界面控件，涉及 `core` / `user` / `runtime` 三类文件（由 `FUN_00426a90` / `FUN_004272b0` 按 `operator==<>(...,"core"/"user"/"runtime")` 分支选择）。

- `FUN_00419350`：读 `TeacherIp`（`FUN_00496d80(...,"TeacherIp")`），界面 `SetChannelEdit` / `ChannelSwith`。
- `FUN_004197a0`：读 `ReIp`、`Limit`（界面控件 `L"ReIp"`）。
- `FUN_0041a590`：读 `GeneralEducation`、`Limit`（界面控件 `genneral` / `genneral0` / `option3` / `option4`）。
- `FUN_0041c6f0`：界面控件绑定 `genneral` / `ipv6` / `ipv4`（IPv4/IPv6 选择）。
- `FUN_0041e3d0`：`GetPrivateProfileIntW(L"TeaSide", L"Flag", 0, <TeaSide.ini 路径>)`。

### 2. 配置写入

保存时将界面值写入配置文件。文件类型选择同读取（`core` / `user` / `runtime`）。

- `FUN_00425720`：写入处理，出现 `"Curiptype"` 与 `"core"`（`FUN_00410430(&...,"core")` → `FUN_00402e80()` 落盘）。
- `FUN_00427490`：保存处理（`FUN_004983a0(local_e0,"TeacherIp")` 判断 + `FUN_00496d80(...,"TeacherIp")` 取值写入）。
- `FUN_0041fb10`：保存流程（最大函数，span=23561），含 `MultiConfig.pleaseInputCorrectTeacherIp` 校验提示。
- `FUN_0043b910`：保存流程（span=4733），含 `TeaSide`/`Flag`、`MultiMediaConfigEvent`、`Skin` 处理，并触发进程结束（见功能 3）。

写入键集合（按字符串命中）：`channel`、`TeacherIp`、`ReIp`、`TeaIp`、`ShowStuMainDlg`、`StuAutoStart`、`StuNavPos`、`StuNavShow`、`GeneralEducation`、`IpProto`、`Limit`、`type`、`Automatic`、`Curiptype`、`genneral`。`TeaSide.ini` 以 `GetPrivateProfileIntW(L"TeaSide", L"Flag", ...)` 形式被读取（本版本反编译中未见 `WritePrivateProfileStringW` 的写入点，仅见读取）。

### 3. 进程结束

存在两种并存的结束机制。

**a) 按名遍历结束（Toolhelp32）**：
- `FUN_00435b70`：`CreateToolhelp32Snapshot(2, 0)`（TH32CS_SNAPPROCESS）+ 遍历，单进程快照处理。
- `FUN_00435c50(wchar_t*)`：`CreateToolhelp32Snapshot(2, 0)` + 按名匹配 + `OpenProcess` + 结束；`FUN_0043b910` 保存流程内逐名调用。
- 结束目标（`FUN_0043b910` 内逐一 `FUN_00435c50(L"...")`）：`FileTransferClient.exe`、`DeviceControl_x64.exe`、`DeviceControl_x86.exe`、`MultiClient.exe`、`MacRender.exe`、`AudioRender.exe`、`AudioRecordSender.exe`、`AudioPlayRender.exe`、`MultiRender.exe`、`ScreenSender.exe`、`SharedDesktop.exe`、`student.exe`、`StudentScreenHelper.exe`、`ScreenRender.exe`、`OePainter.exe`、`Barrage.exe`，另含 `Teacher.exe`、`VideoTechConsole.exe`、`VideoTechUi.exe`（二进制字符串命中）。

**b) 单进程结束**：
- `FUN_0043a4d0`：`TerminateProcess((HANDLE)*param_1, 1)` + `WaitForSingleObject((HANDLE)*param_1, 0xffffffff)`。

### 4. 本地回环 socket 通信（守护进程命令）

本版本通过本地回环 socket 向本机守护进程发送 JSON 命令，与学生端/守护进程交互。这是与 ForTradition 版本（无 socket）的核心结构差异。

- 命令构造：`FUN_00496460(this, 0)`（variant/JSON 对象初始化）+ `FUN_00496d80(obj, "type")`（写入键）+ `FUN_00496420(val, "<cmd>")`（写入字符串值）+ `FUN_004969a0(obj, val)`（`obj["type"] = cmd`）+ `FUN_00498e00(obj, out)`（序列化）。
- 命令类型：`npd-auto`（`FUN_004261b0`）、`kill-student`（`FUN_00426280`）、`quit-daemon`（`FUN_00426350` 的 `param_1==0` 分支）、`daemon`（`FUN_00426350` 的 `param_1!=0` 分支）。
- 发送路径：`FUN_00410430(buf, "127.0.0.1")`（目标固定为回环）→ `FUN_004290b0()`（socket 建立/发送，见下）→ `FUN_00429390()`。
- `FUN_004290b0`：`FUN_00410430(&..., "IpProto")` 读协议类型；`iVar3 == 6`（IPv6）分支将 `127.0.0.1` 替换为 `::1` 并调用 `inet_pton` 解析；`iVar3 != 6`（IPv4）分支构造 `AF_INET` 结构；失败时 `FUN_00410430(&..., "socket INVALID_SOCKET")` 后抛异常（`_CxxThrowException`）。内部经 `Ordinal_9` / `Ordinal_11` / `Ordinal_23` 等 `WS2_32` 导出（动态解析，仅 `inet_pton` 在导出表具名）。

命令 JSON 形如 `{"type":"npd-auto"}` / `{"type":"kill-student"}` / `{"type":"quit-daemon"}` / `{"type":"daemon"}`，目标地址 `127.0.0.1`（IPv6 下 `::1`）。

### 5. 驱动安装

保存流程内按条件调用 `WinExec` 启动外部程序。

- `FUN_004285c0`（`param_1 == 1` 分支）：
  - `FUN_00410430(local_74, "npcapSetup.exe")`：准备 npcap 安装程序名。
  - `FUN_0041a1a0(local_5c, "DriverInstall.exe")`：准备驱动安装程序名。
  - `pCVar3 = (LPCSTR)FUN_00432a40(local_44); WinExec(pCVar3, 0)`：以独立进程方式启动。

### 6. 文件与目录操作

- `FUN_00440420`：`CreateFileW(param_1, 8, 7, 0, 3, 0x2200000, 0)`（`0x2200000 = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_WRITE_THROUGH`，写设备/文件）。
- `FUN_00440950`：`CreateFileW(ppppWVar6, 0, 7, 0, 3, 0x2000000, 0)`。
- `FUN_00417f50`：`CreateFileW(local_a3c, 0xc0000000, 3, 0, 2, 0, 0)`（`GENERIC_READ`，共享读）。
- `FUN_0041be40`：`CreateFileA(lpFileName, 0x40000000, ...)`（`GENERIC_WRITE`）。
- `FUN_004288c0`：`WriteFile(*(HANDLE*)(local_f4 + 0x50), lpBuffer, n, ...)`。
- `FUN_0048a991`：`ReadFile(*(HANDLE*)(param_4 + 4), param_1, n, ...)`。
- `FUN_00440880`：`DeleteFileW(pWVar1)`。
- `FUN_00418740` / `FUN_00418a90`：`wsprintfW(local_62c, L"%s//%s")` 拼路径后 `DeleteFileW`。
- `FUN_00418df0`：`FUN_00416a10` 取路径 → `DeleteFileW`。
- `FUN_0048842e`：`CreateFileW(param_2, 0x40000000, 0, 0, 2, local_4234, 0)`。
- `FUN_0048a884`：`CreateFileW(param_1, 0x80000000, 1, 0, 3, 0x80, 0)`（`FILE_FLAG_WRITE_ONLY`）。
- 路径构造：`%s\\*.*`、`%s//%s`、`skin\\core.conf`、`..\\skin\\core.conf`、`skin\\default`、`skin\\res.config`、`general.conf`、`user.conf`、`runtime`。
- 第三方库字符串：`boost::filesystem::remove`（boost 文件系统删除）。

### 7. 用户界面（DuiLib）

- 122 个函数命中 DuiLib 控件类型（`CPaintManager` / `uiLabel` / `uiWindow` / `uiButton` / `uiTextBox` / `uiComboBox` / `uiContainer` 等），界面较 ForTradition 版本更复杂。
- 控件名（`FindControl`）：`genneral` / `genneral0` / `option3` / `option4` / `ipv6` / `ipv4` / `TeaIp` / `text_TeaIp` / `ListDemo1` / `SetChannelEdit` / `ChannelSwith` / `ReIp` / `closebtn` / `okbtn` / `cancel` / `title`。
- 界面 XML：`CommMessageBox.xml`、`CommMessageBoxEx2.xml`、`MultiMediaConfigDlgListElement.xml`。
- 图标：`teacher.ico`（32 次命中）。
- 提示资源：`IDS_COMMON_TIP`、`IDS_COMMON_SAVE`、`MultiConfig.pleaseInputCorrectChannel`、`MultiConfig.pleaseInputCorrectTeacherIp`、`StuSignWarnDlg`。

### 8. 其他

- 日志：`%02d-%02d %02d:%02d:%02d %s\r\n`（时间戳日志格式）、`.log`。
- 压缩/编解码：`zlib` 相关（`bad huffman code` / `too large` / `bad file` / `invalid literal/length code` 等错误串）、`BaseN_Decoder`。
- JSON 库：`std::function` / `std::basic_string` 大量出现，命令以 JSON 形式序列化。
- 时间：`GetTickCount`（1 处）。

## 反编译链路

### 本地回环 socket 发送（`FUN_004290b0`，`0x4290b0`）

```
FUN_004290b0():
  FUN_00410430(&buf, "IpProto");
  iVar3 = FUN_004028c0();              // 读 IpProto 值
  if (iVar3 == 6) {                     // IPv6
      if (strcmp(buf, "127.0.0.1") == 0) FUN_00415290(&buf, "::1");
      ... 构造 IPv6 结构 ...
      inet_pton();                      // WS2_32 动态导出
      if (result == -1) { FUN_00410430(&err, "socket INVALID_SOCKET"); _CxxThrowException(...); }
  } else {                              // IPv4
      ... 构造 AF_INET 结构 ...
      if (result == 0xffffffff) { FUN_00410430(&err, "socket INVALID_SOCKET"); _CxxThrowException(...); }
  }
  FUN_0043b1a0(10);                     // 发送/完成
```

### 守护进程命令封装（`FUN_004261b0` / `FUN_00426280` / `FUN_00426350`）

```
FUN_004261b0():                        // npd-auto
  FUN_0041d6a0();
  FUN_00496460(&obj, 0);               // JSON 对象
  FUN_00496420(&val, "npd-auto");      // 字符串值
  obj["type"] = val;                   // FUN_00496d80 + FUN_004969a0
  FUN_00498e00(&obj, &out);            // 序列化
  FUN_00410430(&addr, "127.0.0.1");
  FUN_004290b0();                       // socket 发送
  FUN_00429390();

FUN_00426280():                        // kill-student（结构同上，值 "kill-student"）
FUN_00426350(param_1):
  if (param_1 == 0) { 命令 "quit-daemon"; }
  else               { 命令 "daemon"; }
```

### 进程结束（`FUN_00435c50`，`0x435c50`）

```
FUN_00435c50(wchar_t *name):
  if (name != 0) {
      pvVar2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (pvVar2 != INVALID_HANDLE_VALUE) {
          ... Process32FirstW/NextW 遍历，按名匹配，OpenProcess + TerminateProcess ...
          CloseHandle(pvVar2);
      }
  }
```

### 保存流程（`FUN_0043b910`，`0x43b910`，span=4733）

```
FUN_0043b910():
  ... 写 core.conf / user.conf 各键（"Curiptype"/"core"/"TeacherIp"/"ReIp"/"type" 等）...
  GetPrivateProfileIntW(L"TeaSide", L"Flag", 0, <TeaSide.ini 路径>);   // 读 TeaSide Flag
  ... Skin / MultiMediaConfigEvent 处理 ...
  FUN_00418df0();                              // 删除某文件
  FUN_00435c50(L"FileTransferClient.exe");
  FUN_00435c50(L"DeviceControl_x64.exe");
  FUN_00435c50(L"DeviceControl_x86.exe");
  FUN_00435c50(L"MultiClient.exe");
  FUN_00435c50(L"MacRender.exe");
  ... 逐名结束其余学生端进程 ...
```

## 函数索引

| 地址 | 符号 | 功能 |
|---|---|---|
| `0x4290b0` | `FUN_004290b0` | 本地回环 socket 建立/发送（`inet_pton` + WS2 动态导出，IPv4/IPv6 分支） |
| `0x4261b0` | `FUN_004261b0` | 守护进程命令 `npd-auto`（JSON 构造 + 发送 127.0.0.1） |
| `0x426280` | `FUN_00426280` | 守护进程命令 `kill-student` |
| `0x426350` | `FUN_00426350` | 守护进程命令 `quit-daemon` / `daemon` |
| `0x4285c0` | `FUN_004285c0` | `WinExec` 启动 `npcapSetup.exe` / `DriverInstall.exe` |
| `0x435b70` | `FUN_00435b70` | Toolhelp32 进程快照（单进程） |
| `0x435c50` | `FUN_00435c50` | 按名遍历结束进程 |
| `0x43a4d0` | `FUN_0043a4d0` | 单进程 `TerminateProcess` + `WaitForSingleObject` |
| `0x43b910` | `FUN_0043b910` | 保存流程：写配置 + 读 TeaSide Flag + 结束 16+ 进程 |
| `0x41fb10` | `FUN_0041fb10` | 保存流程（最大函数，含 TeacherIp 校验） |
| `0x427490` | `FUN_00427490` | 保存处理（`TeacherIp` 读写） |
| `0x425720` | `FUN_00425720` | 写入处理（`Curiptype` / `core`） |
| `0x419350` | `FUN_00419350` | 读 `TeacherIp` |
| `0x4197a0` | `FUN_004197a0` | 读 `ReIp` / `Limit` |
| `0x41a590` | `FUN_0041a590` | 读 `GeneralEducation` / `Limit` |
| `0x41e3d0` | `FUN_0041e3d0` | 读 `TeaSide.ini` `Flag` |
| `0x41c6f0` | `FUN_0041c6f0` | 界面控件绑定（`genneral`/`ipv6`/`ipv4`） |
| `0x426a90` | `FUN_00426a90` | 文件类型选择（`core`/`user`/`runtime`） |
| `0x4272b0` | `FUN_004272b0` | 文件类型选择（`core`/`user`/`runtime`） |
| `0x440420` | `FUN_00440420` | `CreateFileW`（`FILE_FLAG_BACKUP_SEMANTICS \| FILE_FLAG_WRITE_THROUGH`） |
| `0x417f50` | `FUN_00417f50` | `CreateFileW`（`GENERIC_READ`） |
| `0x41be40` | `FUN_0041be40` | `CreateFileA`（`GENERIC_WRITE`） |
| `0x4288c0` | `FUN_004288c0` | `WriteFile` |
| `0x48a991` | `FUN_0048a991` | `ReadFile` |
| `0x440880` | `FUN_00440880` | `DeleteFileW` |
| `0x418740`/`0x418a90` | `FUN_00418740`/`FUN_00418a90` | `wsprintfW` 拼路径 + `DeleteFileW` |
| `0x418df0` | `FUN_00418df0` | 取路径 + `DeleteFileW` |

## 字符串表（业务相关）

- 配置文件：`core` / `user` / `runtime` / `skin\\core.conf` / `..\\skin\\core.conf` / `general.conf` / `user.conf` / `skin\\res.config` / `skin\\default` / `TeaSide.ini` / `skin`
- 配置键：`channel` / `TeacherIp` / `ReIp` / `TeaIp` / `ShowStuMainDlg` / `StuAutoStart` / `StuNavPos` / `StuNavShow` / `GeneralEducation` / `IpProto` / `Limit` / `type` / `Automatic` / `Curiptype` / `genneral` / `genneral0` / `option3` / `option4` / `TeaSide` / `Flag` / `ipv4` / `ipv6`
- 守护进程命令：`npd-auto` / `kill-student` / `quit-daemon` / `daemon` / `127.0.0.1`
- 外部程序：`npcapSetup.exe` / `DriverInstall.exe`
- 进程名：`FileTransferClient.exe` / `DeviceControl_x64.exe` / `DeviceControl_x86.exe` / `MultiClient.exe` / `MacRender.exe` / `AudioRender.exe` / `AudioRecordSender.exe` / `AudioPlayRender.exe` / `MultiRender.exe` / `ScreenSender.exe` / `SharedDesktop.exe` / `student.exe` / `StudentScreenHelper.exe` / `ScreenRender.exe` / `OePainter.exe` / `Barrage.exe` / `Teacher.exe` / `VideoTechConsole.exe` / `VideoTechUi.exe`
- 界面 XML：`CommMessageBox.xml` / `CommMessageBoxEx2.xml` / `MultiMediaConfigDlgListElement.xml`
- 提示资源：`IDS_COMMON_TIP` / `IDS_COMMON_SAVE` / `MultiConfig.pleaseInputCorrectChannel` / `MultiConfig.pleaseInputCorrectTeacherIp` / `StuSignWarnDlg` / `TeacherAppError`
- 网络：`socket INVALID_SOCKET` / `inet_pton` / `WS2_32.dll` / `127.0.0.1` / `::1`

## 分类扫描统计（全量业务函数）

| 类别 | 命中函数数 | 代表 |
|---|---|---|
| core.conf 读写 | 2 | `FUN_00425720` |
| channel | 4 | `FUN_00419350` |
| SearchType | 3 | — |
| RemoteIp | 2 | — |
| ShowStuMainDlg | 5 | — |
| StuAutoStart | 4 | — |
| StuNavPos | 4 | — |
| StuNavShow | 4 | — |
| GeneralEducation | 4 | `FUN_0041a590` |
| IpProto | 4 | `FUN_004290b0` |
| Limit | 7 | `FUN_004197a0` / `FUN_0041a590` |
| general.conf | 1 | — |
| user.conf | 2 | — |
| res.config | 1 | — |
| TeaSide / Flag | 9 | `FUN_0041e3d0` / `FUN_0043b910` |
| 进程结束（Toolhelp32/TerminateProcess） | 3 | `FUN_00435b70` / `FUN_00435c50` / `FUN_0043a4d0` |
| WinExec（驱动安装） | 1 | `FUN_004285c0` |
| npcap | 1 | `FUN_004285c0` |
| DriverInstall | 1 | `FUN_004285c0` |
| 本地 socket（`inet_pton`/`INVALID_SOCKET`） | 1 | `FUN_004290b0` |
| 文件 I/O（CreateFile/Read/Write） | 8 | `FUN_00440420` / `FUN_00417f50` / `FUN_004288c0` |
| DeleteFile | 4 | `FUN_00440880` / `FUN_00418740` |
| CreateDirectory | 1 | — |
| FindFirstFile | 2 | — |
| GetModuleFileName | 4 | — |
| DuiLib UI | 122 | `FUN_0041c6f0` / `FUN_0041c600` |
| 界面 XML | 6 | — |
| Windows 服务 / 注册表 | 0 | — |
| 网卡枚举（GetAdapters*） | 0 | — |

## 与 MultiMediaConfigForTradition.exe 的对比

| 维度 | MultiMediaConfig.exe（本版本，新模式） | MultiMediaConfigForTradition.exe（传统模式） |
|---|---|---|
| 网络 | 本地回环 socket（`inet_pton` + `WS2_32` 动态加载），向 127.0.0.1 发送守护进程命令 | 无 socket，纯本地 |
| 守护进程命令 | `npd-auto` / `kill-student` / `quit-daemon` / `daemon`（JSON，`{"type":"..."}`） | 无 |
| 进程结束 | Toolhelp32 遍历（`FUN_00435c50`）+ 单进程 `TerminateProcess`（`FUN_0043a4d0`） | Toolhelp32 遍历（`FUN_0042c6f0`） |
| 配置键 | `TeacherIp` / `ReIp` / `TeaIp` | `RemoteIp` / `IpAddressFilter` |
| 系统补丁 | 无（无 `.msu`） | `WinExec` 启动 `Windows6.1-KB3033929-x64.msu` |
| 网卡枚举 | 无（无 `GetAdapters*`） | `GetAdaptersAddresses` / `GetAdaptersInfo` |
| 驱动安装 | `WinExec` 启动 `npcapSetup.exe` / `DriverInstall.exe` | 同 |
| 文件类型 | `core` / `user` / `runtime` 三类 | `core`（`skin\\core.conf`） |
| TeaSide.ini | 读 `Flag`（`GetPrivateProfileIntW`） | 写 `Flag=0`（`WritePrivateProfileStringW`） |
| 界面 | DuiLib 122 函数，控件含 `ipv4`/`ipv6`/`genneral`/`option3/4` | DuiLib 19 函数 |

## 未决项

- 本地回环 socket 的端口号与守护进程端协议未在反编译中显式出现（`FUN_0043b1a0(10)` 的实参 10 可能为端口或标志，需进一步确认）。
- `WS2_32.dll` 经 `GetProcAddress` 动态解析的全部导出未逐一确认（导出表仅 `inet_pton` 具名，其余以 `Ordinal_*` 形式引用）。
- `core` / `user` / `runtime` 三类配置文件各自的具体键集未逐一展开。
- `daemon` 命令（`FUN_00426350` 的 `param_1 != 0` 分支）的具体负载内容未完整提取。