# MultiMediaConfigForTradition.exe 组件逆向

> 样本：`samples/os-easy/MultiMediaConfigForTradition.exe`（1017856 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/mmconfig`
> 反编译存档：容器内 `/scripts/bizfull.txt`（业务区 1748 个函数全量）、`/scripts/listfuncs.txt`（全量 5536 函数清单）
> 覆盖：全量业务函数反编译与分类扫描

## 样本信息

| 项 | 值 |
|---|---|
| 大小 | 1017856 字节（约 994 KB） |
| 类型 | PE32 Windows GUI（subsystem=2） |
| 架构 | 32 位（i386） |
| MD5 | `5ba5dfee476d4d6df83d890aa10d0224` |
| SHA-256 | `d7dfd4d4a91d252cdebfd2a8c2732c57930143a50a552f94ad5ec521fa9cdfa3` |
| ImageBase | `0x400000` |
| 入口点（E8/RVA 对应入口） | `0x33310` |
| 框架 | MFC140u（MSVC2015+，Unicode / UTF-16LE）+ DuiLib |

**导入依赖**（节选）：
- `KERNEL32`：`CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW` / `OpenProcess` / `TerminateProcess` / `WinExec` / `GetAdaptersAddresses` / `GetAdaptersInfo` / `CreateDirectoryW` / `DeleteFileW` / `GetModuleFileNameW` / `GetTickCount`
- `USER32` / `GDI32`：窗口与绘图
- `WS2_32`：仅 `gethostbyname` 等地址解析辅助，**无 `socket` / `sendto` / `recvfrom` / `bind`**
- `MFC140u.dll`：`AfxWinInit` / `AfxGetThread` / `AfxThrowResourceException` / `AfxMessageBox` 等
- `DuiLib.dll`：DUI 控件体系

## 程序结构

- 32 位 MFC 对话框程序，主对话框类 `CStuSettingDlg`（"传统模式"学生端配置界面）。
- 界面由 DuiLib 渲染，`FUN_00410870` 等加载 `CommMessageBox.xml` 等消息框/界面 XML。
- 全量函数 5536 个，业务代码集中在 `0x400000–0x43ffff`（约 1889 个函数，其中跨度 ≥ 24 字节的业务函数 1542 个）。
- 全量反编译 1748 个业务函数（`/scripts/bizfull.txt`），对全函数集按字符串/导入 API 做分类扫描。

## 功能清单

本程序为纯本地工具，不含网络收发（无 socket/UDP/TCP）、不含 Windows 服务操作、不含注册表读写。功能分为以下类别。

### 1. 配置读取

启动时从 `skin\core.conf` 等配置文件读取各项设置，填充到界面控件。

- `FUN_00417910` / `FUN_004181a0`：以 `key=channel, file=core` 调用 `FUN_0040ef80` 读 `skin\core.conf`，配合 `FUN_00401e60` 取值、`FUN_004058a0` 转整数。
- `FUN_00418320`：读 `IpProto`、`Limit` 等键。
- `FUN_004163d0`：读 `IpProto`，并调用 `GetAdaptersAddresses` / `GetAdaptersInfo` 枚举本机网卡与 IP（见功能 5）。
- `FUN_0041edd0` / `FUN_00417ce0`：读 `user.conf` / `general.conf` 相关项。

### 2. 配置写入

保存时（`FUN_0041efc0`）将界面值写入配置文件，随后触发进程结束与外部程序调用。

**`skin\core.conf`（`file=core`）**：
| 键 | 取值来源 | 出现分支 |
|---|---|---|
| `channel` | 自动模式下由 `FUN_00430490` 计算并回写 | 自动模式 |
| `SearchType` | 0=自动 / 1=手动（界面选择） | 常写 |
| `RemoteIp` | 手动模式下教师端 IP 文本框 | 手动模式 |
| `IpAddressFilter` | IP 过滤文本框 | — |
| `ShowStuMainDlg` | 勾选状态 | — |
| `StuAutoStart` | 勾选状态 | — |
| `StuNavPos` / `StuNavShow` | 导航位置/显示 | — |
| `GeneralEducation` | 勾选状态 | — |
| `IpProto` | 协议/网卡选择 | — |
| `Limit` | 限制项 | — |

写入采用三拍模式：`FUN_0040ef80(&key, "<键名>")` → `FUN_0040ef80(&file, "core")` → `FUN_004029c0()`（落盘）。`FUN_004029c0` 内部调用 `CreateDirectoryW` 确保 `skin` 目录存在。

**`TeaSide.ini`（安装根目录）**：
- `FUN_0041efc0` 末尾调用 `WritePrivateProfileStringW(L"TeaSide", L"Flag", L"0", <路径>)`。
- 路径由 `FUN_00416110` 构造：`GetModuleFileNameW` 取 exe 目录，去掉文件名，拼 `\TeaSide.ini`，故落在安装根目录。
- 键 `[TeaSide] Flag`，固定写 `0`。

**其他配置文件**：
| 文件 | 相关函数 |
|---|---|
| `general.conf` | `FUN_00417ce0`（读）、`FUN_00417e30`（读/写） |
| `user.conf` | `FUN_0041edd0`（读）、`FUN_00418320`（读） |
| `skin\res.config` | `FUN_00417e30`（资源相关读取） |

### 3. 进程结束

保存后按名结束学生端进程链。

- `FUN_0042c6f0(wchar_t*)`：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` → `Process32FirstW`/`Process32NextW` 遍历 → `_wcsicmp` 比对进程名 → `OpenProcess(PROCESS_TERMINATE)` → `TerminateProcess`。
- `FUN_0042c610(wchar_t*)`：仅判断进程是否存在（返回是否找到）。
- `FUN_0043399b` 区域：独立的一处 `TerminateProcess`，用于结束单个指定进程。

结束目标（`_wcsicmp` 比对，不区分大小写）：
`FileTransferClient.exe`、`DeviceControl_x64.exe`、`DeviceControl_x86.exe`、`MultiClient.exe`、`MacRender.exe`、`AudioRender.exe`、`AudioRecordSender.exe`、`AudioPlayRender.exe`、`MultiRender.exe`、`ScreenSender.exe`、`SharedDesktop.exe`、`student.exe`、`StudentScreenHelper.exe`、`ScreenRender.exe`、`OePainter.exe`、`Barrage.exe`。

### 4. 驱动与补丁安装

保存流程内按条件调用 `WinExec` 启动外部程序。

- `FUN_0041f6c0`（`param_1 == 1` 分支）：
  - `WinExec(L"npcapSetup.exe", 0)`：启动 npcap 驱动安装程序。
  - `WinExec(L"DriverInstall.exe", 0)`：启动驱动安装程序。
- `FUN_0041efc0`（`iVar4 == 2` 分支）：
  - `WinExec(L"Windows6.1-KB3033929-x64.msu", 0)`：安装 Windows 系统补丁（KB3033929）。

上述路径均相对于安装目录，由 `WinExec` 以独立进程方式启动。

### 5. 网卡枚举

- `FUN_004163d0`：读取 `IpProto` 配置后调用 `GetAdaptersAddresses` / `GetAdaptersInfo`，枚举本机网卡及其 IP 地址，供界面展示或协议选择使用。

### 6. 文件与目录操作

- `FUN_004157e0` / `FUN_00436750`：执行 `DeleteFileW` / `CreateDirectoryW` 等文件与目录操作，用于清理或准备配置/资源目录。
- `FUN_004029c0`：`CreateDirectoryW` 创建 `skin` 目录。

### 7. 用户界面（DuiLib）

- `FUN_00410870` 等 19 个 DUI 控件函数构成消息框与配置界面。
- 加载 `CommMessageBox.xml` 等界面描述 XML。
- MFC 对话框 `CStuSettingDlg` 作为宿主，DuiLib 负责控件渲染与事件分发。

## 反编译链路

### 保存（`FUN_0041efc0`，`0x41efc0`）

```
FUN_0041efc0():
  ... 各键写入 core.conf（三拍：FUN_0040ef80(&key,name) -> FUN_0040ef80(&file,"core") -> FUN_004029c0()）
  FUN_0040ef80(&key, "channel");     FUN_0040ef80(&file, "core");   FUN_004029c0();  // 自动模式回写 channel
  FUN_0040ef80(&key, "SearchType");  FUN_0040ef80(&file, "core");   FUN_004029c0();
  if (手动模式) { FUN_0040ef80(&key, "RemoteIp"); ... FUN_004029c0(); }
  FUN_0040ef80(&key, "IpAddressFilter"); ... FUN_004029c0();
  FUN_0040ef80(&key, "ShowStuMainDlg"); ... FUN_004029c0();
  FUN_0040ef80(&key, "StuAutoStart");    ... FUN_004029c0();
  FUN_0040ef80(&key, "StuNavPos");       ... FUN_004029c0();
  FUN_0040ef80(&key, "StuNavShow");      ... FUN_004029c0();
  FUN_0040ef80(&key, "GeneralEducation");... FUN_004029c0();
  FUN_0040ef80(&key, "IpProto");         ... FUN_004029c0();
  FUN_0040ef80(&key, "Limit");           ... FUN_004029c0();
  if (iVar4 == 2) WinExec(L"Windows6.1-KB3033929-x64.msu", 0);   // 条件安装系统补丁
  FUN_0041f6c0(1);                       // 条件触发驱动安装（npcapSetup / DriverInstall）
  ... 结束 16 个学生端进程（FUN_0042c6f0 逐个调用）
  FUN_00416110(&local_path);             // 取安装目录
  WritePrivateProfileStringW(L"TeaSide", L"Flag", L"0", local_path);
  ...
```

### 配置读写器（`FUN_0040ef80`，`0x40ef80`）

```
FUN_0040ef80(out*, in*):
  将 (key, file) 二元组暂存到全局 g_key/g_file；
  由 FUN_004029c0（读/写动作）实际执行对 skin\<file>.conf 的 Inifile 操作。
```
- `FUN_00401e60`：按 g_key/g_file 从 Ini 取字符串值。
- `FUN_004058a0`：字符串转整数（`_wtoi` 类）。
- `FUN_004029c0`：执行 Ini 落盘/建目录（`CreateDirectoryW` 确保 `skin`）。
- `FUN_00402b80` / `FUN_00402aa0`：Ini 读取辅助。

### 进程结束（`FUN_0042c6f0`，`0x42c6f0`）

```
FUN_0042c6f0(wchar_t *name):
  hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  Process32FirstW(hSnap, &pe);
  do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
          hProc = OpenProcess(PROCESS_TERMINATE, 0, pe.th32ProcessID);
          if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
      }
  } while (Process32NextW(hSnap, &pe));
  CloseHandle(hSnap);
```

### 路径构造（`FUN_00416110`，`0x416110`）

```
FUN_00416110(wchar_t *out):
  GetModuleFileNameW(0, buf, ...);   // 取 exe 全路径
  截去文件名得目录；
  拼接 L"\\TeaSide.ini" -> *out;
```

## 函数索引

| 地址 | 符号 | 功能 |
|---|---|---|
| `0x41efc0` | `FUN_0041efc0` | 保存处理：写 core.conf 各键、条件装补丁、调驱动安装、结束 16 进程、写 TeaSide.ini |
| `0x40ef80` | `FUN_0040ef80` | 配置读写器（key+file 暂存） |
| `0x4029c0` | `FUN_004029c0` | Ini 落盘 / `CreateDirectoryW` 建 skin 目录 |
| `0x401e60` | `FUN_00401e60` | Ini 取值（字符串） |
| `0x4058a0` | `FUN_004058a0` | 字符串转整数 |
| `0x416110` | `FUN_00416110` | 安装目录路径构造（TeaSide.ini） |
| `0x42c6f0` | `FUN_0042c6f0` | 按名结束进程（Toolhelp32 + TerminateProcess） |
| `0x42c610` | `FUN_0042c610` | 进程存在判断 |
| `0x43399b` | — | 单进程 `TerminateProcess` 调用点 |
| `0x41f6c0` | `FUN_0041f6c0` | `WinExec` 启动 `npcapSetup.exe` / `DriverInstall.exe` |
| `0x4163d0` | `FUN_004163d0` | 读 `IpProto` + `GetAdaptersAddresses`/`GetAdaptersInfo` 枚举网卡 |
| `0x417910`/`0x4181a0` | `FUN_00417910`/`FUN_004181a0` | 读 `core.conf`（channel 等） |
| `0x418320` | `FUN_00418320` | 读 `IpProto`/`Limit` 等 |
| `0x417ce0`/`0x417e30` | `FUN_00417ce0`/`FUN_00417e30` | 读/写 `general.conf` / `skin\res.config` |
| `0x41edd0` | `FUN_0041edd0` | 读 `user.conf` |
| `0x4157e0`/`0x436750` | `FUN_004157e0`/`FUN_00436750` | `DeleteFileW`/`CreateDirectoryW` 文件与目录操作 |
| `0x410870` | `FUN_00410870` | DuiLib 消息框（`CommMessageBox.xml`） |

## 字符串表（业务相关）

- 配置文件：`core` / `general.conf` / `user.conf` / `res.config` / `TeaSide.ini`
- 配置键：`channel` / `SearchType` / `RemoteIp` / `IpAddressFilter` / `ShowStuMainDlg` / `StuAutoStart` / `StuNavPos` / `StuNavShow` / `GeneralEducation` / `IpProto` / `Limit` / `TeaSide` / `Flag`
- 外部程序：`npcapSetup.exe` / `DriverInstall.exe` / `Windows6.1-KB3033929-x64.msu`
- 进程名：`FileTransferClient.exe` / `DeviceControl_x64.exe` / `DeviceControl_x86.exe` / `MultiClient.exe` / `MacRender.exe` / `AudioRender.exe` / `AudioRecordSender.exe` / `AudioPlayRender.exe` / `MultiRender.exe` / `ScreenSender.exe` / `SharedDesktop.exe` / `student.exe` / `StudentScreenHelper.exe` / `ScreenRender.exe` / `OePainter.exe` / `Barrage.exe`
- 界面 XML：`CommMessageBox.xml`

## 分类扫描统计（全量业务函数）

| 类别 | 命中函数数 | 代表 |
|---|---|---|
| core.conf 读写 | 5 | `FUN_0041efc0` / `FUN_00417910` |
| channel / SearchType | 5 / 5 | 同上 |
| RemoteIp | 3 | `FUN_0041efc0` |
| 进程结束（TerminateProcess） | 2 | `FUN_0042c6f0` / `0x43399b` |
| 网卡枚举 | 1 | `FUN_004163d0` |
| 驱动/补丁安装（WinExec） | 2 | `FUN_0041f6c0` / `FUN_0041efc0` |
| 文件/目录操作 | 8 | `FUN_004157e0` / `FUN_00436750` |
| DuiLib UI | 19 | `FUN_00410870` |
| socket/UDP/TCP | 0 | — |
| Windows 服务 / 注册表 | 0 | — |

## 未决项

- `FUN_0041f6c0` 与 `FUN_0041efc0` 中 `WinExec` 各外部程序的完整触发条件（何种配置组合进入 `param_1==1` / `iVar4==2` 分支）未逐分支展开。
- `general.conf` / `user.conf` / `res.config` 的具体键集未逐一列出。
- `FUN_004157e0` / `FUN_00436750` 的目标文件/目录具体路径未逐一确认。
