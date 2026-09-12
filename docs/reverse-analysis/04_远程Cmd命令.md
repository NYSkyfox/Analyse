# 04 远程 Cmd 命令

## 一、功能定位

教师端"教室端 Cmd 远程命令"功能，最终落到学生端执行命令。核心执行路径分布在 `systemoper.dll` 和 `MmcImplBase.dll`。

## 二、学生端执行命令的实现

### 1. SYS_RunCommand（systemoper.dll 导出）

反编译 `systemoper.dll FUN_10007580`：

```c
// 命令 = "/k " + 用户命令
local_228 = L"/k ";          // cmd.exe /k（执行后保持窗口）
// 拼接 "/k" + 命令
ShellExecuteW(0, L"open", L"cmd.exe", L"/k命令", 0, param_2);
```

- 通过 `ShellExecuteW("open", "cmd.exe", "/k <命令>")` 执行；
- `param_2` 为显示方式（可隐藏窗口）。

### 2. OE_StopProcess / OE_StopProcessW（MmcImplBase.dll 导出）

杀进程，通过 taskkill 命令：

```c
OE_Sprintf(local_108, "/c taskkill /F /IM %s");
ShellExecuteA(0, "open", "cmd.exe", "/c taskkill /F /IM <进程名>", 0, 0);
```

### 3. OE_RunProcess / OE_RunProcessByUser（MmcImplBase.dll 导出）

运行进程（普通 / 以指定用户身份）。

## 三、教师端侧证据

`Teacher.exe` 中的相关字符串：

```
C:\Windows\System32\cmd.exe      // 调用 cmd.exe
exec                             // 执行命令（多次出现）
RemoteCommand.cache              // 命令缓存
RemoteCommands                   // 命令列表
iCmd                             // 命令 ID
sRemoteIp                        // 远程 IP
SetRemoteCommand                 // 设置远程命令
RemoteCommandDlg.cpp_RemoteReboot          // 远程重启对话框
RemoteCommandDlg.cpp_RemoteShutdownApplication  // 远程关闭应用
```

## 四、完整链路

```
教师端 Teacher.exe
  └─ 选择"远程命令" → 构造命令（cmd.exe / exec）
       └─ 通过 WebSocket/管控通道 发送到学生端
            └─ 学生端 Student.exe / StudentLogic.dll 接收
                 └─ executor 机制分发（"bad executor" 为错误提示）
                      └─ 调用 systemoper.dll SYS_RunCommand / MmcImplBase OE_RunProcess
                           └─ ShellExecuteW("cmd.exe /k命令") 或 CreateProcess
```

## 五、注意点

- 命令执行依赖 `cmd.exe`（`/k` 参数），因此**劫持 cmd.exe（映像劫持）可干扰远程命令执行**；
- `StudentLogic.dll` 中存在 `bad executor` 提示，说明有"执行器"抽象，支持不同类型的执行方式（命令 / 进程 / 直接 exe）；
- 相关可执行文件：`client_console.exe`、`transfer_console.exe`、`ConfBackupRestore.exe`、`BlackSlient.exe` 等由学生端按需启动。
