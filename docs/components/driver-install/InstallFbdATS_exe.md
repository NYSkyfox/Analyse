# InstallFbdATS.exe 组件逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/InstallFbdATS.exe`
> 样本：23592 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_InstallFbdATS.exe.txt`（29 函数）

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 23592 字节 |
| MD5 | `f329830fec1999e23a20d6bfa5e4a396` |
| 入口点 | `0x1002182` |
| 导入 | `ADVAPI32`、`KERNEL32`、`msvcrt`、`SHLWAPI`、`USER32` |

## 1. 角色

**`FbdATS.sys` 的专用安装器**（服务名 `FbdATS`）。与 `InstallEx.exe` 类似，是"文件系统/资产过滤驱动"的部署器。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `C:\Windows\System32\drivers\%s` / `%s.sys` | 目标路径（drivers 目录） |
| `copyfile error...with file is not found` / `copyfile error.. with access is denied` / `copyfile error.. :%lld` | 拷贝失败分支 |
| `OpenSCManger() faild` / `Createservice()faild` / `OpenService()faild` / `DeleteService() faild` / `ControlService() failed` | 服务操作 |
| `service is pending` / `service has existed` | 服务状态分支 |
| `yes you can install!` / `CanInstall:Modify success` / `CanInstall:not found` / `Ok! you can uninstall` / `CanUnInstall::not found` | 安装/卸载前置检查 |
| `Start uninstall FbdATS...` / `Unistall FbdATS Ok!` / `Unistall FbdATS error!` / `FbdATS Install2 error!` | 卸载/安装结果 |
| `/Uninstall` | 命令行开关 |

## 3. 安装模型

```
1. 前置检查（CanInstall/CanUnInstall）→ 决定装/卸
2. CopyFile("<安装目录>\FbdATS.sys" → "C:\Windows\System32\drivers\FbdATS.sys")
3. OpenSCManager → CreateService("FbdATS", SERVICE_KERNEL_DRIVER, lpBinaryPathName = drivers\FbdATS.sys)
4. StartService（失败时按 ERROR_FILE_NOT_FOUND / ALREADY_RUNNING / PENDING 分支处理）
5. 卸载：ControlService(STOP) → DeleteService → 删文件
```

## 4. 关键函数索引（依字符串定位）

| 功能 | 说明 |
|---|---|
| 主入口 | `main(argc, argv)`，识别 `/Uninstall` |
| 拷贝 | `CopyFile` + 错误码分支 |
| 服务 | `OpenSCManager/CreateService/OpenService/DeleteService/ControlService` |
| 前置检查 | CanInstall/CanUnInstall 字符串 |

## 5. 备注

- 与 `InstallEx.exe` 功能重叠（都装 `FbdATS`）；`InstallEx.exe` 使用 `\drivers\FbdATS.sys` 相对路径且 PDB 指向 `AMSvr\bin\client`，二者应属不同时期的部署器。

---

*本文覆盖：InstallFbdATS.exe 指纹、字符串行为、统一安装模型、函数定位。*