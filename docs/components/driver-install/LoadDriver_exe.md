# LoadDriver.exe 组件逆向

> 来源：`DriverInstall.exe` NSIS 解包（`/d3=ProcFireWall` 的安装器）
> 样本：27960 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_LoadDriver.exe.txt`（41 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 27960 字节 |
| MD5 | `22025a6ec6222d2807b790612af4f0fb` |
| 入口点 | `0x10021d0` |
| 导入 | `ADVAPI32`、`KERNEL32`、`msvcrt`、`SHLWAPI`、`USER32` |

## 1. 角色

**通用驱动加载器**，在此用于安装 `ProcFireWall.sys`（服务名 `ProcFireWall`）。名字叫 "LoadDriver"，逻辑与其它 `*install*.exe` 一致：拷文件 + 建服务 + 启动。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `C:\Windows\System32\drivers\%s` / `%s.sys` | 目标路径 |
| `OpenSCManger() faild` / `Createservice()faild` / `OpenService()faild` / `DeleteService() faild` / `ControlService() failed` | 服务操作 |
| `service is pending` / `service has existed` | 服务状态 |
| `yes you can install!` / `CanInstall:Modify success` / `CanInstall:not found` / `Ok! you can uninstall` / `CanUnInstall::not found` | 前置检查 |
| `ProcFireWall` | 服务/驱动名 |
| `ProcFireWallInstall error!` / `ProcFirewall install Ok!` | 安装结果 |
| `Start uninstall ProcFireWall...` / `Unistall ProcFireWall error!` / `Unistall ProcFireWall Ok!` | 卸载流程 |
| `/Install` / `/Uninstall` | 命令行开关 |

## 3. 安装模型

```
1. 前置检查（CanInstall/CanUnInstall）
2. CopyFile("<安装目录>\ProcFireWall.sys" → "C:\Windows\System32\drivers\ProcFireWall.sys")
3. CreateServiceA("ProcFireWall", SERVICE_KERNEL_DRIVER, lpBinaryPathName = drivers\ProcFireWall.sys)
4. StartService（ERROR_FILE_NOT_FOUND / ALREADY_RUNNING / PENDING 分支）
5. 卸载：ControlService(STOP) → DeleteService → 删文件
```

## 4. 关键函数索引（依字符串/调用定位）

| 功能 | 说明 |
|---|---|
| main | 解析 `/Install` / `/Uninstall` |
| CopyDriverFile | 拷贝 `.sys` 到 drivers |
| CreateServiceA / OpenServiceA / DeleteService / ControlService | 服务操作 |
| 前置检查 | CanInstall/CanUnInstall |

## 5. 未决项

1. 是否支持任意 `.sys`（作为通用加载器）还是硬编码 `ProcFireWall`——字符串显示为硬编码。

---

*本文覆盖：LoadDriver.exe 指纹、ProcFireWall 安装模型、字符串行为、函数定位。*