# NSIS 插件（$PLUGINSDIR）组件说明

> 来源：`DriverInstall.exe` NSIS 解包 → `$PLUGINSDIR/`
> 样本：`System.dll`（11264）、`nsExec.dll`（6656）、`ExecCmd.dll`（4608）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 来源 | `DriverInstall.exe` NSIS 解包 → `$PLUGINSDIR/` |
| 样本 | `System.dll`(11264) / `nsExec.dll`(6656) / `ExecCmd.dll`(4608) |
| 类型 | NSIS 运行期插件（PE32 i386 DLL） |
| MD5 | `System.dll`=`00a0194c20ee912257df53bfe258ee4a` / `nsExec.dll`=`e54eb27fb5048964e8d1ec7a1f72334b` / `ExecCmd.dll`=`b9380b0bea8854fd9f93cc1fda0dfeac` |
| SHA-256 | `System.dll`=`dc4da2ccadb11099076926b02764b2b44ad8f97cd32337421a4cc21a3f5448f3` / `nsExec.dll`=`ff00f5f7b8d6ca6a79aebd08f9625a5579affcd09f3a25fdf728a7942527a824` / `ExecCmd.dll`=`1f4bd9c9376fe1b6913baeca7fb6df6467126f27c9c2fe038206567232a0e244` |

## 1. 清单

| 文件 | 大小 | MD5 | 类型 | 作用 |
|---|---|---|---|---|
| `System.dll` | 11264 | `00a0194c20ee912257df53bfe258ee4a` | NSIS 插件 | 注册表/文件/字符串等系统操作（NSIS 官方 System 插件） |
| `nsExec.dll` | 6656 | `e54eb27fb5048964e8d1ec7a1f72334b` | NSIS 插件 | 静默执行命令并捕获输出（`nsExec::Exec`） |
| `ExecCmd.dll` | 4608 | `b9380b0bea8854fd9f93cc1fda0dfeac` | NSIS 插件 | 执行外部命令（第三方/自制 exec 插件） |

- 三者都是 **`DriverInstall.exe`（NSIS 安装器）运行期解压到 `$PLUGINSDIR` 的插件**，用于支撑 NSIS 脚本逻辑。
- `System.dll` 依赖 `KERNEL32/USER32/ole32`；`nsExec/ExecCmd` 依赖 `KERNEL32/USER32(/ADVAPI32)`。

## 2. 与安装流程的关系

`DriverInstall.nsi` 通过它们在安装时执行诸如：
- 调用各驱动的安装器（`InstallFbdATS.exe`、`easyusbinstall.exe`、`LoadDriver.exe`、`OeNetLimitSetup.exe` 等，带 `/install` 参数）；
- 写注册表/文件、判断条件（`System.dll`）；
- 静默执行不弹窗（`nsExec.dll`）。

## 3. 备注

- 均为**通用 NSIS 组件**，非 Os-Easy 自研逻辑，仅作为解释"安装器如何执行子安装器"的依据。

---

*本文：$PLUGINSDIR 下三个 NSIS 插件的定位与用途。*