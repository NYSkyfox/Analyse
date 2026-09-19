# InstallEx.exe 组件逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/InstallEx.exe`
> 样本：57344 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_InstallEx.exe.txt`（237 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 57344 字节 |
| MD5 | `e389fda6788dbfed141c314772102364` |
| 入口点 | `0x40162f` |
| 导入 | `ADVAPI32`、`KERNEL32` |
| PDB | `d:\AMSvr\bin\client\Install.pdb` |

## 1. 角色

**`FbdATS.sys` 的另一安装器**（服务名 `FbdATS`）。PDB 路径 `AMSvr\bin\client`（Asset Management Server）暗示它属于**资产/设备管控** 体系。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `usage: %s [/install \| /uninstall]` | 用法 |
| `/install` / `/uninstall` / `install` | 命令行开关 |
| `\drivers\FbdATS.sys` | 驱动相对路径（相对系统目录） |
| `FbdATS` | 服务名 |
| `Error Code = %d` | 错误输出 |
| `CreateServiceA` / `OpenServiceA` / `DeleteService` / `CloseServiceHandle` | 服务操作 |
| `GetSystemDirectoryA` | 取系统目录拼路径 |

## 3. 安装模型

```
1. 解析 argv[1]：/install 或 /uninstall
2. GetSystemDirectoryA() + "\drivers\FbdATS.sys"  → 目标路径
   （源文件来自安装目录，CopyFile 到系统 drivers）
3. /install   → CreateServiceA("FbdATS", SERVICE_KERNEL_DRIVER, lpBinaryPathName=…\drivers\FbdATS.sys) + StartService
   /uninstall → OpenServiceA → ControlService(STOP) → DeleteService
4. 失败打印 "Error Code = %d"
```

## 4. 与 InstallFbdATS.exe 的关系

两者都安装 `FbdATS` 服务：
- `InstallEx.exe`：PDB 属 `AMSvr`（资产管控早期版本），路径用 `GetSystemDirectoryA` 拼接；
- `InstallFbdATS.exe`：较新的部署器，硬编码 `C:\Windows\System32\drivers\%s`，并带更完整的结果日志（`Start uninstall FbdATS...` 等）。

## 5. 关键函数索引（依字符串/调用定位）

| 功能 | 说明 |
|---|---|
| main | `usage: %s [/install \| /uninstall]` |
| 路径 | `GetSystemDirectoryA` + `\drivers\FbdATS.sys` |
| 服务 | `CreateServiceA` / `OpenServiceA` / `DeleteService` |

---

*本文覆盖：InstallEx.exe 指纹、FbdATS 安装/卸载模型、与 InstallFbdATS 的关系、函数定位。*