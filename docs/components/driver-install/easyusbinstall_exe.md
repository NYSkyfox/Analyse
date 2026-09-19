# easyusbinstall.exe 组件逆向

> 来源：`DriverInstall.exe` NSIS 解包（`/d2=easyusbflt` 的安装器）
> 样本：135992 字节，PE32 GUI/控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_easyusbinstall.exe.txt`（288 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 135992 字节 |
| MD5 | `45bc4696c2c08e79b4004b56631ebb7d` |
| 入口点 | `0x4027e6` |
| 导入 | `KERNEL32`、`SHLWAPI`、`ADVAPI32` |
| PDB | `D:\win_drv\win_drv\trunk\new_drv\easyusb\Release\easyusbinstall.pdb` |

## 1. 角色

**`easyusbflt.sys`（USB 白名单过滤驱动）的安装器**。用宽字符 API 版本操作服务。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `CreateServiceW` / `OpenServiceW` / `DeleteService` / `CloseServiceHandle` | 服务安装/卸载（**W 版 API**） |
| `CanInstall:not found` / `CanInstall:Modify success` / `yes you can install!` / `CanUnInstall::not found` / `Ok! you can uninstall` | 安装/卸载前置检查 |
| `runtime error …`、`TLOSS/SING/DOMAIN error`、`unexpected heap error` | 来自 CRT 的运行时错误串（内嵌 CRT） |
| `GetSystemTimeAsFileTime` / `GetOEMCP` 等 | CRT 初始化 |

## 3. 安装模型

```
1. 前置检查（CanInstall/CanUnInstall）
2. 复制 easyusbflt.sys 到系统 drivers 目录（同类安装器统一做法）
3. CreateServiceW("easyusbflt", SERVICE_KERNEL_DRIVER, …)
4. StartService
5. 卸载：OpenServiceW → ControlService(STOP) → DeleteService
```

## 4. 与其它组件的关系

- 安装的 `easyusbflt.sys` 需作为 **USB 设备类上层过滤**（UpperFilters）才能生效；`easyusbctrl.dll` 暴露 `EasyUsb_StartWorking` / `EasyUsb_StopWorking` 供运行时启停；`DeviceControl` 的 `CtrlCode` 中 USB 相关位最终驱动此链（另见 `DeviceControl_exe.md`、`easyusbflt_sys.md`）。
- `KbDriver.exe` 中残留 `EasyUsb_IsIntall` / `enter easyusb_install` 字样，说明二者共用同一套驱动安装代码库。

## 5. 关键函数索引

| 功能 | 说明 |
|---|---|
| main / WinMain | 入口与命令行 |
| CreateServiceW / OpenServiceW / DeleteService | 服务操作 |
| CanInstall/CanUnInstall 检查 | 前置判定 |
| CRT | 内嵌 VC 运行时 |

## 6. 未决项

1. 是否同时写 USB 类 `UpperFilters`（注册表）需细读（当前字符串证据主要在服务层）。

---

*本文覆盖：easyusbinstall.exe 指纹、服务安装（W API）、前置检查、与 easyusbflt/KbDriver 的关系。*