# easyusbinstall.exe 组件深度逆向（USB 管控独立安装器）

> 样本：`samples/os-easy/easyusbinstall.exe`（138552 字节，x64 PE32+ 控制台程序）
> 工具：objdump + strings（逻辑与 `easyusbctrl_dll.md` 的 `EasyUsb_Intall/UnIntall` 同源，命令化封装）
> 关联：`easyusbflt_sys.md`（内核驱动）、`easyusbctrl_dll.md`（控制库，含同等安装逻辑）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 138552 字节 |
| MD5 | `b474f594aa7f0b4fedb21d5e213c829e` |
| SHA-256 | `26a8a80ecbd930a510fcd409327001e90f7225594d798ea0bf9da884f3021a76` |
| 格式 | PE32+ 控制台 EXE（`pei-x86-64`） |
| 入口点 | `0x1400029e8` |
| 版本串 | `easyusbinstall, Version 1.0`、`About easyusbinstall` |

**导入**：`KERNEL32`、`ADVAPI32`、`SHLWAPI`。关键 API：
- 服务：`OpenSCManagerW`、`OpenServiceW`、`CreateServiceW`、`DeleteService`、`CloseServiceHandle`
- 文件：`CopyFileW`、`DeleteFileW`、`CreateFileA/W`、`GetWindowsDirectoryW`、`GetModuleFileNameW`
- 注册表：`SHSetValueW`、`SHGetValueW`、`SHDeleteKeyW`、`SHDeleteValueW`

**命令行**：
```
easyusbinstall.exe /install     安装 easyusbflt 驱动
easyusbinstall.exe /uninstall   卸载
```

---

## 1. 角色概述

`easyusbinstall.exe` 是 **`easyusbflt.sys` 的独立命令行安装器**，功能与 `easyusbctrl.dll` 的 `EasyUsb_Intall`/`EasyUsb_UnIntall` **完全对应**（同一套代码的 EXE 形态），供脚本/批处理在无 UI 场景下部署/移除 USB 管控驱动。

关键串（与 DLL 一致）：
- `easyusbflt`（服务名/驱动名）
- `\\system32\\drivers\\%s.sys` / `system32\\drivers\\%s.sys`（.sys 落点）
- `SYSTEM\CurrentControlSet\Services\easyusbflt`（服务键）
- `SYSTEM\CurrentControlSet\Services\OECounter\`（计数键，可选）
- `SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}`（存储盘类 GUID）
- `UpperFilters`（上层过滤驱动挂载点）

## 2. 安装流程（`/install`）

```
1) GetModuleFileNameW → 本 exe 所在目录，取 easyusbflt.sys
2) CreateFileW 校验 .sys 存在
3) CopyFileW(本目录\easyusbflt.sys → C:\Windows\system32\drivers\easyusbflt.sys)
4) OpenSCManagerW + CreateServiceW("easyusbflt", SERVICE_KERNEL_DRIVER, ...,
       ImagePath = \SystemRoot\system32\drivers\easyusbflt.sys)
5) 注册表挂接：SHSetValueW(
       HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000},
       "UpperFilters", REG_MULTI_SZ, "easyusbflt")
   → 把 easyusbflt 作为存储（Disk Drive）类的上层过滤驱动，驱动侧据此挂 \Driver\USBSTOR
```

## 3. 卸载流程（`/uninstall`）

```
1) OpenSCManagerW + OpenServiceW("easyusbflt") → DeleteService
2) SHDeleteKeyW(HKLM, "SYSTEM\CurrentControlSet\Services\easyusbflt")   // 删服务键（含 list/pw）
3) DeleteFileW(C:\Windows\system32\drivers\easyusbflt.sys)             // 删驱动文件
4) 从 Class\{36FC9E60-...}\UpperFilters 多值串摘除 "easyusbflt"；若空则 SHDeleteValueW
```

## 4. 与 easyusbctrl.dll 的异同

| 维度 | easyusbinstall.exe | easyusbctrl.dll |
|---|---|---|
| 形态 | 独立命令行 EXE | 被上层链接/调用的 DLL |
| 入口 | `/install` `/uninstall` 命令行 | `EasyUsb_Intall` / `EasyUsb_UnIntall` API |
| 安装逻辑 | 拷 .sys → 注册服务 → 挂 UpperFilters | **相同** |
| 卸载逻辑 | 删服务 → 删 .sys → 摘 UpperFilters | **相同** |
| 附加 | 无设备通信（纯安装） | 含 11 个 `EasyUsb_*`（白名单/启停/查询等运行时操作） |

> 二者面向同一驱动 `easyusbflt`，注册表键与存储类 GUID 完全一致；EXE 用于部署阶段，DLL 用于运行阶段。

## 5. 与体系的关系

```
部署阶段：
  教师端部署脚本 / student_install_control.bat
    → easyusbinstall.exe /install   （或 easyusbctrl.dll::EasyUsb_Intall）
        → easyusbflt.sys 安装为存储类上层过滤驱动

运行阶段：
  DeviceControl.exe → easyusbctrl.dll → \\.\EasyUsbflt → easyusbflt.sys
```

## 6. 未决项

1. 安装包内旧版 `easyusbinstall.exe`（135992 字节，MD5 见 driver-install 报告）与本顶层版（138552 字节）的字节差异。
2. `Services\OECounter\` 计数键的用途（本 exe 串中引用，疑为 USB 使用次数/设备计数）。
3. 是否附带签名目录 / `pnputil` 注册路径（本 exe 走 CreateServiceW，未见 INF/签名流程）。

---

*本文覆盖：easyusbinstall.exe 指纹、命令行、安装/卸载流程（.sys→drivers + CreateServiceW + 存储类 UpperFilters 挂接）、与 easyusbctrl.dll 的对应关系、与部署/运行体系的位置。*