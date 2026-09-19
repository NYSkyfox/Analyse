# msvcr120.dll 组件说明（第三方运行库）

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/msvcr120.dll`
> 样本：970552 字节，PE32 DLL（`pei-i386`）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 970552 字节 |
| MD5 | `d8a846c61bf72a3eba1775dec31ee35c` |
| SHA-256 | `fe61ecf62c38205c1b9337c035fa58f46d2c879e2f42df1d2518437fca68c8af` |
| 格式 | PE32 DLL（`pei-i386`） |
| 导入 | `KERNEL32.dll` |

## 1. 角色

**Microsoft Visual C++ 2013 运行库（msvcr120.dll）**——第三方组件，供本安装包内的某些可执行文件（如 `easyusbinstall.exe`/`KbDriver.exe` 等以 VS2013 构建的模块）使用。

## 2. 备注

- 与被测软件的"管控"逻辑无关，属**依赖库**。
- 存在于 `$_12_`（安装目录）说明这些模块运行时可能就近加载该 DLL。

---

*本文仅定位：msvcr120.dll 为第三方 VC++2013 CRL，便于完整清点安装包内容。*