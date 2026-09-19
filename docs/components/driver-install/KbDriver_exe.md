# KbDriver.exe 组件逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/KbDriver.exe`
> 样本：28472 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_KbDriver.exe.txt`（48 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 28472 字节 |
| MD5 | `5319baccf0636c9b413f2639f1c15926` |
| 入口点 | `0x10023c7` |
| 导入 | `ADVAPI32`、`KERNEL32`、`msvcrt`、`SHLWAPI` |
| PDB | `d:\win_drv\win_drv\trunk\new_drv\keyboard\kbdriver\kbdriver\objfre_wxp_x86\i386\KbDriver.pdb` |

## 1. 角色

**`KbFilter.sys` 的专用安装器**——不仅创建内核服务 `KbFilter`，还把驱动**注册为"键盘设备类"的上层过滤驱动（UpperFilters）**，使其能挂到键盘栈上生效。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `/install` / `/uninstall`、`start install` / `start uninstall` | 命令行开关 |
| `KbFilter` | 服务名 |
| `system32\drivers\%s.sys` / `\system32\drivers\%s.sys` / `\%s.sys` | 驱动文件路径（drivers 目录） |
| `COPYdriverfile ok!` / `CopyDriverFile failed` | 拷贝驱动文件 |
| `SYSTEM\CurrentControlSet\Services\KbFilter` | 服务注册表键 |
| `SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}` | **键盘设备类 GUID**（Keyboard）→ 写 `UpperFilters` 挂过滤 |
| `shgetvalue 1 ok` / `ShGetvalue1 oK!` / `SHGetValue 1 failed` | 读类键值 |
| `error.remove driver` / `ManageDriver failed` | 失败/移除 |
| `EasyUsb_IsIntall failed` / `enter easyusb_install` | 与 easyusb 逻辑耦合（复用代码） |

## 3. 安装模型

```
1. CopyFile("<安装目录>\KbFilter.sys" → "<系统>\system32\drivers\KbFilter.sys")
2. OpenSCManager → CreateServiceA("KbFilter", SERVICE_KERNEL_DRIVER, lpBinaryPathName=drivers\KbFilter.sys)
3. 写 Class\{4D36E96B-…}（键盘类）的 UpperFilters，加入 KbFilter  → 使其成为键盘上层过滤
4. StartService
5. 卸载：DeleteService + 从 UpperFilters 移除 + 删文件
```

## 4. 关键函数索引（依字符串/调用定位）

| 功能 | 说明 |
|---|---|
| main | 解析 `/install` / `/uninstall` |
| CopyDriverFile | 拷贝 .sys |
| CreateServiceA / OpenServiceA / DeleteService | 服务操作 |
| SHGetValue | 读键盘类注册表键（挂/摘 UpperFilters） |

## 5. 未决项

1. `UpperFilters` 的写入/读取细节（是追加还是覆盖、位置）需细读注册表操作函数。

---

*本文覆盖：KbDriver.exe 指纹、服务+键盘类 UpperFilters 双注册、字符串行为、函数定位。*