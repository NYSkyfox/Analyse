# ManagerWhtProcPath.exe 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/ManagerWhtProcPath.exe`
> 样本：79160 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_ManagerWhtProcPath.exe.txt`（269 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 79160 字节 |
| MD5 | `6c7189415e830ef77fb091245e9ea45d` |
| SHA-256 | `b3f3bce4a849231fe08b76b3a9bd97c2eb813031cc8ea4d059eb1941cdf636c4` |
| 入口点 | `0x401acd` |
| 导入 | `KERNEL32` |
| PDB | `C:\Users\qiaoli\Documents\Visual Studio 2008\Projects\ManagerWhtProcPath\Release\ManagerWhtProcPath.pdb` |

## 1. 角色

**白名单文件管理器**——维护 `%SystemRoot%\WhiteProcessPath.txt`（OeNetLimit / tdifilter 共用的"允许通行进程"名单）：把一个进程路径**登记/去重写入**该文件。

## 2. 行为（字符串实证）

| 串 | 含义 |
|---|---|
| `SystemRoot` / `GetWindowsDirectory is failed` | 取 `%SystemRoot%` |
| `\WhiteProcessPath.txt` | 目标白名单文件 |
| `FilePath is %s` / `RegisterPath is %s` | 打印路径 |
| `/Install` | 命令行开关 |
| `Parameter is error` / `Parameter Count is error` | 参数校验 |
| `[Install] InstallPath is error,error is %d` / `strstr is failed` / `pTmp is %s` | 安装路径处理 |
| `[Register] Path is NULL` / `[Register] Open File is failed` | 登记前检查 |
| `GetFileSize is failed` / `ReadFile is failed,Error is %d` / `SetFilePointer is failed` | 读写白名单文件 |
| `Path is exsit` | 已存在 → 去重 |
| `[Register] Write File failed` | 追加写失败 |

## 3. 逻辑

```
ManagerWhtProcPath.exe /Install <进程路径>
1. GetWindowsDirectory() → %SystemRoot%
2. 打开 %SystemRoot%\WhiteProcessPath.txt
3. GetFileSize + ReadFile 读入现有名单
4. 若 <进程路径> 已在（strstr 匹配）→ 打印 "Path is exsit"，跳过
5. 否则 SetFilePointer 到末尾 → 追加写入（RegisterPath）
```

- 该文件即 `OeNetLimit.sys` / `tdifilter.sys` 读取的 `\SystemRoot\WhiteProcessPath.txt`（见对应驱动报告）。

## 4. 关键函数索引（依字符串定位）

| 功能 | 说明 |
|---|---|
| main | `/Install` 参数解析 |
| GetWindowsDirectory | 取 %SystemRoot% |
| 文件读写 | GetFileSize / ReadFile / SetFilePointer / WriteFile |
| 去重 | `Path is exsit` 判定 |

## 5. 未决项

1. 白名单条目的具体行格式（是否含端口/子项）与多条目分隔需结合驱动侧解析确认。
2. 除 `/Install` 外是否还有删除/列举子命令。

---

*本文覆盖：ManagerWhtProcPath.exe 指纹、WhiteProcessPath.txt 的登记/去重逻辑、与 OeNetLimit/tdifilter 的共享关系、函数定位。*