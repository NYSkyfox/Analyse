# wpcapSetup.exe 组件说明（第三方 WinPcap 安装器）

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/wpcapSetup.exe`
> 样本：79672 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_wpcapSetup.exe.txt`（243 函数）

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 79672 字节 |
| MD5 | `e7ff5de2ed74f4397f2cf05e4ee85304` |
| 导入 | `SHLWAPI`、`USER32`、`ADVAPI32`、`KERNEL32` |

## 1. 角色

**第三方 WinPcap/Npcap 安装器**——负责把 `npf.sys` 安装为网络抓包服务。

## 2. 行为（字符串实证）

使用与其它安装器相同的服务安装样板：

| 串 | 含义 |
|---|---|
| `copyfile error...with file is not found` / `copyfile error.. with access is denied` / `PATH NOT FOUND` | 拷贝驱动文件 |
| `OpenSCManger() faild` / `Createservice()faild` / `OpenService()faild` | 服务操作 |
| `service is pending` / `service has existed` | 服务状态 |
| `startService() ERROR_FILE_NOT_FOUND` / `StartService()faild ERROR_SERVICE_ALREADY_RUNNING` / `ERROR_IO_PENDING` | 启动错误分支 |
| `The service has been disabled/…/has been marked for deletion` 等 | 标准 Service 错误文本表 |

## 3. 作用

- 把 `npf.sys` 装为服务（`NPF`），供 `Packet.dll` / `wpcap.dll`（用户态）调用来抓包。
- 被 `LISSNetInfoSniffer.exe` / `DeviceControl` 的 `start-lissNet` 流程使用。

## 4. 备注

- **第三方组件**，仅做定位；与 Os-Easy 自研的安装器共用同一套"拷贝+建服务"模板（说明 Os-Easy 直接复用了 WinPcap 的安装代码风格，或二者同源）。

---

*本文：wpcapSetup.exe（WinPcap 安装器）的定位与行为。*