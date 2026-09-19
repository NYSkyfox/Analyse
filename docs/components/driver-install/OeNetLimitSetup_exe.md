# OeNetLimitSetup.exe 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/OeNetLimitSetup.exe`（亦作用于 `OeNetLimit.inf`/`oenetlimit*.cat`）
> 样本：96808 字节，PE32 控制台程序（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_OeNetLimitSetup.exe.txt`（299 函数）；关键函数存档 `/root/ghidra/mmpc/setup_funcs.txt`
> 关联：`../OeNetLimit_sys.md`（驱动本体）、`../DeviceControl_exe.md`（上层调用方）

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 96808 字节 |
| MD5 | `98c833e944bd2927dc379a0fa69365ba` |
| 入口点 | `0x100556e` |
| 导入 | `ADVAPI32`、`KERNEL32`、`ole32`、`SETUPAPI`、`USER32`、`SHLWAPI` |
| PDB | `z:\win_drv\new_drv\network\netconfig\objfre_win7_amd64\amd64\OenetlimitSetup.pdb` |

## 1. 角色

**OeNetLimit 网络管控的"全栈"安装器**：一次性部署 **WFP + NDIS(netsf) + TDI(tdifilter) + OeNetLimit** 四类内核部件，并管理服务键与签名目录。

## 2. 命令行

| 参数 | 作用 |
|---|---|
| `/Install` | 安装并（可选）启动 |
| `/InstallAndStart` | 安装并启动 |
| `/Uninstall` | 卸载 |
| `/RemoveNdis5` | 移除 NDIS5 部件 |

## 3. 安装流程 `FUN_1000050dc`（`/Install`）

```
FUN_100004d8c()                                // 环境/权限检查
DbgOut("Begin to install driver...")
GetVersion() → if (major == 5 /*WinXP*/) {
    FUN_1000049cc()                            // 旧驱动清理
    FUN_100003ed0("tdifilter", …)              // 装 TDI 过滤：拷贝 tdifilter.sys + 建服务(组 NetDDEGroup)
    DbgOut("windows xp / Starting install... / Tdi driver install OK!")
    CopyFile  %Windir%\inf\netsf_m.inf / netsf.inf   // 部署 NDIS 过滤 INF
    ...
}
// 其余（Win7/Vista）：WFP + NDIS(netsf) 部件
... FUN_10000422c("OeNetLimit", …)             // 装 OeNetLimit 服务
... SetupCopyOEMInfW(netsf.inf)                // 安装 NDIS 过滤驱动到驱动库
```

## 4. 关键实现（反编译）

### 4.1 拷驱动 + 建服务 `FUN_100003ed0(名字, 是否建服务)`

```c
GetModuleFileNameA(0, path); StrStrIA(path,"oenetlimitsetup.exe"); 截断 → <安装目录>
wsprintfA(src, "%s.sys", 名字);  lstrcatA(<安装目录>, src)      // 源 = 安装目录\<名字>.sys
wsprintfA(dst, "C:\\Windows\\System32\\drivers\\%s", 名字)     // 目标 = drivers 目录
CopyFileA(src, dst, FALSE);                                     // 失败打印 file not found / access denied
if (建服务) {
  hSCM = OpenSCManagerA(0,0,SC_MANAGER_ALL_ACCESS);
  CreateServiceA(hSCM, 名字, 名字, SERVICE_ALL_ACCESS,
                 SERVICE_KERNEL_DRIVER(1), SERVICE_AUTO_START(2), 0,
                 dst /*lpBinaryPathName*/, "NetDDEGroup", 0,0,0,0);
}
```

### 4.2 变体 `FUN_10000422c(名字, …)`

同 4.1 的拷贝逻辑，但 `CreateServiceA(..., SERVICE_KERNEL_DRIVER(1), SERVICE_SYSTEM_START(1), 0, dst, NULL, …)`（无组名）。**OeNetLimit 服务即由这里创建**，`lpBinaryPathName = C:\Windows\System32\drivers\OeNetLimit.sys`。

### 4.3 卸载 `FUN_100005078`

```c
SHDeleteKeyA(HKLM, "SYSTEM\\CurrentControlSet\\services\\Oenetlimit");
SHDeleteKeyA(HKLM, "SYSTEM\\CurrentControlSet\\services\\Oenetlimittmp");
```

### 4.4 其它

- `FUN_1000050dc` 中 `CopyFileW(<安装目录>\netsf_m.inf → %Windir%\inf\netsf_m.inf)`；配合 `SetupCopyOEMInfW` 把 NDIS 过滤 INF 装入驱动库。
- 管理服务键：`SYSTEM\CurrentControlSet\services\Oenetlimit`、`...\Oenetlimittmp`、`...\OECounter\`。
- 日志/DbgOut 串：`FilePath is %s`、`RegisterPath is %s`、`Old driver has remove successfully!`、`Old driver not exist!`、`Wfp/Tdi/ndis5 driver install OK!/error!`。

## 5. 内置的 Service 状态错误处理

`StartService` 失败时按以下分支打印：

```
startService() ERROR_FILE_NOT_FOUND          ← 注册的 .sys 不存在
StartService()faild ERROR_SERVICE_ALREADY_RUNNING
StartService()faild ERROR_IO_PENDING
ControlService() failed / DeleteService() faild %d
service has existed / service is pending
```

## 6. 与 OeNetLimit 驱动的关系

```
OeNetLimitSetup.exe /Install
  ├─ CopyFile OeNetLimit.sys → C:\Windows\System32\drivers\OeNetLimit.sys
  ├─ CreateServiceA("OeNetLimit", …, "C:\Windows\System32\drivers\OeNetLimit.sys")
  ├─ CreateServiceA("Oenetlimittmp", …)      // 临时服务
  ├─ 部署 tdifilter.sys / netsf.inf（NDIS/TDI 部件）
  └─ StartService
```

- 卸载（`/Uninstall`）会 `DeleteService` + `SHDeleteKey` 服务键。

## 7. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x1000050dc | `/Install` 主流程（架构/系统分支、NDIS/TDI/WFP） |
| 0x100003ed0 | 拷贝 .sys + 建服务（组 NetDDEGroup） |
| 0x10000422c | 拷贝 .sys + 建服务（无组，OeNetLimit 本体/临时服务） |
| 0x100005078 | 卸载：SHDeleteKey 服务键 |
| 0x1000049cc / 0x100004d8c | 旧驱动清理 / 环境检查 |
| 0x100005c40 | 安全 Cookie 校验 |

## 8. 未决项

1. `/InstallAndStart`、`/RemoveNdis5` 的完整分支与 `netsf.inf` 的 NetCfg 安装细节。
2. `OECounter` 服务的用途（计数/统计？）待确认。

---

*本文覆盖：OeNetLimitSetup.exe 指纹与命令、安装流程（WFP/NDIS/TDI/本体/临时服务）、拷贝+CreateService 实现、卸载 SHDeleteKey、内建的 Service 错误码处理、函数索引。*