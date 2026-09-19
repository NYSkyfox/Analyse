# OeNetLimitSetup.exe 组件深度逆向（网络管控全栈安装器，x64）

> 样本：`samples/os-easy/OeNetLimitSetup.exe`（98344 字节，PE32+ 控制台程序，`i386:x86-64`）
> 同源 x86 副本：`samples/di_flat/OeNetLimitSetup.exe`（96808 B，PE32，已深度反编译，见 `driver-install/OeNetLimitSetup_exe.md`）
> 反编译存档（x86 副本）：`/root/ghidra/mmpc/di/di_OeNetLimitSetup.exe.txt`（299 函数）；`/root/ghidra/mmpc/setup_funcs.txt`
> 关联：`OeNetLimit_sys.md`（驱动本体）、`OeNetLimit_inf.md`（安装描述）、`x86/OeNetlimit_dll.md`（含 CNetInstall 运行期安装）
> 分析日期：2026-09-19（重组；x64 指纹 + 同源 x86 逻辑）

---

## 0. 样本信息

| 项 | x64（os-easy，本样本） | x86（di_flat，同源副本） |
|---|---|---|
| 大小 | 98344 字节 | 96808 字节 |
| MD5 | `e6cf914bf13d5c72fc007ba57e4979bf` | `98c833e944bd2927dc379a0fa69365ba` |
| SHA-256 | `830dc33b40de975511ccd5d0bea1b5984e0af6c27ef97375473562937607be98` | — | — |
| 格式 | PE32+（`pei-x86-64`） | PE32（`pei-i386`） |
| 入口点 | `0x100005c14` | `0x100556e` |
| 导入 | `ADVAPI32`、`KERNEL32`、`ole32`、`SETUPAPI`、`USER32`、`SHLWAPI` | 同左 |
| PDB | （x86 副本：`z:\win_drv\new_drv\network\netconfig\objfre_win7_amd64\amd64\OenetlimitSetup.pdb`） | 同左 |

> 两副本 **MD5 不同、仅架构不同**（x86 PE32 vs x64 PE32+），PDB 同源码树 `…netconfig…OenetlimitSetup.pdb`，判为**同源同版本、仅目标架构不同**。功能逻辑一致；下文函数地址取自 **x86 副本**（x64 地址不同，需另跑 Ghidra 才能给出 x64 地址）。

---

## 1. 角色

**OeNetLimit 网络管控的"全栈"安装器**：一次性部署 **WFP + NDIS(netsf) + TDI(tdifilter) + OeNetLimit** 四类内核部件，并管理服务键与签名目录。

x64 样本关键字符串（已确认）：`OeNetLimit`、`netsf_m.inf`、`\inf\netsf_m.inf`、`netsf.inf`、`ms_OeNetLimit`、`ms_oenetlimit`，以及 `Couldn't install the network component.` / `Failed to uninstall %s.` 等安装/卸载提示。

---

## 2. 命令行

| 参数 | 作用 |
|---|---|
| `/Install` | 安装并（可选）启动 |
| `/InstallAndStart` | 安装并启动 |
| `/Uninstall` | 卸载 |
| `/RemoveNdis5` | 移除 NDIS5 部件 |

---

## 3. 安装流程（`/Install`，逻辑同源 x86）

```
环境/权限检查
GetVersion() → if (major == 5 /*WinXP*/):
    旧驱动清理
    装 TDI 过滤：拷贝 tdifilter.sys + 建服务(组 NetDDEGroup)
    CopyFile  %Windir%\inf\netsf_m.inf / netsf.inf   // 部署 NDIS 过滤 INF
其余（Win7/Vista+）：WFP + NDIS(netsf) 部件
    装 OeNetLimit 服务（CreateServiceA, SystemStart, %12%\OeNetLimit.sys）
    SetupCopyOEMInfW(netsf.inf)                // 把 NDIS 过滤 INF 装入驱动库
```

### 3.1 拷驱动 + 建服务（x86 `FUN_100003ed0`）
```c
GetModuleFileNameA(0, path); StrStrIA(path,"oenetlimitsetup.exe"); 截断 → <安装目录>
wsprintfA(src, "%s.sys", 名字);  lstrcatA(<安装目录>, src)      // 源 = 安装目录\<名字>.sys
wsprintfA(dst, "C:\\Windows\\System32\\drivers\\%s", 名字)     // 目标 = drivers 目录
CopyFileA(src, dst, FALSE);
if (建服务) CreateServiceA(hSCM, 名字, 名字, SERVICE_ALL_ACCESS,
                  SERVICE_KERNEL_DRIVER(1), SERVICE_AUTO_START(2), 0, dst, "NetDDEGroup", 0,0,0,0);
```

### 3.2 OeNetLimit 本体服务（x86 `FUN_10000422c`）
同拷贝逻辑，但 `CreateServiceA(..., SERVICE_KERNEL_DRIVER(1), SERVICE_SYSTEM_START(1), 0, dst, NULL, …)`（无组名）。**OeNetLimit 服务即由这里创建**，`lpBinaryPathName = C:\Windows\System32\drivers\OeNetLimit.sys`。

### 3.3 卸载（x86 `FUN_100005078`）
```c
SHDeleteKeyA(HKLM, "SYSTEM\\CurrentControlSet\\services\\Oenetlimit");
SHDeleteKeyA(HKLM, "SYSTEM\\CurrentControlSet\\services\\Oenetlimittmp");
```

### 3.4 其它
- 拷 `netsf_m.inf → %Windir%\inf\netsf_m.inf`，配合 `SetupCopyOEMInfW` 把 NDIS 过滤 INF 装入驱动库。
- 管理服务键：`services\Oenetlimit`、`...\Oenetlimittmp`、`...\OECounter\`。
- 日志/DbgOut：`FilePath is %s`、`Old driver has remove successfully!`、`Wfp/Tdi/ndis5 driver install OK!/error!` 等。

---

## 4. Service 状态错误处理

`StartService` 失败分支：`ERROR_FILE_NOT_FOUND`（注册的 .sys 不存在）/ `ERROR_SERVICE_ALREADY_RUNNING` / `ERROR_IO_PENDING`；另有 `ControlService() failed`、`DeleteService() faild %d`、`service has existed` / `service is pending`。

---

## 5. 与 OeNetLimit 驱动的关系

```
OeNetLimitSetup.exe /Install
  ├─ CopyFile OeNetLimit.sys → C:\Windows\System32\drivers\OeNetLimit.sys
  ├─ CreateServiceA("OeNetLimit", …, "C:\Windows\System32\drivers\OeNetLimit.sys")
  ├─ CreateServiceA("Oenetlimittmp", …)      // 临时服务
  ├─ 部署 tdifilter.sys / netsf.inf（NDIS/TDI 部件）
  └─ StartService
```

- 卸载（`/Uninstall`）`DeleteService` + `SHDeleteKey` 服务键。
- 运行期按需重装/更新由 `OeNetlimit.dll` 的 `CNetInstall` 承担（见 `x86/OeNetlimit_dll.md` §6），与本 Setup 互补。

---

## 6. 关键函数索引（x86 副本地址）

| 地址 | 职责 |
|---|---|
| 0x1000050dc | `/Install` 主流程（架构/系统分支、NDIS/TDI/WFP） |
| 0x100003ed0 | 拷贝 .sys + 建服务（组 NetDDEGroup） |
| 0x10000422c | 拷贝 .sys + 建服务（无组，OeNetLimit 本体/临时服务） |
| 0x100005078 | 卸载：SHDeleteKey 服务键 |
| 0x1000049cc / 0x100004d8c | 旧驱动清理 / 环境检查 |
| 0x100005c40 | 安全 Cookie 校验 |

> 上述地址均为 **x86 副本**（`0x10000xxxx` 段）；x64 样本入口 `0x100005c14`，函数地址需对 x64 单独跑 Ghidra 方能给出。

---

## 7. 未决项

1. x64 样本独立 Ghidra 反编译（给出 x64 函数地址、逐指令核对与 x86 逻辑一致性）。
2. `/InstallAndStart`、`/RemoveNdis5` 的完整分支与 `netsf.inf` 的 NetCfg 安装细节。
3. `OECounter` 服务的用途（计数/统计？）。

---

*本文覆盖：OeNetLimitSetup.exe（x64）指纹与角色、命令行、全栈安装流程（WFP/NDIS/TDI/本体/临时服务）、拷驱动+建服务+卸载逻辑（同源 x86）、Service 错误处理、与驱动及 OeNetlimit.dll CNetInstall 的关系、函数索引（x86 副本地址）。*