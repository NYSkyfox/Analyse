# OeNetLimit.sys 组件说明（驱动安装程序内置副本）

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/OeNetLimit.sys`
> 样本：`samples/di_flat/OeNetLimit.sys`（42520 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_OeNetLimit.sys.txt`（83 函数）
> **完整逆向见**：`../OeNetLimit/OeNetLimit_sys.md`（`os-easy/` 根目录样本，x64；二者逻辑一致）

---

## 0. 样本信息与差异

| 项 | 值 |
|---|---|
| 大小 | 42520 字节 |
| MD5 | `10668397e1ca3b56e77bbc53aef742a6` |
| SHA-256 | `25b75af685377d79f7b809964d5022273022cbc57d14cbbc774aaabcfb0d6046` | — |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x2603E` |
| 导入 | `ntoskrnl.exe`、`HAL.dll`、`NDIS.SYS`、`fwpkclnt.sys` |

安装包内为 **x86 版**（`x64/OeNetLimit.sys` 为 44568 字节的 64 位版，二者哈希不同、逻辑同源）。安装器 `OeNetLimitSetup.exe` 按架构选择对应 `.sys` + `oenetlimitx86.cat` / `oenetlimitx64.cat`。

## 1. 关键结论（与 x64 版一致）

- **WFP 过滤驱动 + NDIS 过滤服务（NetService）**：
  - callout：`WfpSampleInboundIPV4CalloutName`、`WfpSampleOutboundIPV4CalloutName`、`WfpSampleAleResourceAssignmentCalloutName`、`WfpSampleAleResourceReleaseCalloutName`
  - 子层/过滤器：`WfpSampleSubLayerName`、`WfpSampleFilter{Inbound,Outbound}IPV4Name`、`WfpSampleFilterAleResource{Assignment,Release}Name`
- 设备 `\Device\OeNetLimit` / `\DosDevices\OeNetLimit`；IOCTL `0x122048`(SET SpeedControl) / `0x122044`(GET SpeedControl)，结构 `0xF534`。
- 进程白名单：`\SystemRoot\WhiteProcessPath.txt`，内置 `StormPlayer.exe / acad.exe / LMU.exe / SLDWORKS.exe`。
- 进程创建监控：`PsSetCreateProcessNotifyRoutine` → `OE process start:%wZ`。
- DNS/IP 白名单：`g_DnsIpWhiteList`（`AddDnsWhiteListIp … is full`）。
- 日志串 `OEDRV WfpSampleIRPDispatch Check OEDRV_IsPassProcess`、`OE_NET IOCTL_SET_SpeedControl disableInternet:%d disableNet:%d isDownLimit:%d`。

## 2. 安装/卸载（见 `OeNetLimitSetup_exe.md`）

- 安装：`OeNetLimitSetup.exe /Install`（或 `DriverInstall.exe /d4=OeNetLimit`）——
  1. 把 `OeNetLimit.sys` 拷到 `C:\Windows\System32\drivers\`；
  2. `CreateServiceA("OeNetLimit", …, SERVICE_KERNEL_DRIVER, …, "C:\Windows\System32\drivers\OeNetLimit.sys", "NetDDEGroup", …)`；
  3. 另建临时服务 `OeNetlimittmp`；装 NDIS/TDI/WFP 部件；
  4. `StartService`。
- 卸载：`DeleteService` + `SHDeleteKey(SYSTEM\CurrentControlSet\services\OeNetLimit[tmp])`。

## 3. 安装产物（客观）

安装器 `OeNetLimitSetup.exe` 把 `OeNetLimit.sys` 拷到 `C:\Windows\System32\drivers\` 并创建同名内核服务；卸载时 `DeleteService` + `SHDeleteKey(SYSTEM\CurrentControlSet\services\OeNetLimit[tpm])`。详见 `OeNetLimitSetup_exe.md`。

---

*本文为安装包内 x86 版 OeNetLimit.sys 的定位与差异说明；功能细节请见 `../OeNetLimit/OeNetLimit_sys.md`。*