# netsf.inf / netsf_m.inf 组件说明（OeNetLimit 的 NDIS 过滤 INF）

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/netsf.inf`、`$_12_/netsf_m.inf`
> 样本：`netsf.inf` 3520 字节、`netsf_m.inf` 1712 字节
> 使用者：`OeNetLimitSetup.exe`（`SetupCopyOEMInfW` 装入驱动库，并拷到 `%Windir%\inf`）

---

## 0. 内容（`netsf.inf` 实证）

```ini
[Version]
Signature  = "$Windows NT$"
Class      = NetService
ClassGUID  = {4D36E974-E325-11CE-BFC1-08002BE10318}
Provider   = %Msft%
DriverVer  = 10/01/2002, 6.0.5019.0
CatalogFile.nt = oenetlimit.cat

[Manufacturer]
%Msft% = MSFT,NTx86,NTia64,NTamd64
[MSFT] / [MSFT.NTx86] / [MSFT.NTia64] / [MSFT.NTamd64]
%OeNetLimit_Desc% = OeNetLimit.ndi, ms_OeNetLimit

[OeNetLimit.ndi]
AddReg          = OeNetLimit.ndi.AddReg, OeNetLimit.AddReg
Characteristics = 0x4418   ; NCF_FILTER | NCF_NDIS_PROTOCOL
CopyFiles       = OeNetLimit.Files.Sys
CopyInf         = netsf_m.inf

[OeNetLimit.ndi.Services]
AddService = OeNetLimit,, OeNetLimit.AddService
[OeNetLimit.AddService]
DisplayName = %OeNetLimitService_Desc%
ServiceType = 1   ; SERVICE_KERNEL_DRIVER
StartType   = 3   ; SERVICE_DEMAND_START
```

- 这是把 `OeNetLimit.sys` 安装为 **NDIS 过滤（NetService）** 的 INF；`netsf.inf` 是主 INF，`netsf_m.inf` 为配套（`CopyInf`），名称沿用经典 NDIS 过滤示例 `netsf`。
- 与 `OeNetLimit.inf`（同为 NetService，ClassGUID 相同）互为配套/变体；`OeNetLimitSetup.exe` 会把这两个 INF 拷到 `%Windir%\inf\` 并调用 `SetupCopyOEMInfW` 完成驱动库注册。
- `CatalogFile.nt = oenetlimit.cat` 对应安装包内的 `oenetlimitx86.cat` / `oenetlimitx64.cat`。

## 1. 作用

- 让 OeNetLimit 同时具备 **NDIS 过滤** 形态（配合其内建的 **WFP callout** 一起实现网络限制）。
- 与 `OeNetLimit.inf` 内容一致（`Class=NetService`、`Ndi.Service="OeNetLimit"`、`FilterMediaTypes="ethernet"`），二者同为该驱动的 **NDIS 过滤**安装 INF。

---

*本文：netsf.inf/netsf_m.inf 为 OeNetLimit 的 NDIS 过滤 INF 对，说明其服务类型与安装路径。*