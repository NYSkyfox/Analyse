# OeNetLimit.inf 组件说明（NDIS LWF 安装描述）

> 样本：`samples/os-easy/OeNetLimit.inf`（2617 字节，纯文本 INF）
> 配套：`OeNetLimit.sys`（驱动本体）、`oenetlimitx64.cat`（签名目录）、`OeNetLimitSetup.exe`（安装器）
> 说明：INF 为安装/部署描述文件（非 PE 程序），本文按节逐行解读其安装语义。
> 分析日期：2026-09-19（重组）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/OeNetLimit.inf` |
| 大小 | 2617 字节 |
| 类型 | 纯文本 INF（NDIS LWF 安装描述） |
| MD5 | `e347f9adf68d9a340ed068f14392b04a` |
| SHA-256 | `30c3ffe0c11d3a8ef634be6f15d30bf7de1fc24c4cc8f63f8b32260ef6505464` |
| 配套 | `OeNetLimit.sys` / `oenetlimitx64.cat` / `OeNetLimitSetup.exe` |

## 1. 文件性质

Windows **INF 安装描述脚本**，供 `OeNetLimitSetup.exe`（或 NetCfg/SetupAPI）解析后完成"NDIS 轻量过滤器网络服务 + 内核驱动服务"的注册。**无执行逻辑**，仅声明"装什么、装到哪、建什么键"。

---

## 2. 逐节解析

### `[version]`
| 键 | 值 | 含义 |
|---|---|---|
| `Class` | `NetService` | 网络服务类 |
| `ClassGUID` | `{4D36E974-E325-11CE-BFC1-08002BE10318}` | 标准 **NetService** 类 GUID |
| `Provider` | `%Msft%` → `OeNetLimit` | 供应商标题（借 MSFT 占位，实为 OeNetLimit） |
| `DriverVer` | `04/21/2009` | 驱动日期（WFP/NDIS 示例默认日期） |
| `CatalogFile.ntx86` | `OeNetLimitX86.cat` | x86 签名目录 |
| `CatalogFile.ntamd64` | `OeNetLimitX64.cat` | x64 签名目录（随包 `oenetlimitx64.cat`） |

### `[Manufacturer]` / `[MSFT]`
`%Msft%=MSFT,NTx86,NTia64,NTamd64` → 四种系统架构下都用 `[MSFT]` 段，安装同一设备 `Install, OeNetLimit`。

### `[Install]`（核心：NDI 声明）
| 键 | 值 | 含义 |
|---|---|---|
| `AddReg` | `Inst_Ndi` | 执行 NDI 注册 |
| `Characteristics` | `0x40008` | NDIS 过滤驱动特征位 |
| `NetCfgInstanceId` | `{00007D53-7B62-04BF-5AC1-62E24E55183F}` | NetCfg 实例 GUID |
| `Copyfiles` | `OeNetLimit.copyfiles.sys` | 拷贝驱动文件段 |

### `[SourceDisksNames]` / `[SourceDisksFiles]` / `[DestinationDirs]`
- 介质 `1` = 本目录；`OeNetLimit.sys=1`（源盘文件）；
- `DefaultDestDir=12`（`%12%` = `System32\drivers`）；`OeNetLimit.sys` 拷到 `12` 并带标志 `2`（只在新安装/升级时覆盖）。

### `[Inst_Ndi]`（NDIS 轻量过滤器声明）
```
HKR, Ndi,Service,,                "OeNetLimit"      ; 服务名
HKR, Ndi,CoServices,0x00010000,   "OeNetLimit"
HKR, Ndi,HelpText,,               %OeNetLimit_HelpText%
HKR, Ndi,FilterClass,,            compression       ; 过滤类别
HKR, Ndi,FilterType,0x00010001,   0x00000002        ; 过滤类型
HKR, Ndi\Interfaces,UpperRange,,  "noupper"         ; 无上层
HKR, Ndi\Interfaces,LowerRange,,  "nolower"         ; 无下层
HKR, Ndi\Interfaces,FilterMediaTypes,, "ethernet"   ; 以太网
HKR, Ndi,FilterRunType,0x00010001, 1                ; 过滤器运行类型
```
→ 声明本驱动以 **NDIS 轻量过滤器（LWF）** 挂在以太网协议栈上。

### `[Install.Services]` / `[OeNetLimit_Service_Inst]`
```
AddService = OeNetLimit, , OeNetLimit_Service_Inst
DisplayName   = OeNetLimit
ServiceType   = 1          ; SERVICE_KERNEL_DRIVER
StartType     = 1          ; SERVICE_SYSTEM_START
ErrorControl  = 1          ; SERVICE_ERROR_NORMAL
ServiceBinary = %12%\OeNetLimit.sys
LoadOrderGroup = NDIS
AddReg        = Common.Params.reg
```
→ 注册**内核驱动服务**，`%12%\OeNetLimit.sys` = `System32\drivers\OeNetLimit.sys`，加载组 `NDIS`。

### `[Install.Remove.Services]`
`DelService=OeNetLimit,0x200` → 卸载时删除服务。

### `[Common.Params.reg]`
```
HKR, FilterDriverParams\DriverParam,   ParamDesc,, "Driverparam for lwf"
HKR, FilterDriverParams\DriverParam,   default,,   "5"
HKR, FilterDriverParams\DriverParam,   type,,      "int"
HKR, FilterAdapterParams\AdapterParam, ParamDesc,, "Adapterparam for lwf"
HKR, FilterAdapterParams\AdapterParam, default,,   "10"
HKR, FilterAdapterParams\AdapterParam, type,,      "int"
```
→ NDIS LWF 的 `FilterDriverParams` / `FilterAdapterParams` 参数（默认 5 / 10）。

### `[Strings]`
`Msft = "OeNetLimit"`、`OeNetLimit_Desc = "OeNetLimit"`、`OeNetLimit_HelpText = "OeNetLimit"` —— 显示名全部自指。

---

## 3. 关键结论

1. **双重身份**：同一 `OeNetLimit.sys` 既以 **NDIS LWF**（`[Inst_Ndi]`）又以**内核驱动服务**（`[Install.Services]`）注册——这正是驱动内同时导入 `NDIS.SYS` 与 `fwpkclnt.sys` 的原因（见 `OeNetLimit_sys.md` §5 WFP、§2 安装形态）。
2. **借壳**：`Provider=%Msft%`、`DriverVer=04/21/2009`、`ClassGUID` 用标准 NetService——沿用微软 WFP/NDIS 示例模板，仅把设备名/服务名替换为 `OeNetLimit`。
3. **部署路径**：`System32\drivers\OeNetLimit.sys`，签名走 `oenetlimitx64.cat`（x64 运行版只带 x64 cat）。
4. **参数**：LWF 的 driver/adapter 参数默认 5/10，供 NDIS 栈调优，非核心管控逻辑。

---

## 4. 与其它文件的关系

| 文件 | 关系 |
|---|---|
| `OeNetLimit.sys` | 本 INF 部署的驱动本体（见 `OeNetLimit_sys.md`） |
| `OeNetLimitSetup.exe` | 解析本 INF 完成安装（见 `OeNetLimitSetup_exe.md`） |
| `oenetlimitx64.cat` | 本 INF `CatalogFile.ntamd64` 引用的签名目录 |

---

*本文覆盖：OeNetLimit.inf 逐节解析（version/Install/Inst_Ndi/Services/Remove/Params/Strings）、NDIS LWF 与内核服务双重注册语义、部署路径与签名引用、与 sys/setup/cat 的关系。*