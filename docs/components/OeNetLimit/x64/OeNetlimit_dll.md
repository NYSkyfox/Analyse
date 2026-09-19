# OeNetlimit.dll（x64）组件说明

> 样本：`samples/os-easy/x64/OeNetlimit.dll`（488592 字节，PE32+ DLL，`pei-x86-64`）
> 同源 x86：`samples/os-easy/x86/OeNetlimit.dll`（已深度反编译，见 `../x86/OeNetlimit_dll.md`）
> 工具：objdump + strings + Ghidra 指纹比对
> 说明：本样本**未独立跑 Ghidra 全量反编译**（服务器上无 x64 存档）；基于 PE 指纹 + 同源 x86 逻辑推断，**不含 x64 逐指令地址**。
> 关联：`../OeNetLimit_sys.md`（内核驱动）、`../x86/OeNetlimit_dll.md`（同源代码）、`../OeNetLimitSetup_exe.md`
> 分析日期：2026-09-19（重组）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 488592 字节 |
| MD5 | `fffd08262983178aab7a4f7277baf679` |
| SHA-256 | `39366c3ea5afa8108001c7bde40b5613ebb9c49ab01b402d69fc17edb99dd853` |
| 格式 | PE32+ DLL（`pei-x86-64`） |
| ImageBase | `0x180000000` |
| 入口点 | `0x18001666c` |
| PDB | **已剥离**（`strings -el` 未检出 `.pdb` 串，x86 副本保留 PDB） |

---

## 1. 与 x86 副本的关系

| 维度 | 结论 |
|---|---|
| 架构 | x86 PE32 vs **x64 PE32+** |
| 大小 | 372368 vs **488592**（x64 更大，指针 8 字节 + 对齐） |
| MD5 | 不同（架构不同所致） |
| 功能 | **同源同版本**：导出集、类结构（`CArpMgr`/`CNetInstall`）、设备通信、SpeedControl 语义与 x86 一致 |

> 判据：两副本同目录（`os-easy/x86| x64/`）配套部署、导出名相同、逻辑角色一致；差异仅目标架构。**功能逻辑以 x86 报告为准**（`../x86/OeNetlimit_dll.md`），本文不重复其内容。

---

## 2. 功能概览（同源 x86）

- **用户态网络管控库**，封装 14 个导出 API（`Enable/Disable`、`Get/Set`、`White/Black` × `IP/Port/Url` + `AntiArp`）；
- **`CArpMgr`**：经设备 `\\.\OeNetLimit` 读写 `SpeedControl`（IOCTL `0x122044`/`0x122048`，结构 `0xF534`）+ ARP 防攻击（网关 MAC 周期监控）；
- **`CNetInstall`**：`SetupCopyOEMInfW` 等 INF 安装/更新驱动 + 管理员校验；
- 上层被 `NetLimitInterface.dll`（`../x64/NetLimitInterface_dll.md`）的 `CNetLimitInstance` 转发调用。

> 详细 API 语义、SpeedControl 字段、CArpMgr 流程、函数索引见 **x86 报告**（`../x86/OeNetlimit_dll.md` §2–§10）。

---

## 3. 未决项

1. **x64 独立 Ghidra 反编译**：给出 x64 函数地址（`0x1800xxxxx` 段）、核对与 x86 逐函数逻辑一致性、确认 x64 是否引入额外逻辑。
2. x64 剥离 PDB 后，若要符号级还原需另寻符号源。

---

*本文覆盖：OeNetlimit.dll（x64）指纹、与 x86 同源关系判定、功能概览（引用 x86 报告）、未决项（x64 独立反编译）。*