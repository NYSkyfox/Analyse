# NetLimitInterface.dll（x64）组件说明

> 样本：`samples/os-easy/x64/NetLimitInterface.dll`（172544 字节，PE32+ DLL，`pei-x86-64`）
> 同源 x86：`samples/os-easy/x86/NetLimitInterface.dll`（已深度反编译，见 `../x86/NetLimitInterface_dll.md`）
> 工具：objdump + strings + Ghidra 指纹比对
> 说明：本样本**未独立跑 Ghidra 全量反编译**（服务器上无 x64 存档）；基于 PE 指纹 + 同源 x86 逻辑推断，**不含 x64 逐指令地址**。
> 关联：`OeNetlimit_dll.md`（下一层）、`../OeNetLimit_sys.md`（内核）、`../../DeviceControl_exe.md`（上层）
> 分析日期：2026-09-19（重组）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 172544 字节 |
| MD5 | `b843822afe478b94a221e42db9092cfa` |
| SHA-256 | `2544ab07f527ef658f99958420fde66a44f889af31a9d2e9afa4f5faa0565708` |
| 格式 | PE32+ DLL（`pei-x86-64`） |
| ImageBase | `0x180000000` |
| 入口点 | `0x180007ecc` |
| PDB | **已剥离**（`strings -el` 未检出 `.pdb` 串，x86 副本保留 PDB） |

---

## 1. 与 x86 副本的关系

| 维度 | 结论 |
|---|---|
| 架构 | x86 PE32 vs **x64 PE32+** |
| 大小 | 145408 vs **172544**（x64 更大，指针 8 字节 + 对齐） |
| MD5 | 不同（架构不同所致） |
| 功能 | **同源同版本**：6 个 `CNetLimitInstance` 导出（构造/析构/拷贝赋值/`GetNetSpeed`/`SetNetSpeed`/`SetWhiteRule`）与 x86 一致 |

> 判据：两副本同目录（`os-easy/x86| x64/`）配套部署、导出名相同、逻辑角色一致；差异仅目标架构。**功能逻辑以 x86 报告为准**（`../x86/NetLimitInterface_dll.md`），本文不重复其内容。

---

## 2. 功能概览（同源 x86）

- **`OeNetlimit.dll` 的 C++ 适配层**（源码目录 `limit_driver_interface`），本身不碰内核；
- 构造时 `SYS_GetModuleFileDir` + `LoadLibraryW(dir + "OeNetlimit.dll")` **延迟加载下一层**；
- 三个方法把语义化结构（`NET_SPEED` / `NET_LIMIT_INFO`）翻译成 `OeNetlimit.dll` 的 14 个底层 API：
  - `GetNetSpeed` → `GetSpeed` + `GetLimitSpeed`
  - `SetNetSpeed` → `SetSpeed(8B, byte, byte)`
  - `SetWhiteRule` → `SetWhiteIP` / `SetWhitePort` / `SetWhiteUrl` + 模式 `p[0]`（1=全断 / 2=断外网 / 3=放开，均保留 serverIp 放行）
- 上游为 `DeviceControl.exe`（回环 UDP 8454 收教师端指令）。

> 字段级转发逻辑、`NET_SPEED`/`NET_LIMIT_INFO` 布局、模式分派、日志格式、函数索引见 **x86 报告**（`../x86/NetLimitInterface_dll.md` §2–§6）。

---

## 3. 未决项

1. **x64 独立 Ghidra 反编译**：给出 x64 函数地址（`0x1800xxxxx` 段）、核对与 x86 逐函数逻辑一致性。
2. x64 剥离 PDB 后，若要符号级还原需另寻符号源。

---

*本文覆盖：NetLimitInterface.dll（x64）指纹、与 x86 同源关系判定、功能概览（引用 x86 报告）、未决项（x64 独立反编译）。*