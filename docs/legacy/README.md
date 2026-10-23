# legacy · 历史分析（已被取代，仅作溯源用）

> ⚠️ **这里的内容不作为结论依据**。当前有效结论统一在
> [`../reverse-analysis/`](../reverse-analysis/00_总览与系统架构.md)。
> 保留本目录的唯一目的：追溯"某个结论什么时候、基于什么证据被修正过"。

## 目录

| 目录 | 时间 | 状态 | 说明 |
|---|---|---|---|
| `reverse-reports/` | 2026-09 上旬 | **部分结论已修正** | 12 篇英文命名专题报告（IDA/Ghidra 仲裁、管控协议、注入研究等），是 `reverse-analysis/` 的前身 |
| `early-notes/` | 2026-08 | **基本过时** | 早期 strings/静态分析笔记与流程图，未做字节级验证 |

## 新旧对应（被取代的结论去哪看）

| 旧文档 | 现在看这里 |
|---|---|
| `reverse-reports/CONTROL_COMMAND_PROTOCOL_REPORT.md` | [02_行为管控指令](../reverse-analysis/02_行为管控指令.md)、[23_管控通道纠错实证](../reverse-analysis/23_20260920_管控通道纠错实证.md) |
| `reverse-reports/ARBITRATION_VERIFICATION_REPORT.md` | [08_核查说明](../reverse-analysis/08_核查说明.md)、[09_端口与配置总览](../reverse-analysis/09_端口与配置总览.md) |
| `reverse-reports/CRASH_FUNCTION_REVERSE_REPORT.md` | [25_教师端崩溃与假卡死机理](../reverse-analysis/25_教师端崩溃与假卡死机理.md)（§十二 逐条核对） |
| `reverse-reports/REMOTECOMMAND_REVERSE_REPORT.md` | [04_远程命令执行](../reverse-analysis/04_远程命令执行.md) |
| `reverse-reports/DEVICECONTROL_ANALYSIS_REPORT.md` | [06_DeviceControl设备管控](../reverse-analysis/06_DeviceControl设备管控.md) |
| `reverse-reports/NET_LIMIT_PAYLOAD_RESEARCH.md` | [02_行为管控指令](../reverse-analysis/02_行为管控指令.md) |
| `reverse-reports/STUDENT_TO_STUDENT_CONTROL_FEASIBILITY.md` | [docs/9.22抓包/总览与结论](../9.22抓包/总览与结论.md)（抓包3 实测） |
| `early-notes/Report.md` / `Os-Easy Report.md` | `reverse-analysis/` 各功能篇 + [docs/components/](../components/) |
| `early-notes/new.md` | [16_9003通道报文结构](../reverse-analysis/16_9003通道报文结构.md) |

## 使用建议

1. 只在两种情况下进来：① 想确认"这条结论以前是怎么写的"；② 需要旧报告里的原始截图/函数清单。
2. 任何与 `reverse-analysis/` 冲突的表述，**一律以 `reverse-analysis/` 为准**。
3. 引用本目录内容时请注明「历史结论，已被 X 号文档取代」。
