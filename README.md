# Os-Easy 多播教学系统 · 逆向分析资料库

> 对 **Os-Easy 多播教学系统 V10.9.1.5145** 的完整逆向分析资料、证据与 PoC 工具。
> 分析工具：Ghidra 12.1.3 + IDA Pro + Wireshark（抓包）

---

## 📁 目录结构

```
Analyse/
├── docs/                          # 📄 文档
│   ├── reverse/                   #   逆向分析报告（按主题）
│   │   ├── CONTROL_COMMAND_PROTOCOL_REPORT.md   管控指令协议
│   │   ├── NET_LIMIT_PAYLOAD_RESEARCH.md        网络限制载荷
│   │   ├── REMOTECOMMAND_REVERSE_REPORT.md      远程命令
│   │   ├── DEVICECONTROL_ANALYSIS_REPORT.md     设备管控
│   │   ├── MULTICLIENT_ANALYSIS_REPORT.md       多客户端
│   │   ├── ARBITRATION_VERIFICATION_REPORT.md   Ghidra/IDA 仲裁
│   │   ├── CONTROL_INJECTION_RESEARCH.md        注入研究
│   │   ├── STUDENT_TO_STUDENT_CONTROL_FEASIBILITY.md  学生机互控
│   │   ├── CRASH_FUNCTION_REVERSE_REPORT.md     崩溃函数分析
│   │   ├── OS-EASY_ANALYSIS_REPORT.md           总体分析
│   │   ├── PROJECT_SUMMARY.md                   项目总结
│   │   └── DEPLOYMENT_SUMMARY.md                部署摘要
│   ├── 逆向分析报告/              #   ★ 本轮系统化报告（00-10，推荐先看）
│   │   ├── 00_总览与系统架构.md
│   │   ├── 01_通信机制.md
│   │   ├── 02_行为管控.md
│   │   ├── 03_屏幕广播.md
│   │   ├── 04_远程Cmd命令.md
│   │   ├── 05_远程关机重启.md
│   │   ├── 06_DeviceControl设备管控.md
│   │   ├── 07_建议点深挖.md
│   │   ├── 08_核查说明.md
│   │   ├── 09_管控指令协议定稿.md
│   │   └── 10_行为管控报文核查定稿.md           ★ 报文定稿（抓包实证）
│   ├── toolkit/                   #   工具文档（CLI/GUI/PAGES/容器指南）
│   └── assets/                    #   流程图/截图
│
├── analysis/                      # 🔬 分析产物
│   ├── ghidra-scripts/            #   Ghidra Java 脚本
│   ├── ida-output/                #   IDA 导出（ida_out / ida_out_stu）
│   └── extract_functions.py       #   函数提取脚本
│
├── evidence/                      # 🔍 原始证据
│   ├── arbitration/               #   反编译产物（verify_*.txt / portall_*.txt）
│   └── captured-logs/            #   ★ 真实抓包日志 + 分析报告
│
├── reports/                       # 📊 历史报告
│   ├── OsEasyPOC_ANALYSIS.md
│   └── toolkit-analysis/          #   Report.md / Os-Easy Report.md / 流程图
│
└── tools/                         # 🛠 工具
    └── OsEasy-ToolKit-dev/        #   管控指令模拟 PoC（Python）
```

---

## 🎯 核心结论速览

### 管控指令报文（教师端 → 学生端）

```
[cmdType:u32][flag1:u32][flag2:u32][payloadLen:u32] + "/*//" + JSON
     500          0          0           90
```

- **传输**：UDP 单播 → 学生机 `:8040`（`UdpMessageControllerPort`）
- **载荷**：`/*//` + `{"CtrlCode":<int>, "apps":[], "cites":[], "keys":[], "sendState":1, "tipInfo":"", "serverIp":""}`
- **实证**：`evidence/captured-logs/` 真实抓包（106 字节报文，payloadLen=90=4+86）

### CtrlCode 位标志

| 值 | 管控 |
|---|---|
| `0x01` | 禁用网络 |
| `0x02` | 键盘过滤 |
| `0x10` | 禁用应用 |
| `0x100` / `0x1000` / `0x10000` | 禁 USB（3 变体） |
| `-0x44000000` | 停止全部管控 |

### 关键端口（`skin/core.conf`）

| 端口 | 用途 |
|---|---|
| **8040** | 管控指令 UDP（`UdpMessageControllerPort`） |
| 8045 | 学生端本地 IPC → DeviceControl |
| 9030 | `npd-auto` 通道 |
| 7777 | 频道扫描（教师广播） |
| 7778 | 组播 |

### 安全要点

- `core.conf` 的 `/IpAddressFilter//` 为**空** → 无来源 IP 校验
- 管控走 **UDP 明文**（16B 头 + `/*//` + JSON）

---

## ⚠️ 重要提醒

1. **抓包实证 > 反编译推断**：本仓库的报文格式结论以 `evidence/captured-logs/` 的真实抓包为准。
2. **历史报告可能存在过时结论**：`docs/reverse/` 下部分报告成文较早，与 `docs/逆向分析报告/10_*.md` 冲突时**以 10 号定稿为准**。
3. 仅供**安全研究与授权测试**使用。

---

## 📌 推荐阅读顺序

1. `docs/逆向分析报告/00_总览与系统架构.md` — 建立整体认知
2. `docs/逆向分析报告/10_行为管控报文核查定稿.md` — 报文格式（工具开发必读）
3. `docs/逆向分析报告/09_管控指令协议定稿.md` — 端口/协议全景
4. `docs/reverse/ARBITRATION_VERIFICATION_REPORT.md` — Ghidra/IDA 仲裁方法与结论
