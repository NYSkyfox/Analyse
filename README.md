# Os-Easy 多播教学系统 · 逆向分析资料库

> 目标样本：Os-Easy 多播教学系统 V10.9.1.5145（x86 PE）
> 工具链：Ghidra 12.1.3 + objdump + IDA + tshark/Wireshark
> 本仓库只做**安全研究与授权环境验证**。

---

## 📁 目录结构（2026-10 整理后）

```
Analyse/
├── README.md                      ← 本文件：总入口
├── docs/
│   ├── reverse-analysis/          # ⭐ 唯一有效结论区（编号 00-31，按主题组织）
│   ├── components/                # 组件级档案（25 个 PE/DLL/SYS 逐个说明）
│   ├── 9.22抓包/                   # 一次完整现场抓包的分报告（抓包1 / 抓包3 + 总览）
│   ├── toolkit/                   # PoC 工具使用文档（CLI/GUI/部署/Ghidra 容器）
│   ├── assets/                    # 流程图、GUI 截图
│   └── legacy/                    # ⚠️ 历史报告（已被取代，仅溯源）
│       ├── reverse-reports/       #   12 篇英文命名专题（2026-09 上旬）
│       └── early-notes/           #   早期 strings 分析（2026-08）
├── analysis/                      # 分析产物：Ghidra 脚本、IDA 导出、函数提取
├── evidence/                      # 原始证据：反编译片段、现场抓包日志
└── tools/                         # 抓包/验证脚本 + OsEasy-ToolKit-dev（PoC）
```

**阅读规则**：结论只认 `docs/reverse-analysis/`。`docs/legacy/` 里任何与它冲突的表述一律作废，
新旧对应表见 [`docs/legacy/README.md`](docs/legacy/README.md)。

---

## 📚 推荐阅读顺序

| 顺序 | 文档 | 用途 |
|---|---|---|
| 1 | [`docs/reverse-analysis/00_总览与系统架构.md`](docs/reverse-analysis/00_总览与系统架构.md) | 全局：组件、驱动、报告索引 |
| 2 | [`09_端口与配置总览`](docs/reverse-analysis/09_端口与配置总览.md) | 端口—阶段矩阵，先搞清"谁在哪个端口说话" |
| 3 | [`16_9003通道报文结构`](docs/reverse-analysis/16_9003通道报文结构.md) | 9003 帧格式（4B 前缀 + 16B 头）与 cmdType 全集 |
| 4 | [`26_协议实现规格`](docs/reverse-analysis/26_协议实现规格.md) | 要写伪端/互操作时看这本（含 IDL、状态机、测试向量） |
| 5 | [`31_学生端屏幕预览链路`](docs/reverse-analysis/31_学生端屏幕预览链路.md) | 0x2B 缩略图（64×64 / 5s），区别于屏幕广播 |
| 6 | [`25_教师端崩溃与假卡死机理`](docs/reverse-analysis/25_教师端崩溃与假卡死机理.md) | 拆帧状态机与崩溃点（排障必看） |

工程实现向：另见工作区根目录 [`PROTOCOL_DEV_GUIDE.md`](../PROTOCOL_DEV_GUIDE.md)（可直接照写伪教师端/伪学生端）。

---

## 🎯 当前有效结论（摘要）

### 9003 主连接（学生 → 教师，TCP）

```
线上字节 = [4B total_len][4B cmdType][4B u3][4B u4][4B body_len][payload]
total_len = 16 + body_len        // 不含自身 4 字节
```

- 学生用临时端口 **connect** 教师 9003；教师 LISTEN
- 无鉴权、无加密、无 CRC、无版本协商
- 心跳 `0x59`：教师每 **5.00 s** 发一次，20 字节空载（u3=0x40）
- 屏幕预览 `0x2B`：学生每 **5 s** 发一张 **64×64 JPEG**（q≈40，约 1.2 KB）

### 管控指令

- 9.20 抓包**实证走 9003**（早期"UDP 8040 单播"结论已被修正，8040 至今零流量）
- 行为管控外层 cmdType `500`，载荷 JSON `{"CtrlCode":int, ...}`，`CtrlCode` 带 `0xBC` 高位标志
- 黑屏肃静 `0x0C`、远程命令 `0x0D`（学生回执 `"1"`）、环境配置 `0x2D`

### 发现与媒体

| 端口 | 协议 | 用途 |
|---|---|---|
| 7777 | UDP 广播 | 教师身份 `teacherip` JSON（channel 幂次 + checksum），3 s/次 |
| 7771 | UDP 组播 | 频道心跳 `teacher`，`229.9.<网段>.<主机>` |
| 7778 | UDP 组播 | **屏幕广播**（JPEG 或 H.264），`229.1.<网段>.<主机>` |
| 9030 / 8045 | 本地 IPC | MainLogic 总线 / LISS SDK，JSON-over-UDP |

---

## ⚠️ 重要提醒

1. **证据分级**：机器码/反编译（事实）> 现场抓包 > 自制工具构造包。
2. `evidence/captured-logs/` 中的 8040 测试包是**按早期错误结论构造**的，只能证明链路可达，**不能**当格式证据。
3. `docs/legacy/` 下报告成文较早，仅作溯源，不作为结论。
4. 仅供授权测试与教学研究使用。