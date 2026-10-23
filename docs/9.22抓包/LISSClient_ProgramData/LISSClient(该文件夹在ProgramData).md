# LISSClient(该文件夹在ProgramData) · 分析报告

> 文件夹说明（用户）：该文件夹位于学生机 `C:\ProgramData\LISSClient`。
> 内含 2 个文件：`sslkey.log`、`logs/LISSNetSnifferLog.txt`。

## 一、样本信息（实测）

| 文件 | 大小 | MD5 | SHA-256 |
|---|---|---|---|
| `sslkey.log` | 418,141 B | `a0bd66d648bd486e9a196147382e8732` | `24a4955d8cc755906ceba20db1c8dcd63f1a8aaf9717cefd8f9e650ca7e45962` |
| `logs/LISSNetSnifferLog.txt` | 30,010 B | `dc3d2c3fd53af5c18ef491d6514a3d71` | `b7130786146d3e954e6fa34d2bcc324f07f97c1e0c9972eab392bb16b55f458e` |

## 二、组件定性：学生端常驻"本地流量嗅探 + HTTPS 解密 + 关键词审查"器

### 2.1 宿主进程（日志实测）
```
C:\Program Files (x86)\Os-Easy\os-easy multicast teaching system\x86\LISSNetInfoSniffer.exe
```
- 启动参数格式（日志 argv 实测）：`LISSNetInfoSniffer.exe  <本机IP> <本机MAC> [keywords.json路径]`
  - 例：`argv[1]=192.168.1.57  argv[2]=EC:D6:8A:F6:E9:F2  argv[3]=`（9.22 当日 16:54:26、16:56:24、16:56:38 三次启动）
  - 2024-12-09 记录带第 4 参：`...x64\keywords.json` → 触发 `TlsStreamDecryption::SetMMCNetKeywordFilePath mmc handle: 131550, keywords count: 1`
- 监听网卡：`Start to monitor adapter: {04B3C6ED-0560-4E0D-A627-FEACCEF7DB37}` —— **与本批次 pcapng 物理段接口 GUID 完全一致**（= 抓包所在学生机 `.57` 的网卡）；
- 日志路径：`C:\ProgramData\LISSClient\logs\LISSNetSnifferLog.txt`（滚动追加，2024-06 至 2026-09 跨 27 个月）。

### 2.2 sslkey.log = TLS 1.3 NSS 密钥日志（格式实测）
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 063e9a7ea19c081137a6961577942542ee337ef657848edd938e2e725a3013b5 1f0d3307...
SERVER_HANDSHAKE_TRAFFIC_SECRET 063e9a7ea19c081137a6961577942542ee337ef657848edd938e2e725a3013b5 08a45fa2...
```
- 标准 **NSS Key Log Format**（Wireshark `SSLKEYLOGFILE` 可识别）：DHE/ECDHE 会话密钥 + 每向 traffic secret（SHA-256 派生）；
- 该文件由 `LISSNetInfoSniffer` 在每次启动时写入（日志 `sslkeyfile: C:\ProgramData\LISSClient\sslkey.log`），供**本机进程直接读取 TLS 会话密钥** → 无需 MITM 即可**解密学生机自身发起的 HTTPS 流量**；
- 418 KB 规模 = 大量历史会话密钥累积（跨 27 个月）。

### 2.3 审查行为（日志实测样本）
日志按"进程 pid + URL + HTTP 状态 + 完整 query 串"逐条记录学生机浏览行为，含：
- 搜狗输入法更新/卸载引导、腾讯文档、百度搜索（逐字符输入的 search suggest 全过程：`sh→sho→shou→…→手心输入法`）、WPS 活动页、手心输入法安装器（`PalmInput_Win 2.7.0.1700`）等；
- 处理动作分类：`masking data for 200 and title is empty:`（200 且无标题→打码记录）、`masking data except for 200 and 302:`（非 200/302 保留）、`404 Not Found`/`502`/`ACCESS DENIED` 原始记录；
- 2024-12-09 起出现 **`TlsStreamDecryption` + `keywords` 关键词匹配管线**（"keywords count: 1"）→ 对解密后的 TLS 明文做关键词命中。

### 2.4 与 8045/9030/9122 的组件关系（联合证据）
| 证据 | 来源 | 指向 |
|---|---|---|
| 8045 IPC `{"ip":"192.168.1.57","mac":"EC:D6:8A:F6:E9:F2","type":"start-lissNet"}` | 抓包1 回环（9.22） | **主控经 8045 总线启动 LISSNet 嗅探**（参数=本机 IP/MAC，与 sniffer argv 完全一致） |
| 8045 IPC `{"type":"check-liss-sdk"}` → `failed` | 抓包1 回环（9.22，6 次） | 周期自检 LISS SDK，恒失败（未决项 3） |
| 9122 流量查询 API（JSON 分页，含 `frameNumber/srcMac/belongSessionId` 等抓包字段） | 9.20 抓包（实测） | **9122 的查询内容 = 该 sniffer 抓到的本机流量** → 9122 宿主 = LISSNetInfoSniffer（强推断，本批 9122 零帧未复测） |
| `LISSNetSnifferLog` 中 `monitor adapter` GUID = 抓包网卡 GUID | 9.22 日志 + pcapng | 同一组件同一网卡，身份闭环 |

## 三、启动历史（日志全量提取，关键节点）
| 时间（本机） | 学生 IP | MAC | 备注 |
|---|---|---|---|
| 2024-06-30 12:40/12:45 | 192.168.1.32 | EC:D6:8A:F6:E8:5A | 早期部署 |
| 2024-10-09 19:40/19:48 | 192.168.1.64 | EC:D6:8A:F6:E8:C0 | |
| 2024-12-09 17:39 | 192.168.2.238 | FA:16:3E:A4:88:06 | **首次带 keywords.json**（`TlsStreamDecryption` 出现） |
| 2024-12-27 多次 | 192.168.2.238 | FA:16:3E:A4:88:06 | |
| 2025-02-13 15:33 | 192.168.2.238 | FA:16:3E:A4:88:06 | |
| 2026-01-04 09:09 | 192.168.2.238 | FA:16:3E:60:52:4A | |
| 2026-01-04 09:51 / 2026-01-16 14:46 | 192.168.3.177 | FA:16:3E:D0:94:16 | |
| **2026-09-22 16:54:26 / 16:56:24 / 16:56:38** | **192.168.1.57** | **EC:D6:8A:F6:E9:F2** | **本批次抓包所在机，三次重启 sniffer**（与抓包1 8045 `start-lissNet` 时刻对应） |

> 同一物理机（同 MAC 前 5 位 `EC:D6:8A:F6`）跨机房/跨 IP 复用：.32 → .64 → .238 → .177 → .57，符合"学生机固定资产、IP 按机房分配"的机房管理模式。

## 四、安全含义
1. **学生端内置 HTTPS 解密 + 关键词审查器**，密钥落盘于 `ProgramData\LISSClient\sslkey.log`（**任何本地用户可读**，ProgramData 默认 Everyone 可读）；
2. 审查粒度到**搜索框逐字符**（suggest 请求全记录），可还原完整搜索行为；
3. 该组件独立于教师端存在（本地 8045 IPC 启动），**教师端断开后仍持续工作**；
4. 关键词库 `keywords.json` 由教师端 x64 目录下发（`os-easy multicast teaching system\x64\keywords.json`），内容本批未提供（未决：关键词清单）。

## 五、未决
1. `check-liss-sdk` 恒 `failed` 的分支语义（需 Ghidra `LISSNetInfoSniffer` 字符串定位）；
2. sslkey.log 密钥与具体 TLS 会话的绑定（可用 Wireshark 加载该文件解密 9.22 出网 443 流量复验）；
3. `keywords count: 1` 的关键词内容；
4. 9122 API 与 sniffer 数据面的直接调用关系（9.20 定性，待代码层闭环）。

---
*分析日期 2026-09-22 · 文件哈希/内容全实测*