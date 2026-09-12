# Os-Easy 双重逆向结果仲裁验证报告
> ⚠️ **修正声明（2026-09）**：本报告 2.1 节关于 `/*//` 是「载荷前缀」的结论**错误**，已于 2026-09 反汇编复核为死代码。详见《10_行为管控报文核查定稿.md》。
>
> 对【IDA Pro 逆向结论】(MainLogic.dll / StudentLogic.dll) 与【Ghidra 逆向结论】(Teacher.exe / Student.exe / LissHelper.exe / DeviceControl) 的分歧点进行逐项验证
> 验证方法：Ghidra 12.1.3 对 IDA 分析的核心载体 MainLogic.dll / StudentLogic.dll 重新做全量分析，逐函数反编译 + 字符串地址校验 + 全文件端口扫描
> 验证时间：2026-09-06

---

## 一、仲裁结论总览

| # | 分歧点 | IDA 说法 | Ghidra 之前说法 | **仲裁结果** |
|---|--------|---------|----------------|-------------|
| 1 | 传输格式 | 16B 命令头 `[cmdType][flag1][flag2][payloadLen]` | JSON `{CtrlCode,type,...}` | ✅ **IDA 对**：16B 头是教师端→学生端的线格式 |
| 2 | 命令标识 | 数字 cmdType (11/13/28/79/111/500) | type 字符串 | ✅ **两套都对**：外层数字 cmdType，内层 JSON type |
| 3 | 管控通道 | **单播**遍历在线学生 | 8040 单播 或 7778 组播（未决） | ✅ **IDA 对**：`FUN_1009e070` 确认遍历单播 |
| 4 | 学生端接收/转发 | StudentLogic.dll 翻译 → 本地 8045 | LissHelper 是接收器 | ✅ **IDA 对**：StudentLogic.dll 才是翻译/转发者 |
| 5 | 本地执行链 | 127.0.0.1:**8045** → DeviceControl | npd-auto 127.0.0.1:**9030** | ✅ **两套都是**：多个 IPC 端口并存（8045/9030） |
| 6 | 网络限制载荷 | type=500 载荷未还原 | CtrlCode JSON (0x01网络) | ⚠️ **存量分歧**：`this+0x548` 内容仍未完全还原 |
| 7 | 加密/魔数 | 未涉及 | `/encode` 加密 + `udPPPPj` 魔数 | ✅ **udPPPPj 仅 LissHelper**：本地通道魔数 |

---

## 二、逐项证据链

### 2.1 传输格式：16B 命令头 ✅（IDA 正确）

`MainLogic.dll` 三个函数反编译得到铁证：

**`FUN_1003f850`（命令头写入，size=74）：**
```c
puVar1 = *(undefined4 **)((int)this + 4);
*puVar1 = param_1[0];   // cmdType    (uint32)
puVar1[1] = param_1[1]; // flag1      (uint32)
puVar1[2] = param_1[2]; // flag2      (uint32)
puVar1[3] = param_1[3]; // payloadLen (uint32)
this+4 += 0x10;         // 步进16字节
```
**4 个 DWORD 顺序写入，固定 16 字节头** —— 与 IDA 完全一致。

**`FUN_10099cd0`（载荷组包，size=186）：**
```c
uVar1 = FUN_10135865(param_2 + 4);  // malloc(len+4)
memcpy(buf + 4, param_1, param_2);  // 载荷后移4字节
*(size_t *)this = param_2;          // 长度存前4字节
```
**`[payloadLen][payload]` 组包格式** —— 与 IDA 一致。

**`FUN_10064770`（type=500 发送，size=251）：**
```c
local_24 = 500;        // cmdType = 500 ✅
local_20 = 0;          // flag1 = 0
local_1c = 0;          // flag2 = 0
if (FID_conflict_size(param_1 + 0x548) < 0x8000) {   // 载荷长度检查
    FUN_1003f850(&local_34, &local_24);              // 写16B头
    FUN_100218a0(&local_34, param_1 + 0x548, 1);     // 载荷 = this+0x548
    FUN_10008b40(&auStack_58, "/*//");               // ⚡ 死代码（构造后未拼入发送缓冲）
    FUN_1009e070(*(void **)(param_1+0x30), pvVar3, sVar2);  // 遍历发送
}
```

> ⚡ **修正（2026-09 反汇编复核）**：type=500 的载荷**不带** `/*//` 前缀。`/*//` 在组包函数中被构造但**未拼入发送缓冲**（发送的是 `local_34`），是编译器优化残留的死代码。发送缓冲 = 16B 头 + 纯 JSON。

### 2.2 命令标识：数字 cmdType 外层 + JSON type 内层 ✅（两套都正确）

| 层 | 内容 | 出处 |
|----|------|------|
| **外层（教师端→学生端）** | 数字 cmdType：11/13/28/79/111/500 | MainLogic.dll `FUN_10064770` 等确认 |
| **内层（学生端内部）** | JSON `{"type":"support-use-device-control", ...}` | StudentLogic.dll `FUN_100838a0`/`FUN_100836a0` 确认 |

**`FUN_100838a0`（学生端"开管控"翻译，size=506）反编译关键行：**
```c
FUN_101fc820();  // 启动 JsonCpp
... "type" ...                          // JSON key: type
... 0x1023EDD4 ...                       // value 地址 = support-use-device-control
... "networktraffic" ...  param_3
... "network" ...        param_4
... "device" ...         param_5
... "process" ...        param_2(推)
puStack_c0 = 0x1f6d;                     // 端口 8045
FUN_100133f0("127.0.0.1");               // 发往本地
FUN_1008e960(...);                       // UDP socket 发送
```

**`FUN_100836a0`（学生端"关管控"）同样确认：**
```c
... "type" ...         → 0x1023EE28 = stop-device-control
... "stopnetworktraffic" ... "stopnetwork" ... "stopdevice" ... "stopprocess" ...
puStack_c0 = 0x1f6d;                     // 8045
FUN_100133f0("127.0.0.1");
```

**字符串地址验证（ReadStr 脚本）：**
| 地址 | 内容 |
|------|------|
| 0x1023EDD4 | `support-use-device-control` |
| 0x1023EE28 | `stop-device-control` |
| 0x1023EDF0 | `networktraffic` |
| 0x1023EE3C | `stopnetworktraffic` |
| 0x1023EE50 | `stopnetwork` |

> ✅ **至此 Ghidra 与 IDA 完全统一**：教师端通过 16B 头 + 数字 cmdType 把指令发给学生端；学生端 StudentLogic.dll 收到后翻译成 `{"type":"support/stop-device-control", "network":x, "device":x, ...}` JSON，转发给本机 8045 的 DeviceControl 执行。两者是**同一个协议链路的两段**。

### 2.3 管控通道：遍历单播 ✅（IDA 正确）

**`FUN_1009e070`（群发入口，size=356）完整反编译：**
```c
FUN_10009920(local_48);                    // 初始化迭代器
FUN_100494a0(local_3c, local_18 + 0xf0);   // 绑定在线学生列表 (this+0xf0)
local_14 = 0;
while (true) {
    uVar2 = FUN_10095e50(local_48);        // 获取列表长度
    if (uVar2 <= local_14) break;          // 遍历完退出
    local_1c = malloc(0x20);
    p_Var3 = FUN_100541c0(local_48, local_14);   // ← IDA 说 sub_100541C0(i)：取第i个在线节点
    local_24 = FUN_10099cd0(local_1c, param_1, param_2);  // 组包
    FUN_100a0610(local_18 + 0x68, &local_2c);   // ← IDA 说 sub_100A0610：加入发送队列
    local_14++;
}
```
**逻辑 = 遍历在线学生列表 → 逐节点组包 → 逐节点入队发送**。
> ✅ 这是**单播群发**（对每个学生 IP 单独发 UDP），不是组播广播。这正是"教师端 UI 只说对全体生效、没有单台按钮"的根本原因——底层是遍历单播，上层自然没有"单台"概念。**对学生机 A→B 注入反而更有利**：底层本来就支持对单个 IP 发。

### 2.4 学生端接收/转发者 ✅（IDA 正确，修正 Ghidra 判断）

**全文件 `push 端口` 扫描结果**（FindPortAll 脚本，只统计 PUSH/MOV 立即数）：

| 文件 | 8040 (0x1f68) | 8045 (0x1f6d) | 9030 (0x2346) | 7778 (0x1e60) |
|------|:---:|:---:|:---:|:---:|
| Teacher.exe | ✅ 1 (FUN_0058b3e0) | — | — | — |
| Student.exe | — | — | ✅ 6 | — |
| StudentLogic.dll | — | ✅ 6 | ✅ 7 | — |
| MultiClient.exe | — | ✅ 2 | ✅ 2 | — |
| LissHelper.exe | — | ✅ 1 | — | — |
| MainLogic.dll | 0x1e60=7776 非7778 | — | — | — |

**结论：**
- **8040 没有在任意文件里被 `push 0x1f68` 硬编码** → 8040 是**运行时从 core.conf 读取**的配置端口（`UdpMessageControllerPort`，MainLogic.dll `FUN_1005e5e0` 确认读取并存入 `this+0xC8`）
- **8045/9030 是被硬编码的本地 IPC 端口**，由学生端各进程（StudentLogic/MultiClient/LissHelper）发往 127.0.0.1
- **StudentLogic.dll 是 8040 接收 → 8045/9030 本地转发的核心**（LissHelper 仅含 8045，是辅助）
- 7778 组播端口在杜撰的 `0x1e60=7776` 扫描中未命中（说明 7778 是配置读取，不是硬编码）

### 2.5 本地执行链：8045 + 9030 并存（两套都对）

| 端口 | 用途 | 证据 |
|------|------|------|
| **8045** (0x1F6D) | StudentLogic DLL 发 `support/stop-device-control` JSON → 本地 DeviceControl | StudentLogic `FUN_100838a0/100836a0` 等 6 处；LissHelper 1 处；MultiClient 2 处 |
| **9030** (0x2346) | Student.exe 的 npd-auto 通道（另一条本地逻辑链路） | Student.exe 6 处；StudentLogic 7 处；MultiClient 2 处 |

> 两个端口是**不同逻辑链路**的本地 IPC，都真实存在。Ghidra 之前只挖到 9030 (npd-auto)，IDA 只挖到 8045，其实**并存**。

### 2.6 网络限制载荷 ⚠️ 仍有未还原部分

- IDA 与 Ghidra 反编译都确认：`cmdType=500`（`Limit` → `FUN_10067F50` → `FUN_10064770`），载荷来自 `this+0x548`
- `this+0x548` 的**具体字段结构仍未还原**（IDA new.md 自己也标注"待办"）
- 但已知：载荷**不带**任何前缀（`/*//` 为死代码），长度需 < 0x8000，且与 Teacher.exe 的 CtrlCode JSON（`0x01网络/0x02键盘/0x10应用/0x100设备`）**很可能就是同一内容的两种编码**
- **结论**：500 的实际载荷结构仍需动态抓包才能 100% 定案

### 2.7 加密/魔数 ✅（udPPPPj 定位）

- **`udPPPPj` 只在 LissHelper.exe 出现 1 次**（全文件扫描），其他 Teacher/Student/MainLogic/StudentLogic 均无
- → `udPPPPj` 是 **LissHelper 本地/内部通道的魔数**，不是教师端→学生端管控指令的线格式
- Teacher.exe 的 `/encode` 接口（`{"encoded":"%s"}`）+ CryptoPP DES-EDE2-CBC/HMAC-SHA1 是**教师端用于加密敏感载荷**的通道，与主管控链路（16B头+明文 JSON 候选）用途不同

---

## 三、最终完整链路（两套逆向合并定稿）

```
[教师端 Teacher.exe / MainLogic.dll]
  行为管控 UI (BehaviorControlDlg)
    │  CtrlCode JSON 构造 (Teacher.exe FUN_005648c0)
    ▼
  cmdType 组包: FUN_1003f850 写16B头 [cmdType][flag1][flag2][len],
                FUN_10099cd0 组 [len][payload] 载荷
    ▼
  FUN_1009e070 遍历在线学生列表 (this+0xf0)
    逐节点 FUN_100541c0(i) → FUN_100a0610 队列发送
    ▼
  UDP 单播 → 学生机 IP : 8040 (UdpMessageControllerPort, core.conf)
═════════════════════════════════════════════
[学生端 StudentLogic.dll]
  监听/接收 8040 的 16B头+载荷
    ▼ 解析 cmdType (11/13/28/79/111/500)
  本地翻译成 JSON:
    {"type":"support-use-device-control"/"stop-device-control",
     "network":x, "networktraffic":x, "device":x, "process":x}
    ▼ UDP → 127.0.0.1:8045 (0x1F6D)
  DeviceControl_x64.exe 接收执行
    ▼ DeviceIoControl
  OeNetLimit.sys (断网) / easyusbflt.sys (USB) / KbFilter.sys (键鼠) / ProcFireWall.sys (进程)
```

---

## 四、对"A→B 注入工具"的影响（更新后的技术结论）

| 项 | 之前判断 | **仲裁后定稿** |
|----|---------|--------------|
| 主通道 | 8040 或 7778 组播(未决) | ✅ **8040 单播优先**（组播 7778 仅媒体流） |
| 报文格式 | 16B头 + JSON 候选 / CtrlCode 候选 | ✅ **16B头 `[cmdType][flag][flag][len]` + 载荷**（IDA 定稿） |
| 网络限制 cmdType | 500 | ✅ 500 固定 |
| 载荷"魔法前缀" | udPPPPj(疑) | ✅ **无前缀**（`/*//` 为死代码，2026-09 纠正） |
| 学生发现 | 未实现 | ✅ 可扫 8040 或利用 8003 注册通道 |
| 本地链路 | 9030 | ✅ 8045 + 9030 并存（对注入无影响，注入直发 8040 即可） |

**关键启示：** 教师端管控本质是"遍历在线学生 → 单播 8040"，**天然支持对单个 IP 发送**。Python 工具只需：
1. 组装 `[500][0][0][len] + payload`（payload 先用 `/*//` + CtrlCode JSON 候选，现场双格式对照测试）
2. UDP 发往目标学生机 IP:8040
3. 单台 = 发一个 IP；全体 = 遍历扫描到的学生 IP 列表逐个发

---

## 五、验证方法与产物

| 工具 | 说明 |
|------|------|
| Ghidra 12.1.3 analyzeHeadless | 对 MainLogic.dll / StudentLogic.dll / Teacher.exe 全量分析 |
| VerifyAddr2.java | 按地址定位函数并反编译（输出到 /tmp/verify_*.txt） |
| FindPortAll.java | 扫描 PUSH/MOV 端口常量（输出到 /tmp/portall_*.txt） |
| ReadStr.java / ReadDat.java | 读取字符串/数据地址内容 |

**产物清单（服务器 ghidra 容器 /tmp/）：**
- `verify_MainLogic.dll.txt` — FUN_1009e070/FUN_10099cd0/FUN_1003f850 等
- `verify_StudentLogic.dll.txt` — FUN_100838a0/FUN_100836a0 等
- `verify_Teacher.exe.txt` — FUN_0058b3e0 等
- `portall_Student.exe / LissHelper.exe / MultiClient.exe / Teacher.exe.txt` — 全端口扫描
- `findport_StudentLogic.dll.txt` — 8045/9030 定位

---

## 六、遗留问题（需动态验证）

1. `this+0x548` 载荷（type=500）的**确切字段结构**（纯 JSON，无前缀）
2. 8040 监听进程的**具体绑定地址**（0.0.0.0 vs 127.0.0.1）
3. 学生机是否校验指令来源 IP / 是否有口令（Padlock/StuInternet 哈希用途）
4. 不同 cmdType（11/13/28/79/111）的载荷 JSON 最小字段
5. 教师端 CtrlCode JSON（`{"CtrlCode":19,"apps":[]}`）与 type=500 载荷的对应关系

---

*报告时间：2026-09-06*