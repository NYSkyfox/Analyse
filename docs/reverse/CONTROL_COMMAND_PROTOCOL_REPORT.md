# Os-Easy 教师端 → 学生端 管控指令协议分析报告

## 🎯 分析目标

还原教师端（Teacher.exe）向学生端（Student.exe）发送的**行为管控指令**内容（JSON 格式）及学生端的执行逻辑。

**分析对象**：
- Teacher.exe（发送端/控制端）
- Student.exe（接收端/执行端）
- DeviceControl.exe（策略执行组件）
- NPDControl.xml / NPDControl.json / keywords.json（配置模板）

---

## 📦 协议载体与传输链路

### 1. 管控配置模板：NPDControl.json

Teacher.exe 通过 `FUN_0043fe30` / `FUN_0042c7c0` 加载 **`NPDControl.json`**（用 JsonCpp 解析），UI 界面定义在 `skin/NPDControl.xml`（800×680 窗口）。

**UI 结构（4 个管控页签）**：

```
┌─ NPDControl 行为管控窗口 ─────────────────────┐
│ option0: PControl (进程/应用管控)              │
│   ├─ 复选框 PControl (总开关)                  │
│   ├─ p-model 下拉: 1=进程名 0=可执行文件       │
│   ├─ app-name / exec-name 输入框               │
│   ├─ PList 规则列表 (app/exec/type)            │
│   ├─ p-black (黑名单) / p-white (白名单) 单选   │
│                                               │
│ option1: NControl (网络管控)                   │
│   ├─ 复选框 NControl (总开关)                  │
│   ├─ n-model 下拉: 1=域名 0=IP                 │
│   ├─ cite 输入框 (域名/IP/关键字)              │
│   ├─ net-add 添加按钮                          │
│   └─ NList 规则列表                            │
│                                               │
│ UControl (附加): u-p / u-o / u-d 三个复选框     │
│   (限制网页/限制在线/限制下载 等)               │
│                                               │
│ option2: KControl (键盘管控)                   │
│   ├─ 复选框 KControl (总开关)                  │
│   ├─ key-name 关键词输入 + key-add             │
│   ├─ KList 关键词列表                          │
│   ├─ key-message 提示消息输入                  │
│   ├─ send-message (发送消息给学生)             │
│   └─ send-kill (发送并杀掉相关进程)            │
│                                               │
│ [确定] [取消]                                  │
└───────────────────────────────────────────────┘
```

---

## 🔑 核心：CtrlCode 管控码（位标志）

反编译 `FUN_005648c0`（Teacher.exe）确认：**`CtrlCode` 是一个按位 OR 组合的整型标志**，决定下发哪些管控：

| 位 | 值 | 管控项 | 对应 JSON 字段 | UI 控件 |
|----|-----|--------|---------------|---------|
| bit0 | `0x01` | **网络禁用** | `DisabledNet` | NControl |
| bit1 | `0x02` | **键盘过滤** | `EnableNetKeyFilter` | KControl |
| bit4 | `0x10` | **应用禁用** | `DisabledApp` | PControl |
| bit8 | `0x100` | **USB 禁用** | `DisabledUsb` | UControl |
| bit12 | `0x1000` | USB 禁用(变体) | `DisabledUsb` | UControl |
| bit16 | `0x10000` | USB 禁用(变体) | `DisabledUsb` | UControl |

```cpp
// 伪代码（来自 FUN_005648c0 反编译）
if (ctrlCode & 0x10)   → 读取 "DisabledApp" 规则列表
if (ctrlCode & 0x01)   → 读取 "DisabledNet" 规则列表
if (ctrlCode & 0x100)  → 读取 "DisabledUsb" 规则列表
if (ctrlCode & 0x10000)→ 读取 "DisabledUsb" 规则列表
if (ctrlCode & 0x02)   → 读取 "EnableNetKeyFilter" 列表
```

---

## 📋 JSON 指令完整字段（从 .rdata 数据区提取）

通过 Ghidra 内存转储，确认了 Teacher 端构造指令时使用的**全部 JSON 键名**（地址 0x6C1000-0x6C10F4）：

```
0x6C1000: type            ← 规则类型
0x6C1008: type
0x6C1010: cite            ← 单个站点/域名/IP
0x6C1018: keys            ← 键盘关键词列表
0x6C1020: keys
0x6C1028: keys
0x6C1030: keyName         ← 键盘关键词
0x6C1038: keyName
0x6C1040: keyName
0x6C1048: sendState       ← 发送状态标志
0x6C1054: tipInfo         ← 提示信息
0x6C105C: sendState
0x6C1068: tipInfo
0x6C1070: NPDControl.json ← 配置文件名
0x6C1084: CtrlCode        ← 管控码（核心字段！）
0x6C1090: app             ← 应用白/黑名单条目
0x6C1094: exec            ← 可执行文件名
0x6C109C: type            ← 规则类型
0x6C10A4: apps            ← 应用列表
0x6C10AC: cite            ← 站点条目
0x6C10B4: type
0x6C10BC: cites           ← 站点列表
0x6C10C4: keyName
0x6C10CC: keys            ← 键盘关键词列表
0x6C10D4: sendState
0x6C10E0: tipInfo
0x6C10E8: TSpaceInUse
0x6C10F4: serverIp        ← 服务器 IP
```

---

## 📤 Teacher 端指令构造流程（FUN_0059ca10）

```cpp
// 伪代码（基于 FUN_0059ca10 反编译还原）
void SendBehaviorControl(Json::Value& cmd) {
    // ===== 第一部分：PControl 应用管控 =====
    for (auto& rule : PList) {                    // 遍历 PList 列表
        jObj["CtrlCode"] = ctrlCode;              // 管控码
        jObj["app"]     = rule.appName;           // 应用名
        jObj["exec"]    = rule.execName;          // 可执行文件名
        jObj["type"]    = rule.type;              // 类型: 0/1
        jObj["apps"]    = accumulateApps();       // 全部应用
    }

    // ===== 第二部分：NControl 网络管控 =====
    for (auto& rule : NList) {                    // 遍历 NList 列表
        jObj["CtrlCode"] = ctrlCode;
        jObj["cite"]     = rule.cite;             // 域名/IP/网址
        jObj["type"]     = rule.type;             // 1=域名 0=IP
        jObj["cites"]    = accumulateCites();
    }

    // ===== 第三部分：KControl 键盘管控 =====
    for (auto& key : KList) {                     // 遍历 KList 列表
        jObj["CtrlCode"] = ctrlCode;
        jObj["keyName"]  = key.name;              // 关键词
        jObj["keys"]     = accumulateKeys();
    }

    // ===== 附加字段 =====
    jObj["sendState"] = sendStateFlag;            // 发送状态
    jObj["tipInfo"]   = warningMessage;           // 提示文字
    jObj["serverIp"]  = teacherIp;                // 教师机 IP
}
```

---

## 🔐 传输加密：HTTP encode 通道

Teacher 端通过 **HTTP 接口 + 加密编码** 下发指令：

```cpp
// 反编译发现的关键 URL 构造
FUN_0041fe70("http://%s:%d/encode");                     // encode 接口
FUN_0041fe70("productId=%s&hardware=%s");                // 产品/硬件认证参数

// 响应解析
jObj["encoded"] = encodedString;                          // 返回 {"encoded": "%s"}
FUN_005c6200("encoded");
```

**关键发现**：
- 接口：`POST http://{serverIp}:{port}/encode`
- 参数：`productId` + `hardware`
- 响应：`{"encoded":"<加密后的管控指令>"}`
- 含义：**管控指令以 JSON 构造后，经 encode 接口加密，再以 `encoded` 字段包装下发**

---

## 📥 Student 端接收与执行流程

### 1. 本地代理轮询：npd-auto

```cpp
// FUN_004bb570（Student.exe）
FUN_004d8110("npd-auto");                         // 指令类型标识
FUN_004d8940("127.0.0.1"; 0x2346);                // 连接 127.0.0.1:9030
```

- Student 端通过 **`npd-auto`** 连接**本地代理 127.0.0.1:9030（0x2346）**获取管控数据
- 即：教师端 → [encode 服务器/代理] → 学生端本地组件 → 9030 端口 → Student.exe

### 2. 命令分发（cmd1 / cmd3）

Student.exe 中存在命令枚举与分发：
```
cmd1   ← 主要管控指令通道
cmd3   ← 辅助/扩展指令通道
[DataFromLogicEx]Classification::EXAMCMDEND      ← 考试结束
[DataFromLogicEx]Classification::EXAMCMDEXTEND   ← 考试扩展
[DataFromLogicEx]Classification::EXAMCMDPAUSE    ← 考试暂停
[DataFromLogicEx]Classification::EXAMCMDPUSHANS  ← 推送答案
[DataFromLogicEx]Classification::EXAMSENDFILE    ← 发送文件
[DataFromLogicEx]Classification::SENDIMAGEFILE   ← 发送图片
SYS_RunCommand                                    ← 系统命令执行
```

### 3. 执行组件调用链

Student 收到指令后分发到各执行模块：

| 管控类型 | Student 端动作 | 实际执行者 |
|---------|---------------|-----------|
| **网络禁用** `DisabledNet` | 调用 DeviceControl | `DeviceControl.exe` → `NetLimitInterface.dll` → `CNetLimitInstance::SetWhiteRule` |
| **应用禁用** `DisabledApp` | 调用 DeviceControl | `DeviceControl.exe` → `\\.\ProcFireWall` 驱动 (IOCTL 0x222000) |
| **USB 禁用** `DisabledUsb` | 调用 DeviceControl | `DeviceControl.exe` → `easyusbctrl.dll` → `EasyUsb_StartWorking/StopWorking` |
| **键盘锁定** `EnableKeyboard/DisableKeyboard` | 加载 DLL | `LockKeyboard.dll`（`FUN_004084a0(L"LockKeyboard.dll")`） |
| **键盘过滤** `EnableNetKeyFilter` | 关键词匹配 | `keywords.json` → `UIStudentMainWnd` 窗口键检测 → `GetKeyState/ImmGetVirtualKey` |
| **上网限制** | 浏览器监控 | `surfInternet` → `keywords.json` (`{"keys":[{"key":"surf"}],"windowName":"UIStudentMainWnd"}`) |
| **黑屏** `BlackSilent` | 黑屏锁定 | `BlackSilent` / `menu_BlackSilence` / `RemoveBlackLock` |
| **提示消息** `tipInfo` | 弹窗提示 | `TeacherWarning` UI 弹窗 |
| **远程命令** | 执行命令 | `SYS_RunCommand` / `cmd.exe` |

---

## 🗄️ 相关配置文件

### keywords.json（学生端键盘/上网监控）
```json
{
   "keys" : [ { "key" : "surf" } ],
   "windowName" : "UIStudentMainWnd"
}
```
- 监控窗口：`UIStudentMainWnd`
- 监控关键词：`surf`（上网类）

### NPDControl.xml 关键控件 → JSON 映射
| XML 控件 | JSON 字段 | 含义 |
|---------|----------|------|
| `PControl` 复选框 | `CtrlCode & 0x10` | 应用管控开关 |
| `p-model` 下拉 | `type` | 1=进程名 0=文件名 |
| `app-name`/`exec-name` | `app` / `exec` | 应用/进程名称 |
| `p-black` / `p-white` | `apps` + 模式 | 黑名单/白名单 |
| `NControl` 复选框 | `CtrlCode & 0x01` | 网络管控开关 |
| `n-model` 下拉 | `type` | 1=域名 0=IP |
| `cite` | `cite` / `cites` | 禁止访问的站点/IP |
| `KControl` 复选框 | `CtrlCode & 0x02` | 键盘管控开关 |
| `key-name` | `keyName` / `keys` | 键盘监控关键词 |
| `key-message` | `tipInfo` | 违规提示消息 |
| `send-message` | `sendState` | 是否发送提示 |
| `send-kill` | `sendState` | 是否杀掉进程 |

---

## 🌐 完整数据流图

```
┌─────────────────────────────────────────────────────────┐
│ 教师端 Teacher.exe                                       │
│                                                         │
│  UI (NPDControl.xml) → 读取规则列表                      │
│  ↓                                                     │
│  构造 JSON:                                             │
│  { CtrlCode, apps[], cites[], keys[],                  │
│    sendState, tipInfo, serverIp }                      │
│  ↓                                                     │
│  POST http://{ip}:{port}/encode                        │
│  (productId + hardware 参数)                           │
│  ↓                                                     │
│  返回 {"encoded":"..."} → 加密指令                     │
└────────────────────────┬────────────────────────────────┘
                         │ 网络传输（TCP/HTTP）
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 学生端本地代理 (npd-auto)                                │
│  监听 127.0.0.1:9030 (0x2346)                          │
│  解码 encoded → 还原 JSON 管控指令                      │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Student.exe (UIStudentMainWnd)                          │
│  cmd1/cmd3 分发                                         │
│  ↓ ↓ ↓ ↓ ↓                                             │
│  ├─ DisabledNet    → DeviceControl.exe                 │
│  │                    └─ NetLimitInterface.dll          │
│  │                       (CNetLimitInstance::SetWhiteRule)│
│  ├─ DisabledApp    → DeviceControl.exe                 │
│  │                    └─ \\\\.\\ProcFireWall 驱动      │
│  │                       (ZwSuspendProcess / IOCTL)    │
│  ├─ DisabledUsb    → DeviceControl.exe                 │
│  │                    └─ easyusbctrl.dll               │
│  │                       (EasyUsb_StartWorking)        │
│  ├─ EnableKeyboard → LockKeyboard.dll                  │
│  │  /DisableKeyboard                                   │
│  ├─ EnableNetKeyFilter → keywords.json 关键词匹配      │
│  │                    + GetKeyState/ImmGetVirtualKey   │
│  ├─ BlackSilent    → 黑屏锁定                          │
│  ├─ sendState/tipInfo → TeacherWarning 弹窗提示        │
│  └─ SYS_RunCommand → 远程命令执行                      │
└─────────────────────────────────────────────────────────┘
```

---

## 🔍 完整 JSON 指令示例（还原）

```json
{
  "CtrlCode": 19,
  "apps": [
    { "app": "notepad", "exec": "notepad.exe", "type": 1 },
    { "app": "game",    "exec": "game.exe",    "type": 0 }
  ],
  "cites": [
    { "cite": "www.baidu.com", "type": 1 },
    { "cite": "10.1.2.3",       "type": 0 }
  ],
  "keys": [
    { "keyName": "surf" },
    { "keyName": "game" }
  ],
  "sendState": 1,
  "tipInfo": "上课请勿浏览与学习无关的网站！",
  "serverIp": "192.168.1.100"
}
```

> CtrlCode = 0x01(网络) + 0x02(键盘) + 0x10(应用) = 19

---

## 🛡️ 安全关注点

1. **管控能力强**：可远程禁用学生网络、禁 USB、锁键盘、黑屏、杀进程
2. **加密通道**：指令经 `/encode` 接口加密（CryptoPP 库：DES-EDE2/HMAC-SHA1/Base64）
3. **本地明文端口**：`127.0.0.1:9030`（npd-auto）、`8045/8406`（DeviceControl 控制协议）均可被本机程序调用，存在**本地提权/伪造指令**风险
4. **ProcFireWall 驱动 IOCTL**：`0x222000/0x222008` 无权限验证，任意用户态程序可调用
5. **LockKeyboard.dll** 动态加载：存在 DLL 劫持风险

---

## 📊 分析结论

| 项目 | 结果 |
|------|------|
| 指令格式 | ✅ **JSON**（JsonCpp 构造） |
| 核心字段 | ✅ `CtrlCode`（位标志） |
| 管控类型 | ✅ 网络/应用/USB/键盘/黑屏/消息 6 大类 |
| 传输方式 | ✅ HTTP `/encode` 接口 + `encoded` 包装 |
| 学生端入口 | ✅ `npd-auto` → 127.0.0.1:9030 |
| 执行组件 | ✅ DeviceControl.exe / LockKeyboard.dll / 键盘钩子 |
| 分析完整度 | ✅ 约 90%（字段/流程完全还原，动态抓包验证待做） |

---

**分析时间**: 2026-09-06
**分析工具**: Ghidra 12.1.3（Teacher.exe / Student.exe / DeviceControl.exe 反编译）
**辅助证据**: NPDControl.xml、keywords.json、.rdata 字符串地址转储