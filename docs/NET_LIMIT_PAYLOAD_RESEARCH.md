# type=500 网络限制载荷结构 - 深度挖掘报告（CtrlCode JSON 定稿）

> **目标**：还原教师端「行为管控 → 网络限制」指令的完整载荷结构（`this+0x548` 之谜）
> **方法**：Ghidra 12.1.3 对 MainLogic.dll（教师端核心）+ Teacher.exe（UI 层）进行调用链追踪 + JSON 键名还原 + 位标志验证
> **时间**：2026-09-07
> **关联**：`ARBITRATION_VERIFICATION_REPORT.md`（双重逆向仲裁）的遗留问题 #1 现已基本解决

---

## 一、核心结论（本次定稿）

**type=500（网络限制）的载荷 = `/*//` 前缀 + 教师端构造的 CtrlCode JSON**

```
16字节命令头                载荷
[500][0][0][len]  +  "/*//" + {"CtrlCode":<int>, "apps":[...], "cites":[...], "keys":[...], ...}
```

载荷主体由 Teacher.exe 的 `FUN_0059ca10` 构造，经 MainLogic.dll 存入 `DAT_1018faa0+0x548`，发送时用 `/*//` 作前缀标记。

---

## 二、完整调用链（本次追踪确认）

```
[Teacher.exe] 行为管控 UI
   │ 用户勾选 程序限制/禁用外网/禁用USB
   ▼
FUN_005648c0  (size=1770)
   │ 读取 NPDControl.json 配置
   │ 按位判断 local_1c4:
   │   0x01    → DisabledNet          (禁用网络)
   │   0x02    → EnableNetKeyFilter   (启用网络过滤)
   │   0x10    → DisabledApp          (禁用程序)
   │   0x100   → DisabledUsb          (USB 限制 1)
   │   0x1000  → DisabledUsb          (USB 限制 2)
   │   0x10000 → DisabledUsb          (USB 限制 3)
   ▼
FUN_0059ca10  (size=1145)  ← ★ JSON 构造器
   │ 组装 JSON 对象:
   │   CtrlCode  ← 位标志整数值
   │   apps[]    ← 程序限制列表（app/exec/type）
   │   cites[]   ← 网址限制列表（cite/type）
   │   keys[]    ← 关键词列表（keyName/...）
   │   sendState / tipInfo / serverIp
   │ 序列化(JsonCpp) → 字符串
   ▼
[MainLogic.dll]
UnLoad (导出, 0x10019df0)
   ▼
FUN_10077970  (唯一调用者确认)
   │  构造 {"CtrlCode": <值>} JSON (JsonCpp封装)
   │  序列化 → 字符串
   ▼
FUN_10067f50  (保存配置 + 触发发送)
   │  FID_conflict_operator_(this+0x548, JSON串)  ← 存入 DAT_1018faa0+0x548
   │  if (a7 == 0) → 触发发送
   ▼
FUN_10064770  (type=500 发送)
   │  local_24 = 500
   │  local_20 = 0, local_1c = 0
   │  if (len(this+0x548) < 0x8000) {
   │    FUN_1003fc60(&hdr)          ← 分配 0x8000 缓冲区
   │    FUN_1003f850(&hdr, &{500,0,0,len})  ← 写16字节头
   │    FUN_100218a0(&hdr, this+0x548, 1)   ← 附加载荷(JSON)
   │    FUN_10008b40(&buf, "/*//")          ← ★ 前缀
   │    FUN_1009e070(this+0x30, buf, len)   ← 遍历单播发送
   │  }
```

---

## 三、JsonCpp 封装函数识别（本次确认）

在 MainLogic.dll 中确认以下函数为 JsonCpp 的封装（用于 `FUN_10077970` 构造 CtrlCode JSON）：

| 函数 | JsonCpp 对应 | 功能 |
|------|-------------|------|
| `FUN_1012c860(0)` | `Json::Value(Json::objectValue)` | 创建 JSON 对象 |
| `FUN_1012c7c0(int)` | `Json::Value(int)` | 创建整数值 |
| `FUN_1012d050(key)` | `Json::Value(const char*)` | 创建 key 字符串 |
| `FUN_1012cc70(value)` | `Json::Value::operator=` | 赋值 |
| `FUN_1012ecb0(obj, out)` | `Json::StyledWriter::write` | 序列化为字符串 |
| `FUN_1012cbb0(v)` | `Json::Value::~Value` | 析构 |
| `FUN_1012c780` | `Json::Value(ValueType)` | 对象构造（带类型） |
| `FUN_1012c530` | `Json::Value` 拷贝构造 | 复制 |

---

## 四、CtrlCode 位标志表（Teacher.exe FUN_005648c0 实锤）

| 位掩码 | 十六进制 | 功能 | UI 控件/字符串 |
|--------|---------|------|----------------|
| 0b0001 | **0x01** | **DisabledNet 禁用网络** | `DisabledNet` |
| 0b0010 | **0x02** | **EnableNetKeyFilter 网络过滤** | `EnableNetKeyFilter` |
| 0b0100 | 0x04 | (保留/未确认) | - |
| 0b1000 | 0x08 | (保留/未确认) | - |
| 0x0010 | **0x10** | **DisabledApp 禁用程序** | `DisabledApp` |
| 0x0020 | 0x20 | (保留) | - |
| 0x0040 | 0x40 | (保留) | - |
| 0x0080 | 0x80 | (保留) | - |
| 0x0100 | **0x100** | **DisabledUsb USB限制1** | `DisabledUsb` |
| 0x1000 | **0x1000** | **DisabledUsb USB限制2** | `DisabledUsb` |
| 0x10000 | **0x10000** | **DisabledUsb USB限制3** | `DisabledUsb` |

> 0x04/0x08/0x20/0x40/0x80 位在反编译中未见对应判断分支，但存在理论可能（后续可补查）。
> 注意：0x100/0x1000/0x10000 都对应 `DisabledUsb`，但可能代表不同的 USB 设备类别（U盘/移动硬盘/虚拟光驱），需结合 BehaviorControl.xml 的 CBCDLimit/CBULimit/CBVirtualCDLimit 三个勾选对应。

---

## 五、教师端管控 JSON 完整键名（FUN_0059ca10 实锤）

`FUN_0059ca10` 通过 JsonCpp 遍历构造，确认的键名：

| 键名 | 来源 | 说明 |
|------|------|------|
| `CtrlCode` | 直接字符串 | **位标志整数**（核心） |
| `app` | 0x6c1090 | 程序名（apps 数组元素） |
| `exec` | 0x6c1094 | 程序执行路径（apps 数组元素） |
| `type` | 0x6c109c | 类型（apps 元素：黑/白名单） |
| `apps` | 0x6c10a4 | **程序限制数组** |
| `cite` | 0x6c10ac | 网址（cites 数组元素） |
| `type` | 0x6c10b4 | 类型（cites 元素） |
| `cites` | 直接字符串 | **网址限制数组** |
| `keyName` | 直接字符串 | 关键词名（keys 数组元素） |
| `keys` | 0x6c10cc | **关键词过滤数组** |
| `sendState` | 直接字符串 | 发送状态（0/1） |
| `tipInfo` | 直接字符串 | 提示信息文本 |
| `serverIp` | 直接字符串 | 服务器 IP |

---

## 六、type=500 载荷样例（构造还原）

综合所有证据，**教师端发送的 type=500 载荷**应为如下形式（`/*//` 前缀 + JSON）：

```
/*//{"CtrlCode":19,"apps":[{"app":"notepad","exec":"C:\\Windows\\system32\\notepad.exe","type":"black"}],
     "cites":[{"cite":"example.com","type":"black"}],
     "keys":[{"keyName":"surf"}],
     "sendState":1,"tipInfo":"...","serverIp":"192.168.1.100"}
```

其中 `CtrlCode=19` = 0x13 = 0x01(网络) + 0x02(网络过滤) + 0x10(程序)，即"禁网+过滤+禁程序"。

> ⚠️ 注意：`CtrlCode` 值与 Teacher.exe 位判断对应，`apps/cites/keys` 数组与 NPDControl.json / keywords.json 结构对应。**具体数组元素的精确字段名（app/exec/type/cite/keyName）已在本次确认**，但数组嵌套层级（是否还有外层包裹字段）仍需动态抓包最终验证。

---

## 七、与之前分析的对应关系

| 之前发现 | 本次确认 |
|---------|---------|
| `FUN_005648c0` CtrlCode 位标志构造 | ✅ 位标志表完整确认（0x01/0x02/0x10/0x100/0x1000/0x10000） |
| `.rdata 0x6C1000-0x10F4` JSON 键名 | ✅ 键名全部确认（app/exec/type/apps/cite/cites/keys/keyName） |
| `FUN_0059ca10` 与 JSON 构造 | ✅ 确认是完整 JSON 构造器（含 sendState/tipInfo/serverIp） |
| `/*//` 前缀 | ✅ 确认是载荷前缀（组包时写入） |
| `this+0x548` 载荷 | ✅ 确认内容 = CtrlCode JSON 字符串 |
| `FUN_10077970` 调用者 | ✅ 唯一调用者是 `UnLoad` 导出 |
| JsonCpp 封装 | ✅ 识别出 8 个 JsonCpp Value 操作函数 |

---

## 八、对注入工具的直接意义（定稿载荷）

Python 工具发送网络限制指令的**最终载荷格式**：

```python
import struct, json

def build_net_limit_packet(ctrl_code: int, apps=None, cites=None,
                           keys=None, send_state=1, tip="", server_ip=""):
    """构造 type=500 网络限制指令报文"""
    payload_obj = {
        "CtrlCode": ctrl_code,          # 位标志: 0x01网络/0x02过滤/0x10程序/0x100+USB
        "sendState": send_state,
        "tipInfo": tip,
        "serverIp": server_ip,
    }
    if apps:  payload_obj["apps"] = apps   # [{"app":..,"exec":..,"type":..}]
    if cites: payload_obj["cites"] = cites # [{"cite":..,"type":..}]
    if keys:  payload_obj["keys"] = keys   # [{"keyName":..}]

    body = b"/*//" + json.dumps(payload_obj, separators=(',', ':')).encode("utf-8")
    header = struct.pack("<IIII", 500, 0, 0, len(body))
    return header + body

# 示例: 禁用网络+网络过滤+程序限制 (CtrlCode=0x13=19)
pkt = build_net_limit_packet(
    ctrl_code=0x13,
    apps=[{"app": "chrome", "exec": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "type": "black"}],
)
# 发送: UDP → 学生机IP:8040
```

---

## 九、遗留待验证项（回机房后）

1. **`/*//` 前缀后是否紧跟 JSON 起始**（无空格/换行），需要抓包确认
2. **CtrlCode 与 apps/cites/keys 数组是否同时出现**（还是按位选择只带相关数组）
3. **`type` 字段在 apps/cites 里的取值**（black/white？）—— 与 Teacher.exe 的 p-black/p-white 对应
4. **sendState/tipInfo/serverIp 是否必需**（可能是可选字段）
5. **数组元素是否还有外层字段**（如 `{"apps":[{"app":...}]}` 的嵌套层级）
6. **type=500 之外的其他 cmdType（11/13/28/79/111）载荷**是否同样走 `/*//` + JSON
7. **0x04/0x08/0x20/0x40/0x80 位的用途**（未在反编译中见到，可能为保留位或新版本功能）

---

## 十、关键证据文件

| 文件 | 内容 |
|------|------|
| `/tmp/verify_Teacher.exe.txt` (531行) | FUN_005648c0 + FUN_0059ca10 完整反编译 |
| `/tmp/verify_MainLogic.dll.txt` | FUN_100218a0/FUN_1003fc60/FUN_10010110 等 |
| `/tmp/callers_MainLogic.dll.txt` | FUN_10077970 调用者追踪（UnLoad 确认） |
| `/tmp/readdat_Teacher.exe.txt` | JSON 键名地址读取（app/exec/type/apps/cite/keys） |

---

*报告时间：2026-09-07*