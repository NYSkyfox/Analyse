# Os-Easy 教师端管控指令协议逆向分析（new.md）

> 分析对象：Os-Easy（噢易）多媒体电子教室教师端/学生端套件
> 分析方法：Sysinternals Strings + IDA Pro 9.4（IDAPython 静态反编译）
> 分析目标：还原「教师端 → 学生端」管控指令的内容与线格式，用于在学生机上模拟教师端发送控制指令

---

## 一、核心结论：管控指令的线格式

教师端对学生的管控指令是**单播 UDP 包**，报文结构固定如下：

```c
// 报文体
struct Packet {
    uint32_t cmdType;      // 命令类型号（小端）
    uint32_t flag1;        // 0 或 1
    uint32_t flag2;        // 0
    uint32_t payloadLen;   // 载荷字节长度
    uint8_t  payload[];    // 载荷（通常 JSON 或文本）
};
// 线报文 = [16 字节命令头][payloadLen 字节载荷]
```

**证据链（IDA 伪代码）：**

- `sub_1003F850` — 命令头写入函数：把 4 个 DWORD（`*a2` / `a2[1]` / `a2[2]` / `a2[3]`）顺序拷贝到缓冲，步进 `+16` 字节。
- `sub_10099CD0` — 载荷组包：`malloc(Size+4)`，`memcpy(buf+4, Src, Size)`，长度存最前 4 字节。
- `sub_1009E070` — 群发入口：遍历在线节点 `sub_100541C0(i)`，逐节点 `sub_10099CD0` 组包后经 `this+0x68` 队列（`sub_100A0610`）发出。

> 注意：`sub_1009E070` 是**单播遍历在线学生列表**发送，不是组播广播。组播地址 `229.4.x` 用于**屏幕/媒体流**，管控指令走单播。

---

## 二、命令类型号（cmdType）对照表

| cmdType | 命令 | 载荷说明 | 反编译出处 |
|--------|------|---------|-----------|
| 11 | 学生呼号/点名 | 呼号标识 | `SendCallSignToNewStudent` → `sub_1006C010` |
| 13/39/40/41 | 远程命令 | `{"text":...,"second":...}`，命令名 `RemoteCommand` | `SetRemoteCommand` → `sub_10075250` |
| 28 | 学生参数配置 | `StuSet` JSON | `SendStudentParaConfig` → `sub_1006E160` |
| 79 | 考试文件传输结束 | `{"exam":...}` | `sub_10060A10` |
| 111 | 学生信息登记 | `{"ip","mac","name","stunum","shownum","pcname","autosign"}` | `sub_1006C300` |
| 500 | **网络限制** | 限制配置（`a7==0` 时触发） | 导出 `Limit` → `sub_10067F50` → `sub_10064770` |

---

## 三、网络限制（cmdType=500）的具体逻辑

导出函数 `Limit`（`0x100197e0`）：

```c
int Limit(char a1 /*JSON标志*/, int a2, int a3, int a4, int a5, int a6,
          unsigned __int8 a7)
{
    sub_1000B8E0(&a1);          // 把限制配置写入 CMainLogic 对象 +0x548
    sub_10067F50(v8..., a7);    // a7==0 时调用 sub_10064770 发送 type=500
    return 析构;
}
```

`sub_10067F50`（`0x10067f50`）反汇编确认：

```
0x10067f8f  movzx ecx, [ebp+arg_18]
0x10067f93  test  ecx, ecx
0x10067f95  jnz   skip          ; a7 != 0 → 只存配置，不发送
0x10067f9a  call  sub_10064770  ; a7 == 0 → 发送 type=500
```

`sub_10064770`：当 `this+1352` 长度 < 0x8000 时，构造 `v7[0]=500` 的命令头，`sub_1003F850` 写入，再 `sub_1009E070` 发出。

> **待办**：type=500 的载荷（`this+1352` 字符串字段）的确切内容/字段结构**尚未 100% 还原**，需继续反编译 `Limit` 调用链与 `this+1352` 的构造来源（Teacher.exe 侧）。

---

## 四、学生端接收链（教师端指令 → 本地执行）

```
教师端(A) --单播UDP--> B 的 MultiClient.exe / StudentLogic.dll
                         │ 监听 UdpMessageControllerPort
                         ▼ 收到 [16字节命令头+载荷]
                       本地翻译
                         ▼
                   127.0.0.1:8045（DeviceControl_x64.exe）
                         ▼ DeviceIoControl IOCTL_SET_SpeedControl
                    OeNetLimit.sys（WFP 驱动，disableNet/disableInternet）
```

学生端 `StudentLogic.dll` 翻译函数（已反编译）：

- **开网络管控** `sub_100838A0`：命令名 `support-use-device-control` + 字段 `network`/`networktraffic`/`device`/`process` → 发 127.0.0.1:8045。
- **关网络管控** `sub_100836A0`：命令名 `stop-device-control` + 字段 `stopnetwork`/`stopnetworktraffic`/`stopdevice`/`stopprocess` → 同端口。

---

## 五、端口配置（`skin\core.conf`）

格式 `/键/值/`，默认值已全部提取：

| 键 | 默认值 | 用途 |
|----|--------|------|
| **`UdpMessageControllerPort`** | **8040** | **管控指令 UDP 端口（教师端→学生端）** |
| `MultiCastPort` | 7778 | 屏幕广播组播 |
| `ConnectPort` | 9003 | 教师端连接端口 |
| `RegisterServerPort` | 8003 | 注册服务器 |
| `RegisterServerBindingMac` | 1 | MAC 绑定=开启 |
| `AssistIp` | 0.0.0.0 | 辅助 IP |
| `RegisterType` | 0 | 注册类型（0=组播） |
| `TransferType` | multicast | 传输类型 |
| `Limit` | 1 | 限制开关 |

学生端 `StudentLogic.dll` 的 `sub_1005E5E0` 通过 `sub_10002A50`（内部 `sub_1000CF50`）读 `core.conf`。

> 注意区分：**8040**（UdpMessageControllerPort，学生端接收教师指令）与 **8045**（学生端本地 `DeviceControl` 监听 `127.0.0.1`，见 `sub_1008E960` 硬编码）。

---

## 六、组播 IP 前缀（媒体流，非管控指令）

`sub_100618E0` 已确认硬编码：

- IPv4：`229.4.`（另有 `229.0.` / `229.1.` / `229.8.` / `229.9.`），后两段按 `RegisterType`/频道动态拼接。
- IPv6：`ff02::1:` / `ff02::2:` / `ff02::f188`。

---

## 七、关键函数地址索引（MainLogic.dll）

| 地址 | 名称/符号 | 作用 |
|------|----------|------|
| 0x100197E0 | `Limit` | 网络限制导出函数 |
| 0x10067F50 | `sub_10067F50` | Limit 内部：a7==0 时发 type=500 |
| 0x10064770 | `sub_10064770` | 构造 type=500 命令头并发送 |
| 0x1003F850 | `sub_1003F850` | 命令头（16B）写入 |
| 0x10099CD0 | `sub_10099CD0` | 载荷组包（len+bytes） |
| 0x1009E070 | `sub_1009E070` | 单播群发入口 |
| 0x10019C10 | `SetRemoteCommand` | 远程命令 type 13/39/40/41 |
| 0x10019B40 | `SendStudentParaConfig` | StuSet type 28 |
| 0x10019A40 | `SendCallSignToNewStudent` | 呼号 type 11 |
| 0x1005E5E0 | `sub_1005E5E0` | 读 core.conf 端口配置 |
| 0x100618E0 | `sub_100618E0` | 组播 IP 构造 |
| 0x10065120 | `sub_10065120` | 组播地址拼接（`229.4.` + 段） |

## 八、关键字符串证据（StudentLogic.dll）

| 地址 | 字符串 | 引用函数 |
|------|--------|---------|
| 0x1023ee50 | `stopnetwork` | `sub_100836A0`（关网络） |
| 0x1023ee3c | `stopnetworktraffic` | `sub_100836A0` |
| 0x1023edf0 | `networktraffic` | `sub_100838A0`（开网络） |
| 0x102390c0 | `NetModule---->` | `sub_100824E0` |
| 0x10237fa0 | `NetMatchIp` | `sub_10034080` |

---

## 九、已完成的功能落地

将上述协议封装为 `src/modules/teacher_control.py`，并在高级页 `src/gui/pages/page_advanced.py` 新增「教师端管控指令模拟」区块：

- 输入目标 IP/网段 + 端口（默认 8040）。
- 下拉选择命令类型（11/13/28/79/111/500）。
- 输入载荷（JSON/文本）。
- 单播发送 `[16字节命令头+载荷]`，并在输出区显示报文 hex 预览。

---

*分析时间：2026-08-30（静态分析，仅 strings + IDA，未动态调试）*
