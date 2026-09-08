# Os-Easy 教师端"远程执行 cmd 命令"功能逆向报告 —— RemoteCommand（远程命令）链路定位

> **目标**：在教师端套件（Teacher.exe + MainLogic.dll）中“揪出”那个能对目标学生机**远程执行自定义 cmd 命令**的功能，回答三个问题：
> 1. 这个功能在二进制里叫什么 / UI 长什么样？
> 2. 命令从教师 UI 输入到发往学生机的**消息是怎么打包的**？
> 3. 发的是什么通道、什么类型、长什么样？
>
> **方法**：Ghidra 12.1.3（container `ghidra`，headless）对 `Teacher.exe` 与 `MainLogic.dll` 做字符串→引用→反编译逐层追索，交叉核对 PE 导出表。
> **状态**：**功能 + 主链路已揪出并反编译定案 ✅**；“UI 输入框把命令文本塞进消息”的字节层解析仍有一处待最终闭环 ⚠️（范围已缩到具体函数）。
> **报告时间**：2026-09-08

---

## 1. 一句话结论

**教师端“远程执行 cmd 命令”功能 = `RemoteCommand（远程命令）`，是一个 MFC 对话框（`CRemoteCommandDlg`，XML 定义在 `RemoteCommandDlg.xml`），命令本体长期预置/缓存在 `RemoteCommand.cache` 里供选择；点“执行”后，Teacher.exe 经 `LoadLibrary(MainLogic.dll)` + `GetProcAddress("SetRemoteCommand")` 桥接调用 **`MainLogic.dll` 导出 `SetRemoteCommand`**（实际地址 `0x10019c10`，**注意：PE 导出表在 0x10019bf0~d40 一带严重错位，直接按名字读地址会把 SetRemoteCommand 认错**），其内部核心实现函数 `FUN_10075250` 按“命令类型编号”挑选一条**命令类型码（0x0d / 0x27 / 0x28 / 0x29）**，当类型为 0x28/0x29 时还会从一个 JSON 对象里按 `"text"`、`"second"` 两个键取字符串（命令文本/参数即在此处进来），最终封装成**消息类型 `L"RemoteCommand"` 的二进制帧**发出（`FUN_1009e070`），并打印 `[MainLogic][StartRemoteCommand]:%s`。学生机收到该帧后解析执行。**

> 换成人话：这套件的“远程 cmd”更像一个**预置 / 半开放的命令框架**，而非一个裸塞任意 shell 字符串就能逐字节执行的通道——发送宽度受 `RemoteCommand.cache` 预置命令 + 有限命令类型码集合的约束。真正“能塞多任意的命令行”需学生端闭环后才能定论（§7-A），此处不下武断结论。

---

## 2. 二进制关键布局（前提）

| 程序 | ImageBase | .text VA | 说明 |
|------|-----------|----------|------|
| Teacher.exe | `0x400000` | `0x401000`（VSize 0x270d95） | 教师端主程序 + MFC UI + 桥接 |
| MainLogic.dll | `0x10000000` | `0x10001000` | 教师端核心逻辑，**远程命令真身所在** |

Ghidra 项目 `os-easy-analysis` 已导入两者并有分析缓存（`-noanalysis` 加速）。

---

## 3. 字符串证据网（把功能“名字”钉死）

多处扫描命中的关键特征（VA 以 Ghidra 实测 / 引用函数为准）：

| 字符串 | 所在 | 引用/VA | 含义 |
|--------|------|---------|------|
| `start RemoteCommandDlg` | Teacher.exe | `FUN_0055f9d0` | 启动远程命令对话框 |
| `RemoteCommandDlg.xml` | Teacher.exe | `FUN_0055f9d0` | 对话框 XML 布局 |
| `RemoteCommandDlg.cpp_RemoteReboot` | Teacher.exe | `FUN_0048c070` | 预置「重启」命令 |
| `RemoteCommandDlg.cpp_RemoteShutdownApplication` | Teacher.exe | `FUN_005a2ee0`/`005a3de0` | 预置「关闭应用」命令 |
| `RemoteCommand.cache` | Teacher.exe | `FUN_005a60c0` | **命令缓存文件（预置命令落盘）** |
| `RemoteCommands` | Teacher.exe | `FUN_005a60c0` | 命令集合容器名 |
| `SetRemoteCommand` | Teacher.exe | `FUN_00583230` | 桥接调用目标名 |
| `SetRemoteCommand` | MainLogic.dll | 导出表 / `@1017b798` | 导出函数名 |
| `u"RemoteCommand"` | MainLogic.dll | `0x10152cf0`→`FUN_10075250` | **消息类型名** |
| `[MainLogic][StartRemoteCommand]:%s` | MainLogic.dll | `0x10152d0c`→`FUN_10075250` | 核心实现日志 |
| `[MainLogic][StartRemoteControlToAll]...` | MainLogic.dll | `FUN_100756d0` | 对全体开始远程控制 |
| `[MainLogic][StopRemoteControlToAll]...` | MainLogic.dll | `FUN_10075df0` | 对全体停止远程控制 |
| RTTI `.?AVCRemoteCommandDlg@@` | Teacher.exe | `0x73dae4` | MFC 类 `CRemoteCommandDlg` 存在 |

> 结论无歧义：磁盘上确实存在 **`CRemoteCommandDlg`（MFC 对话框）+ `RemoteCommand` 消息通道 + `SetRemoteCommand` 导出** —— 即中文版“远程命令（对目标学生机执行命令）”功能模块。

---

## 4. 教师端 Teacher.exe 链路（UI → 桥）

### 4.1 对话框 UI 入口 — `FUN_0055f9d0 @ 0x55f9d0`

引用 `start RemoteCommandDlg` + `RemoteCommandDlg.xml` → **加载 XML 布局并弹出 `CRemoteCommandDlg` 对话框**的启动函数（MFC 下打开远程命令窗口）。

### 4.2 命令预处理 / 缓存 — `FUN_005a60c0` / `FUN_005a2ee0` / `FUN_005a3de0`

- `FUN_005a60c0 @ 0x5a60c0`：打开并遍历 `RemoteCommand.cache`，逐个把缓存项载入一个命令集合（`local_134 + 0x558` 指向容器并进入迭代循环逐项处理）——即**把上次保存的命令读回 UI 的下拉/列表**。
- `FUN_005a2ee0 / FUN_005a3de0`：同时引用 `RemoteCommandDlg.cpp_RemoteShutdownApplication`（预置「关闭应用程序」）与 `RemoteCommand.cache`、`RemoteCommands`——负责**把预置命令写进/更新命令缓存**，是“命令库”的维护者。

> **关键语义提示**：`.cache` + `.cpp_RemoteShutdownApplication` 的组合说明这套命令很大程度是**可枚举、可预存的命令名**（远程重启、远程关机 / 关应用等），并不天然等于“一个任意字符串会被原样丢进 cmd.dll”。命令能多自由取决于发出后学生端如何解析（§7-A）。

### 4.3 关键执行桥 — `FUN_00583230 @ 0x583230`（转发到 MainLogic）

`FUN_00583230(undefined4 param_1)` 的标准动态加载桥：

```c
pcStack_4c = "SetRemoteCommand";            // 导出名字符串
local_28  = FUN_004157d0(L"MainLogic.dll"); // LoadLibraryW("MainLogic.dll")
...
local_18 = (code *)FUN_0044b8c0();          // GetProcAddress(hMod, "SetRemoteCommand")
if (local_18 != 0) {
    ...
    uStack_54 = 0x5832c9;
    (*local_14)();                          // ★ 调用 SetRemoteCommand(param_1)
}
```

- 仅收一个 `int param_1` → 传的是“**命令类型编号**”（见 §5.2 的表）。
- `FUN_0058cfe0 @ 0x58cfe0` 是对 **`StartRemoteControlToAll`** 的同构桥（LoadLibrary + GetProcAddress），参数按 `&stack0x00000004` 这类栈常量传递。

### 4.4 ★ 决定性证据 — `FUN_0058bb50 @ 0x58bb50`（一个真实执行点：KillProc）

追 `FUN_00583230` 的调用者时命中 `FUN_0058bb50`：

```c
void FUN_0058bb50(void) {
    ...
    local_58 = FUN_004157d0(L"RemoteCommand");  // 引用消息名 RemoteCommand
    ...
    pwStack_64 = L"KillProc";                   // ★ 命令名：KillProc（结束进程）
    FUN_004157d0();
    FUN_0044dbe0();                             // 组装
    pfStack_80 = (function*)0x4;                // ★ 类型参数 = 4
    uStack_84  = 0x58bbfc;
    FUN_00583230();                             // ★ 调 SetRemoteCommand(type=4)
}
```

**串起来的关键事实**：
- `KillProc`（结束目标机某进程）类动作通过 **`type=4` 调 `SetRemoteCommand`**；
- 反查 §5.2，`param_1 == 4` → 命令类型码 `0x29`，且**读 JSON 键 `"text"` 与 `"second"`**。

即：**一个真实“远程命令”执行点（结束进程）被反编译确认会携带 `text/second` 两块文本载荷走进 `RemoteCommand` 消息** —— 是“命令文本从教师端输入进来”的最强间接实证（`text` 即命令文本/程序名，`second` 为参数/附加）。

其余被脚本定位为上层 / 相关候选的函数（`FUN_0056cc60`、`FUN_0057d4a0`、`FUN_0056a170`、`FUN_0052ecc0`、`FUN_005be9a0`）多为命令种类分支分发/UI 事件；其中 `FUN_0056cc60` 当前 Ghidra 反编译失败，待换引擎补全（§7-B）。

---

## 5. MainLogic.dll 核心实现（命令在这封装发出）

### 5.1 ★ 导出序 / 名错位陷阱（必须先讲）

**直接按 PE 导出表名字读地址会犯错**。实测（Ghidra 反编译头注释 + 内部一行转发比对）：

| 导出表名义 | 反编译实测命中地址 | 是否真身 |
|------------|--------------------|----------|
| `SetLockAfterNetWorkBroken` | `0x10019bf0`（ord 47，body → FUN_10071b20） | ✅ 名实相符 |
| `StartMusical` | `0x10019ce0`（ord 52，body → start musical） | ✅ 名实相符 |
| `StopBlackScreen` | `0x10019d40`（ord 54，body → stop blackscreen） | ✅ 名实相符 |
| **`SetRemoteCommand`** | **真正的 SetRemoteCommand = `0x10019c10`（ord 48）** | ⚠️ 此前一度误判到 bf0/ce0/d40，**错位** |

`0x10019c10` 反编译头标注 `/* 0x19c10 48 SetRemoteCommand */`，内部仅做一行核心转发：

```c
void __cdecl SetRemoteCommand(int param_1) {
    ...
    FUN_10075250(param_1);   // ★ 全部逻辑在 FUN_10075250
}
```

> 📌 **坑已排**：凡此前按“导出序把 SetRemoteCommand 标到 0x10019bf0 / 0x10019ce0 / 0x10019d40”的推断全部作废；正确地址就是 **`0x10019c10`**。

### 5.2 核心实现 `FUN_10075250 @ 0x10075250`（完整还原）

| `param_1`（命令类型编号） | 内部命令类型码 `local_24` | 是否读 JSON `text` / `second` | 推测语义 |
|---|---|---|---|
| 0（默认） | `0x0d` (13) | 否 | 基础远程命令 |
| 1 | `0x27` (39) | 否 | 单操作（某功能开） |
| 2 | `0x28` (40) | **读 `text` + `second`**（`FUN_1012d050(obj,"text")` …） | 带参命令（命令文本在 text） |
| 4 | `0x29` (41) | **读 `text` + `second`** | 带参命令（KillProc 走该条，§4.4） |

统一收尾（对任何类型）——消息体组装并发出：

```c
FUN_10016740(auStack_1b8, L"RemoteCommand");        // 构造消息对象，消息类型名 = L"RemoteCommand"
local_150 = FUN_100625f0((void*)(local_e8 + 0xf8), local_54);  // 取命令上下文里的字符串容器
FUN_1003f850(local_114, &local_24);                 // 写入 4B 命令类型码 (0x0d/0x27/0x28/0x29)
iVar2 = FID_conflict_size(local_3c);                // text/second 拼接串字节数
sVar3 = iVar2 << 1;                                 // ★ UTF-16 → 字节数（×2）
pvVar1 = (void*)FUN_100183d0(local_3c);             // 取拼接串缓冲
FUN_10099650(local_114, pvVar1, sVar3);             // 把宽字符载荷追加进帧
sVar3 = FUN_10010110(local_114);                    // 帧总长
pvVar1 = get(local_114);                            // 帧缓冲
FUN_1009e070(*(void**)(local_e8 + 0x30), pvVar1, sVar3);   // ★ 发送到 this+0x30 的连接/句柄
FUN_1000d5e0("[MainLogic][StartRemoteCommand]:%s", ...);   // 日志
```

**要点（已确证）**：
- 消息类型名硬编码 **`L"RemoteCommand"`**（`0x10152cf0`）。
- 载荷 = **4 字节命令类型码 + UTF-16（宽字符）文本**（长度 `iVar2<<1`，即宽字符串的字节长度）。
- `text` / `second` 在 type=0x28/0x29 时经 JSON 取值函数（`FUN_1012d050(obj,"text"...)`、`FUN_1012cc70`）拷入 payload —— **即“命令字符串”（或其参数）进入消息的确切位置**。
- 发出走 `this+0x30` 的连接句柄，`FUN_1009e070` 为通道 send。
- 统一日志 `[MainLogic][StartRemoteCommand]:%s`，便于动态抓包与进程日志对齐。

### 5.3 另一条并行的“全体远程控制”通道 `xsys` + 0x13（勿混淆）

`StartRemoteControlToAll` / `StopRemoteControlToAll` 内部走**消息类型 `"xsys"` + 命令码 `0x13`(19)**，与单条自定义 `RemoteCommand` **不是一条**：

- `FUN_100756d0`（Start 内部）：`"xsys"` + type `0x13`，携带路径类字符串，日志 `[StartRemoteControlToAll][ip:%s][id:%d][type:%d]`；
- `FUN_10075df0`（Stop 内部）：`"xsys"` + `0x13`，置 `this+0x438` 停止标志、`this+0x43c` 存参数字符串。

> 区分：`xsys/0x13` = 对全体/指定机“开/关远程控制会话”的全屏/控制广播；`RemoteCommand + 命令类型码` = 教师对目标机**逐条下发“远程命令 / 动作”** —— 我们要揪的是后者。

### 5.4 追加线索 `.cmd` / `.bat` / `.com` 后缀校验 — `FUN_10129040 @ 0x10129040`

MainLogic.dll 内另检索到 `u".cmd"` → `FUN_10129040`，其反编译对一段路径串做扩展名识别：

```c
// 依次比较小/大写 ".exe" 、".com" 、".bat"、".cmd"（wchar 逐字符分支）
if (后缀不是 ".exe" && 不是 ".com" && 不是 ".bat" && 不是 ".cmd"/".CMD")
    FUN_10128e30(p串, L".cmd", L".CMD");   // 兜底：按 .cmd 匹配/追加处理
```

这种“按 `.cmd/.bat/.com` 分类”的写法通常出现在“把命令落地成批处理文件再执行”的代码旁。因样本当前是 MainLogic（教师端侧也含此类工具函数），只列为“执行侧相关联线索”，**不下定论**（§7-C）。

---

## 6. 完整链路图

```
┌─ 教师端 Teacher.exe ──────────────────────────────────────────────┐
│  CRemoteCommandDlg  (FUN_0055f9d0 打开, RemoteCommandDlg.xml)      │
│       │                                                            │
│       ├─ 预置命令集 RemoteCommand.cache                            │
│       │    (FUN_005a60c0 读回 / FUN_005a2ee0+3de0 维护，            │
│       │     含 RemoteReboot / RemoteShutdownApplication …)          │
│       │                                                            │
│       ▼   用户选命令 + 填 text/second                               │
│  事件回调(例 FUN_0058bb50: 动作 KillProc → type=4,L"RemoteCommand") │
│       │                                                            │
│  FUN_00583230(param_1 = int 类型编号)
│    LoadLibrary(L"MainLogic.dll")
│    GetProcAddress("SetRemoteCommand")
│    SetRemoteCommand(param_1)             ────────────────┐
└──────────────────────────────────────────────────────────┘
                                                          ▼
┌───── 教师端核心 MainLogic.dll ────────────────────────────────────┐
│  导出 SetRemoteCommand @0x10019c10 (ord48)                          │
│      └─ FUN_10075250(param_1)                                      │
│            │ param_1: 0→0x0d │ 1→0x27 │ 2→0x28 │ 4→0x29             │
│            │ (type=0x28/0x29) 读 JSON obj["text"]、obj["second"]    │
│            │    经 FUN_1012d050 / FUN_1012cc70 拷入本地宽串         │
│            ▼                                                       │
│       构造消息: FUN_10016740(msg, L"RemoteCommand")  ← 通道名       │
│       写类型码: FUN_1003f850(&frame, &typeCode)      ← 4B           │
│       写载荷:   FUN_10099650(&frame, wide, len<<1)   ← UTF-16        │
│       发送:     FUN_1009e070(this+0x30, frame, len)  ← socket send  │
│       日志:     "[MainLogic][StartRemoteCommand]:%s"                │
└──────────────────────────────────────────────────────────────────────┘
                                                                  ▼
                                     学生机 StudentLogic / Student 侧
                                     （接收 / 解析 / 执行 —— 下一步追索目标，待续）
```

---

## 7. 结论确证度表

| 结论 | 确证度 | 依据 |
|------|--------|------|
| 存在 `CRemoteCommandDlg` 远程命令对话框 | ✅ 反编译确证 | 字符串 + RTTI + FUN_0055f9d0 |
| 命令预置/缓存 = `RemoteCommand.cache`，含远程重启 / 关应用 | ✅ 反编译确证 | FUN_005a60c0 / 2ee0 / 3de0 |
| Teacher → MainLogic 经 `LoadLibrary + GetProcAddress("SetRemoteCommand")` 桥 | ✅ 反编译确证 | FUN_00583230 |
| 导出 `SetRemoteCommand` = `0x10019c10`（非 bf0/ce0/d40 错位处） | ✅ 反编译确证 | 头注释 `/* 0x19c10 48 */`，一行转发 |
| 核心 FUN_10075250：按类型选 0x0d/0x27/0x28/0x29，读 `text/second` JSON，UTF-16 打包 | ✅ 反编译确证 | §5.2 完整还原 |
| 消息类型名硬编码 `L"RemoteCommand"`，帧 ≈ 类型码 4B + 宽载荷 | ✅ 反编译确证 | 0x10152cf0 / §5.2 |
| 真实执行点 KillProc 用 type=4 → 携带 text/second | ✅ 反编译确证 | FUN_0058bb50 |
| “对全体”的远程控制走独立通道 `xsys/0x13` | ✅ 反编译确证 | FUN_100756d0 / 75df0 |
| `.cmd/.bat/.com` 后缀校验存在于 MainLogic（疑似执行侧） | ⚠️ 部分确证 | FUN_10129040，语义待定 |
| **A. 学生端收到 RemoteCommand 帧后是否真调 cmd.exe / CreateProcess 原样执行 `text`** | ⚠️ **待续** | 需切 StudentLogic.dll / Student.exe |
| **B. FUN_00583230 剩余上层调用者（FUN_0056cc60 等反编译失败）补全** | ⚠️ 待续 | 换分析引擎 / 手动处理 |
| **C. 用户在 UI 敲的自定义命令行确切会填成 text 的字节格式** | ⚠️ 待续 | 需结合 cache 项结构 + 学生端解析 |

---

## 8. 对 OsEasy-ToolKit 的落地建议

1. **接口对齐**：要对目标机“结束进程”等远程命令，教师端走 `SetRemoteCommand(4)`（= 0x29）。但能否“执行任意 cmd”要等 §7-A 学生端闭环后才能确定工具包可开放的最大能力；**此文档发布期不要对外承诺“支持任意 cmd 字符串”**。
2. **动态验证抓手**：教师端进程日志关键字 `[MainLogic][StartRemoteCommand]:%s` + 消息名 `RemoteCommand`，可在隔离 VM 抓包比对载荷格式（≈ 4B 类型码 + UTF-16 载荷）。
3. **命令可枚举化**：优先穷举 `RemoteCommand.cache` 支持的预置操作（重启 / 关机 / 关应用 / KillProc …），据此给出“框架内能做的操作清单”，比赌一个自由 cmd 通道更稳。
4. **别混淆通道**：`xsys/0x13`（全体远程控制）与单条 `RemoteCommand` 是两条；做“单机精确远程命令”应走后者（RemoteCommand 消息）。

---

## 9. 关联文档

| 文档 | 内容 |
|------|------|
| `CONTROL_INJECTION_RESEARCH.md` | core.conf 端口表 / 协议族 |
| `ARBITRATION_VERIFICATION_REPORT.md` | IDA vs Ghidra 交叉仲裁 |
| `CRASH_FUNCTION_REVERSE_REPORT.md` | 9003 崩溃/监控线程停止（MainLogic 内另一条服务链路） |
| `NET_LIMIT_PAYLOAD_RESEARCH.md` | cmdType=500 网络限制载荷（`/*//` + CtrlCode JSON，与 xsys 控制面同族参考） |
| `DEVICECONTROL_ANALYSIS_REPORT.md` | 本地控制端口 8045 |
| `STUDENT_TO_STUDENT_CONTROL_FEASIBILITY.md` | 学生端互控可行性 |

---

**分析工具**：Ghidra 12.1.3（analyzeHeadless + DecompInterface，container `ghidra`）
**分析对象**：`Teacher.exe`（3.7MB）+ `MainLogic.dll`（1.7MB）
**报告时间**：2026-09-08
**状态**：功能 + 教师端主链路已揪出 ✅；学生端接收 / 执行侧 + 自由 cmd 带宽判定开放点待续 🔊
**下一步（建议）**：切 `StudentLogic.dll` / `Student.exe` 追 `RemoteCommand` 帧的接收与执行，关上 §7 的 A / C。
