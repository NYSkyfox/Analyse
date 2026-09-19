# core.conf 全局配置说明（Os-Easy 运行参数）

> 样本：`samples/os-easy/skin/core.conf`（2320 字节，ASCII 文本，CRLF 换行）
> 说明：`core.conf` 为 Os-Easy 多播教学系统的公共运行配置，承载通信端口、身份/安全、显示、录课、视频编码与网络管控等参数。本文按功能分组逐键解析。
> 读取方：`Student.exe` / `Teacher.exe` / `MainLogic.dll` / `MultiClient.exe` 等组件（反编译存档中均出现 `core.conf` 相关引用）
> 分析日期：2026-09-19

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/skin/core.conf` |
| 大小 | 2320 字节（93 行） |
| 类型 | 纯文本配置（`/键/值/` 逐行） |
| 编码 | ASCII，CRLF 换行 |
| MD5 | `aaca4b82cfa6b94834c72dfba9de5819` |
| SHA-256 | `5158c24819530f8c8f1d7766b4ed23962d6fc26b2c4d0e8f29e39a92976c50be` |
| 架构 | 不区分（纯文本配置，全样本树唯一一份） |

---

## 1. 文件性质

`core.conf` 是 Os-Easy 的**公共运行配置**。文件由 93 条 `/键/值/` 记录构成，各组件按**键名**逐条取值，而非解析整体结构。反汇编取证：`Student.exe` 内配置读取函数 `FUN_00403dd0("<Key>")` 以键名字符串为入参返回对应值（例如取 `"Password"`、`"DaasServerPort"` 等）。因此单条记录的取值接口即键名本身，键名是固定契约。

全样本树中仅此一份 `core.conf`（`find` 单命中），无 x86/x64 双版本之分。

---

## 2. 格式规范

- 每行一条记录，格式 `/<键名>/<值>/`，键与值均以 `/` 包裹，行首行尾各一个 `/`。
- 值类型：整数（端口、0/1 开关、质量、像素）、字符串（IP、`h264`/`multicast`/`local`/`info` 等枚举）、十六进制摘要（96-hex）、Base32 串、`$` 分隔的复合串。
- 空值合法（如 `/IpAddressFilter//`）。
- 键名大小写敏感，读取时按原样匹配。
- 部分键名含拼写遗留（`ChannleScanPort`、`NodeManagerIngoreSeconds`），为既有契约，读取方按原样匹配，改名会导致取值失败。

---

## 3. 字段解析（93 键）

> 标注：值为文件实测读取；含义列中〔推断〕为基于键名语义的合理推断，未逐条动态验证。

### 3.1 网络与通信（端口 / IP）

| 键 | 值 | 含义 |
|---|---|---|
| `/AssistIp/` | `0.0.0.0` | 辅助/信令监听地址（0.0.0.0=全接口）〔推断〕 |
| `/RegisterServerIp/` | `0.0.0.0` | 注册/节点管理服务监听地址〔推断〕 |
| `/HomeWorkServerIp/` | `0.0.0.0` | 作业服务监听地址〔推断〕 |
| `/RemoteIp/` | `0.0.0.0` | 远端对端 IP（占位，运行时填充） |
| `/ConnectPort/` | `9003` | 主连接端口〔推断〕 |
| `/RegisterServerPort/` | `8003` | 注册/NodeManager 端口〔推断〕 |
| `/HomeWorkServerPort/` | `80` | 作业服务端口〔推断〕 |
| `/DaasServerPort/` | `443` | DaaS（桌面即服务）服务端口 |
| `/FileNodeManagerPort/` | `8555` | 文件节点管理端口〔推断〕 |
| `/FileReportPort/` | `9979` | 文件上报/进度端口〔推断〕 |
| `/FileTransferPort/` | `9100` | 文件传输端口〔推断〕 |
| `/SharedDeskTopAppBindPort/` | `9101` | 共享桌面应用绑定端口〔推断〕 |
| `/TalkbackServerPort/` | `9001` | 对讲/喊话服务器端口〔推断〕 |
| `/VdiChannelServerPort/` | `8002` | VDI 通道服务器端口〔推断〕 |
| `/MultiCastPort/` | `7778` | 多播（组播）主端口〔推断〕 |
| `/ChannleScanPort/` | `7777` | 信道扫描端口〔推断〕 |
| `/ScreenUdpVerityPort/` | `7788` | 屏幕 UDP 校验端口〔推断〕 |
| `/MacUdpVerityPort/` | `8898` | MAC 层 UDP 校验端口〔推断〕 |
| `/AudioUdpVerityPort/` | `8908` | 音频 UDP 校验端口〔推断〕 |
| `/LocalAudioPort/` | `8889` | 本地音频端口〔推断〕 |
| `/MacroPort/` | `8888` | 宏/广播控制端口〔推断〕 |
| `/UdpMessageControllerPort/` | `8040` | UDP 消息控制端口〔推断〕 |
| `/StudentDemoPort/` | `9201` | 学生演示端口〔推断〕 |
| `/StudentDemoVerityPort/` | `9202` | 学生演示校验端口〔推断〕 |
| `/OuterDataPort/` | `9997` | 外部数据端口〔推断〕 |

端口集中于 `7000` 段与 `8000–9999` 区间，`443` 单独立项用于 DaaS，符合"组播主通道 + 大量点对点校验通道"的教控模型。

### 3.2 身份与安全

| 键 | 值 | 含义 |
|---|---|---|
| `/MD5/` | `RPYUVVPT8V99XN6ZQ6ZUWNUPSXVZZR8X` | 完整性校验值（32 字符 Base32，非标准 MD5 hex）〔推断：配置/包签名〕 |
| `/LissKey/` | `SOFTWARE\LISSClient\liss` | LISS 客户端注册表路径〔推断〕 |
| `/LissValue/` | `InstallPath` | 上表注册表项下的取值键名 |
| `/RegisterType/` | `0` | 注册/激活类型〔推断〕 |
| `/RegisterServerBindingMac/` | `1` | 注册是否绑定 MAC（1=绑定）〔推断〕 |
| `/Password/` | `DA97E410CB7A766DB0189A34EA39CC0DA3B521ED5EFD473581C02866B88E8758043FAE93BA67871F82A1A191198A7755` | 安全密码（96-hex，SHA-384 摘要） |
| `/DaasShutdownPassword/` | `DA97E410CB7A766DB0189A34EA39CC0DA3B521ED5EFD473581C02866B88E8758043FAE93BA67871F82A1A191198A7755` | DaaS 关机/安全退出密码，本样本与 `/Password/` 同值 |
| `/StuInternet/` | `DA97E410CB7A766DB0189A34EA39CC0D8742BFAB48EDC2F7BCDF7585C0C46F46C3504CEE05AC0B3A2A37F4E40E3F643DB6D784A4A43161B597035E53A44B6886` | 学生端网络控制密码，不同摘要 |
| `/bjstConfig/` … `/xfsjConfig/` | `1`×8 | 课程/实验模板开关（bjst/drst/dzqd/jgch/ksjk/ktzy/xfsj + multichannel），0/1 使能位〔推断〕 |

三个密码类键（`/Password/`、`/DaasShutdownPassword/`、`/StuInternet/`）值均为 96-hex，对应 SHA-384 摘要长度；本样本中 `/Password/` 与 `/DaasShutdownPassword/` 同值、`/StuInternet/` 不同值。验证逻辑为"输入 → 摘要 → 与所存 hex 串比对"：学生端托盘退出由 `CSafeQuitDlg`（界面模板 `skin/StuSafePassWord.xml`）触发，`Student.exe` 内 `FUN_004b5460` 读取输入后经 `FUN_00478ae0` 做摘要，与 `FUN_00403dd0("Password")` 取回的串整串比较。`/LissKey/` 与 `/LissValue/` 组合表示从注册表 `HKLM\SOFTWARE\LISSClient\liss\InstallPath` 读取 LISS 模块路径，本文件仅提供"去哪里找"。

### 3.3 显示与布局

| 键 | 值 | 含义 |
|---|---|---|
| `/XScreen/` | `3840` | 逻辑屏宽（像素） |
| `/YScreen/` | `2160` | 逻辑屏高（像素） |
| `/WidthAfterTransform/` | `1024` | 转换后画布宽 |
| `/HeightAfterTransform/` | `576` | 转换后画布高（1024×576，16:9） |
| `/DisplayMode/` | `0` | 显示模式〔推断〕 |
| `/MasterScreen/` | `1` | 主屏使能〔推断〕 |
| `/EachRow/` | `-1` | 每行列数（-1=自动）〔推断〕 |
| `/ChannelSwith/` | `1` | 信道切换使能〔推断〕 |
| `/channel/` | `2` | 信道数/默认信道〔推断〕 |
| `/ShowStuMainDlg/` | `1` | 显示学生主窗体〔推断〕 |
| `/ShowStudentTopWnd/` | `1` | 显示学生置顶窗〔推断〕 |
| `/StuNavPos/` | `0` | 学生导航位置〔推断〕 |
| `/StuNavShow/` | `0` | 学生导航显示（0=隐藏）〔推断〕 |
| `/SortIndex/` | `0` | 排序索引〔推断〕 |
| `/ViewOrder/` | `1` | 视图顺序〔推断〕 |

### 3.4 录课与考试

| 键 | 值 | 含义 |
|---|---|---|
| `/AOVBSaveList/` | `1` | 录课清单保存使能〔推断〕 |
| `/AutoSaveFileRecParams/` | `$1$0$0$1$0$0$0$1$$0$10$` | 自动保存参数（`$` 分隔位串） |
| `/AutoSaveFileRecSet/` | `0` | 自动保存设置〔推断〕 |
| `/ExamDebug/` | `0` | 考试调试开关 |
| `/ExamFileTransferType/` | `1` | 考试文件传输类型〔推断〕 |
| `/Limit/` | `1` | 限速/限流使能〔推断〕 |
| `/LimitFileSize/` | `0` | 文件体积限制（0=不限）〔推断〕 |
| `/SaveLastCallInfo/` | `0` | 保存上次呼叫信息〔推断〕 |
| `/SaveModel/` | `1` | 保存模型/布局〔推断〕 |
| `/SelectModel/` | `1` | 选择模型〔推断〕 |
| `/SelectShow/` | `0` | 选择显示〔推断〕 |

### 3.5 视频与音频编码

| 键 | 值 | 含义 |
|---|---|---|
| `/CompressMode/` | `h264` | 视频压缩编码 |
| `/H264GoSize/` | `5` | H.264 码流尺寸档位〔推断〕 |
| `/H264Quality/` | `26` | H.264 质量档〔推断〕 |
| `/JpegQuality/` | `70` | JPEG 截图质量（0–100） |
| `/NeedVideoTechTransform/` | `0` | 是否做视频技术转换〔推断〕 |
| `/BkAudioVirtualDevice/` | `0` | 虚拟音频设备回环〔推断〕 |
| `/Curiptype/` | `0` | 光标/捕获类型〔推断〕 |

### 3.6 网络管控与行为策略

| 键 | 值 | 含义 |
|---|---|---|
| `/IpAddressFilter/` | （空） | IP 过滤（空=未启用）〔推断〕 |
| `/IpProto/` | `0` | IP 协议过滤类型〔推断〕 |
| `/LockedAfterNetBroken/` | `0` | 断网后是否锁屏（0=否）〔推断〕 |
| `/LockSeat/` | `0` | 锁位/锁机〔推断〕 |
| `/UsingHttps/` | `1` | 启用 HTTPS（配合 `/DaasServerPort/443`） |
| `/TransferType/` | `multicast` | 传输方式：多播/组播 |
| `/VirtualMachineType/` | `local` | 虚拟机类型：本地 |
| `/OnceConfigIp/` | `1` | 一次性 IP 配置〔推断〕 |
| `/NodeManagerIngoreSeconds/` | `10` | 节点管理忽略秒数〔推断〕 |
| `/RemoteAutoCount/` | `6` | 远端自动计数〔推断〕 |
| `/MtuCountWillWait/` | `10` | MTU 计数等待〔推断〕 |
| `/WaitSeconds/` | `80` | 等待秒数 |
| `/GeneralEducation/` | `0` | 普教模式开关〔推断〕 |
| `/TemplateShare/` | `0` | 模板共享〔推断〕 |
| `/AutoHideTools/` | `0` | 自动隐藏工具栏〔推断〕 |
| `/StuAutoStart/` | `1` | 学生端自启〔推断〕 |
| `/LogLevel/` | `info` | 日志级别 |

---

## 4. 端口汇总

| 端口 | 协议倾向 | 对应键 |
|---|---|---|
| 80 | TCP | `/HomeWorkServerPort/` |
| 443 | TCP/TLS | `/DaasServerPort/` |
| 7777 | UDP | `/ChannleScanPort/` |
| 7778 | UDP | `/MultiCastPort/` |
| 7788 | UDP | `/ScreenUdpVerityPort/` |
| 8002 | TCP | `/VdiChannelServerPort/` |
| 8003 | TCP | `/RegisterServerPort/` |
| 8040 | UDP | `/UdpMessageControllerPort/` |
| 8555 | TCP | `/FileNodeManagerPort/` |
| 8888 | TCP | `/MacroPort/` |
| 8889 | TCP | `/LocalAudioPort/` |
| 8898 | UDP | `/MacUdpVerityPort/` |
| 8908 | UDP | `/AudioUdpVerityPort/` |
| 9001 | TCP | `/TalkbackServerPort/` |
| 9003 | TCP | `/ConnectPort/` |
| 9100 | TCP | `/FileTransferPort/` |
| 9101 | TCP | `/SharedDeskTopAppBindPort/` |
| 9201 | TCP | `/StudentDemoPort/` |
| 9202 | TCP/UDP | `/StudentDemoVerityPort/` |
| 9979 | TCP | `/FileReportPort/` |
| 9997 | TCP/UDP | `/OuterDataPort/` |

---

## 5. 关键结论

1. **公共单文件配置**：93 条记录由所有组件共享读取，按键名取值，键名为固定契约。
2. **明文可读**：无加密/混淆，端口、显示、编码等参数均为直接文本值。
3. **摘要类字段**：`/Password/`、`/DaasShutdownPassword/`、`/StuInternet/` 为 96-hex（SHA-384），`/MD5/` 为 32 字符 Base32，均非明文。
4. **注册表外链**：LISS 模块路径来自 `HKLM\SOFTWARE\LISSClient\liss\InstallPath`，非本文件所载。
5. **拼写遗留**：`ChannleScanPort`、`NodeManagerIngoreSeconds` 等键名拼写为既有契约，不得"纠正"。

---

*本文覆盖：core.conf 93 键逐条解析（网络/身份安全/显示/录课/编码/管控分组）、格式规范、端口汇总、读取机制（`FUN_00403dd0` 按键取值）。字段值为实测读取，〔推断〕项为键名语义推断。*