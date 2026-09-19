# LissHelper.exe 组件深度逆向（LISS/TCloud 平台 CLI 分发器）

> 样本：`samples/os-easy/LissHelper.exe`（185856 字节，PE32 i386 **console**）
> PDB：`D:\dmt\master\10.9\Output\Release\LissHelper.pdb`（V10.9 构建）
> 反编译：Ghidra 12.1.3 headless，1092 函数，存档 `/root/ghidra/mmpc/lisshelper_x86.txt`

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/LissHelper.exe` |
| 大小 | 185856 字节 |
| 架构/类型 | PE32 i386 console（LISS/TCloud SDK CLI） |
| MD5 | `85cd3471e9919187970b74f687edd89e` |
| 内嵌 PDB | `D:\dmt\master\10.9\Output\Release\LissHelper.pdb`（V10.9） |

## 1. 定位与职责

**LISS（TCloud / 腾讯课堂云平台）SDK 的命令行前端**。本身无业务逻辑，是一个**一次性 console 进程**：接收一段 **JSON 命令行**（`type` + 参数），**动态加载 `LISSClientSDK.dll`** 并调用对应 `LISS_SDK_*` 函数，把 `success`/`failed` 结果写回后退出。

它把"调用云 SDK"这件事从宿主进程（Teacher.exe / Student.exe）里**剥离成独立进程**——宿主（见 MultiClient/StudentLogic/Teacher 各自的 `initLissHelper`）要么直接内嵌 SDK，要么在需要时 `CreateProcess LissHelper.exe <json>` 走本进程。学生端 `Student.exe` 启动时拉起 `LissHelper.exe`（见 Student_exe.md §5）。

导入极简：KERNEL32 + ADVAPI32（注册表）+ OLEAUT32 + WS2_32 + 静态 **jsoncpp**（解析命令行 JSON）。

## 2. SDK 加载（`initLissHelper` = `FUN_004113b0`）

```
if (DAT_0042b05c 未初始化):
  RegOpenKeyExW(HKLM, L"SOFTWARE\\LISSClient\\liss")
  RegQueryValueExW(key, L"InstallPath")          // 云客户端安装路径
  lissPath = InstallPath + (is64bit ? "sdk\\x64\\" : "sdk\\x86\\")
  日志 [initLissHelper] lissPath:%s
  SetCurrentDirectoryW → LoadLibraryW("LISSClientSDK.dll") → 还原目录
  成功: [initLissHelper] hMod SUCCESS / 失败: hMod failed[%d]!
  GetProcAddress × 7:
    LISS_SDK_InitIntance / FreeIntance / IsLoginUiGoingToShow /
    IsSupportMMCStrategy / SendBroadcastTypeInternal /
    SendMMCMonitorKeywordFilePath / SendMMCStopStrategy
    → 存入 DAT_0042c5xx 函数指针表
返回: SDK 是否加载成功
```

与 Teacher.exe / StudentLogic.dll 内的 `initLissHelper` **完全同一套逻辑**（注册表 `SOFTWARE\LISSClient\liss\InstallPath` + `sdk\x86|64\` + 7 个 SDK 函数）——三处是同一 SDK 的三份加载器。

## 3. type 命令分发（主函数 `FUN_0040bf20` 区，`[LissHelper] type:%s`）

命令行解析为 JSON 后按 `type` 字符串（`FUN_00406c60` 逐字节比较）分发：

| type | 读取参数 | 动作 | 对应 SDK |
|---|---|---|---|
| `support-use-device-control` | — | 查询 MMC 管控能力位 | `LISS_SDK_IsSupportMMCStrategy` → 输出 `process:%d device:%d network:%d traffic%d`（`[SupportUseDeviceControl] ret:%d support:%d`） |
| `send-broadcast-type` | `broadcasttype` + `start` | 下发广播类型 | `LISS_SDK_SendBroadcastTypeInternal` |
| `can-broadcast` | — | 能否广播（登录 UI 是否显示中） | `LISS_SDK_IsLoginUiGoingToShow` → `success`/`failed` |
| `check-liss-sdk` | — | SDK 是否可用 | `FUN_004113b0()` → `success`/`failed` |
| `stop-device-control` | `stopnetworktraffic` / `stopnetwork` / `stopdevice` / `stopprocess` | 四类管控开关（4 个 bool） | `LISS_SDK_SendMMCStopStrategy(4 bool)`；无 SDK 时 `[StopDeviceControl] No LissSDK`，有则 `[StopDeviceControl] %d:%d:%d:%d` |
| `start-lissNet` | `ip` + `mac` + `filepath` | 启动网络信息嗅探 | 先 Toolhelp 枚举**杀掉已运行的 `LISSNetInfoSniffer.exe`** → `CreateProcess "x86\\LISSNetInfoSniffer.exe <ip> <mac> <filepath>"`（`start-lissnet:%s`） |

其余已知 type 词：`device` / `network` / `networktraffic` / `stopdevice` / `stopnetwork` / `stopprocess`（均为 stop-device-control 的参数键或细分开关）。

结果回写：`success`/`failed` 字符串经 `FUN_00407080`（输出封装，带长度/缓冲区参数）写回——console 进程 stdout 或约定的返回通道。

## 4. 与 DeviceControl / 管控体系的关系

`stop-device-control` + `support-use-device-control` 表明 **LISS/TCloud 平台本身带一套"MMC 策略"管控**（进程/设备/网络/流量四维度），与本地自研的 `DeviceControl.exe` + 各 `.sys`（ProcFireWall/easyusbflt/KbFilter/OeNetLimit）是**两套并行的管控**：
- **本地自研驱动链**：Teacher→DeviceControl→.sys（离线可用，已在各驱动报告闭环）；
- **LISS 云平台策略**：经 `LISS_SDK_*` 走 TCloud 云端下发（依赖云客户端安装，`SOFTWARE\LISSClient\liss`）。

教师端 Teacher.exe 的 `[StopDeviceControl]`/`[SupportUseDeviceControl]`/`[CanUseDeviceControl]` 日志（见 Teacher_exe.md §6）即经本路径（LissHelper.exe 或内嵌 SDK）调用。

## 5. 体系位置

```
Teacher.exe / Student.exe / MultiClient / StudentLogic
  └─ 内嵌 initLissHelper (LoadLibrary LISSClientSDK.dll, 同套逻辑)
     或按需 CreateProcess:
  → LissHelper.exe <json: {type, ...}>   (console, 一次性)
       → HKLM\SOFTWARE\LISSClient\liss\InstallPath\sdk\x86|64\
       → LoadLibrary(LISSClientSDK.dll) → LISS_SDK_*
       → 写回 success/failed
       → (start-lissNet 时) 拉起 LISSNetInfoSniffer.exe <ip> <mac> <filepath>
     ⇄ TCloud 云平台 (登录 UI / MMC 策略 / 广播 / 监控)
```

## 6. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `FUN_004113b0` | initLissHelper（注册表读 InstallPath + LoadLibrary LISSClientSDK.dll + GetProcAddress ×7） |
| `FUN_0040bf20` 区（11340 行起） | 主命令分发（type 字符串逐字节比较 → 各分支） |
| `FUN_00406c60` | 字符串相等比较（type 匹配） |
| `FUN_0040db20` | can-broadcast 判定（IsLoginUiGoingToShow） |
| `FUN_00407080` | 结果字符串回写 |
| `FUN_0040d9c0` | 日志（`[LissHelper] type:%s` 等） |
| `DAT_0042c53c/0042c554` | SDK 句柄 / LISS_SDK_* 函数指针表 |

## 7. 未决项

1. `LISSClientSDK.dll` 本体未逆向（云 SDK 黑盒，本报告仅到"调用边界"）；
2. `start-lissNet` 的 `filepath` 具体含义（监控关键词文件？网络快照目录？）；
3. 结果回写通道（stdout vs 命名管道/文件）——console 进程，推测 stdout + 退出码；
4. `can-broadcast` 与教师端广播权限（TCloud 登录态）的关联。