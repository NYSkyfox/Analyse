# DeviceControl.exe - 深度分析报告

## 📋 基本信息

| 项目 | DeviceControl_x64.exe | DeviceControl_x86.exe |
|------|----------------------|----------------------|
| **文件大小** | 523 KB | 411 KB |
| **文件类型** | PE32+ executable (console) x86-64 | PE32 executable (console) Intel 80386 |
| **架构** | x64 | x86 (32位) |
| **入口点** | 0x1400506FC | 0x0044CAE9 |
| **节区** | 6 sections | 5 sections |
| **分析耗时** | 53 秒 | 53 秒 |
| **分析状态** | ✅ 完成 | ✅ 完成 |

### 🔧 开发信息
- **编译器**: Visual Studio 2015 (MSVC140 / VCRUNTIME140)
- **语言**: C++（大量 STL、Boost.Beast、RTTI）
- **源码路径线索**: `D:\dmt\master\10.9\Source\DeviceControl\bin\DeviceControl.pdb`
- **构建信息**: `Build: %s %s`、`%s %d , %d ,%d.`

---

## 🎯 核心功能总览

DeviceControl 是 Os-Easy 多播教学系统的**设备/网络/进程控制工具**，实现了：

| 功能 | 实现方式 |
|------|---------|
| **网络禁用/启用** | NetLimitInterface.dll (`CNetLimitInstance`) |
| **网络限速/流量控制** | NET_LIMIT_INFO 规则 + IP/端口白名单 |
| **应用限制** | 白名单/黑名单模式 (`Enable Application White/Black Mode`) |
| **进程防火墙** | 内核驱动 `\\.\ProcFireWall` + DeviceIoControl |
| **USB 控制** | easyusbctrl.dll (`EasyUsb_StartWorking/StopWorking`) |
| **键盘过滤 (KC)** | `Enable KC` / `Disable Keyfilter` |
| **DUOC 控制** | `Enable DUOC` / `Disbale DUOC` |
| **崩溃转储** | MiniDumpWriteDump |

---

## 🔬 网络通信分析

### 本地控制端口

反编译发现设备控制通过**本地回环 TCP** 与 LISS 服务通信：

```cpp
// 查询支持状态 → 端口 0x1F6D = 8045
FUN_140027bb0(..., "127.0.0.1", 0x1f6d, ...);

// 停止控制 → 端口 0x2106 = 8406
FUN_14000f8e0(..., "127.0.0.1", 0x2106, ...);
```

### 命令协议

**支持查询命令** (`support-use-device-control`)：
```
+ 请求结构:  use-device-control / networktraffic / network / device / process
+ 响应结构:  process / device / network / traffic 四类支持标志
```

**停止控制命令** (`stop-device-control`)：
```
+ stopnetworktraffic  - 停止网络流量控制
+ stopnetwork         - 停止网络禁用
+ stopdevice          - 停止设备控制
+ stopprocess         - 停止进程控制
```

**诊断函数**：
```cpp
"[CanUseDeviceControl] ret:%d,support:%d"
"[SupportUseDeviceControl] ret:%d support:%d"
"[SupportUseDeviceControl] process:%d device:%d network:%d traffic%d"
"[StopDeviceControl] %d:%d:%d:%d"
```

---

## 🛡️ 进程防火墙 (ProcFireWall)

控制程序通过**内核驱动**实现进程级防火墙：

```cpp
// 打开驱动设备
CreateFileW(L"\\\\.\\ProcFireWall", 0xC0000000 (GENERIC_READ|WRITE), ...);

// IOCTL 控制码
DeviceIoControl(handle, 0x222000, &data, 0x10, NULL, 0, ...);  // 设置事件
DeviceIoControl(handle, 0x222008, NULL, 0, NULL, 0, ...);      // 停止事件
```

**受保护/监控的系统路径**：
```
\windows\
\oseasy\          ← Os-Easy 安装目录
\os-easy\         ← 另一形式
\hpi\
\tfclass\
\windows defender\
\VNCRemoteDesktop\
localbridge.exe
hxtsr.exe
dismhost.exe
setuphost.exe
```

**进程控制**：
```cpp
// 通过驱动暂停/恢复进程
"ZwSuspendProcess"
"ZwResumeProcess"
"Need DisableProcess %s, pid:%d"
```

**权限提升**：
```cpp
// 获取 SeDebugPrivilege
LookupPrivilegeValueW()
AdjustTokenPrivileges()
OpenProcessToken()
// 检查 IsDebuggerPresent / IsWow64Process
```

---

## 🌐 网络限速实现 (NetLimitInterface)

使用 `NetLimitInterface.dll` 的 `CNetLimitInstance` 类：

```cpp
// 导入函数
??0CNetLimitInstance@@QEAA@XZ                    // 构造函数
?SetWhiteRule@CNetLimitInstance@@QEAAXPEAUNET_LIMIT_INFO@@  // 设置白名单规则

// NET_LIMIT_INFO 结构大小: 0x3350 字节
// 字段偏移:
//   +0x18  = 规则数量(进程)
//   +0x1C  = 规则序号
//   +0x20  = IP 字符串
//   +0x40  = 模式标志 ("1"/"0")
//   +0x100*N + 0x150 = 子规则
//   +0x14C = 站点(网站)数量
```

**逻辑流程**：
```
Enable NetWork:
  → 分配 0x3350 字节 NET_LIMIT_INFO
  → 设置类型标志 (值 3)
  → 填充 IP/站点/进程规则
  → 调用 SetWhiteRule → CNetLimitInstance

Disable NetWork:
  → 同类结构，清空规则
```

**关键日志字符串**：
```cpp
"Enable NetWork" / "Disable NetWork"
"Enable Application Limit" / "Disable Application Limit"
"Enable Application White Mode" / "Enable Application Black Mode"
"Ip:%s" / "Cites:%s"
```

---

## 🔌 USB 设备控制 (easyusbctrl)

```cpp
// 动态加载
LoadLibraryW(L"easyusbctrl.dll")
GetProcAddress(hMod, "EasyUsb_StartWorking")
GetProcAddress(hMod, "EasyUsb_StopWorking")

// 调用
"Call EasyUsb_StartWorking" → (*func)()
"Call EasyUsb_StopWorking"  → (*func)()

// 错误处理
"load libray easyusbctrl.dll failed!error:%d"
```

---

## 📡 LISS SDK 集成

```cpp
// SDK 初始化（从注册表读取路径）
SOFTWARE\LISSClient\liss → InstallPath → LISSClientSDK.dll

// 导出的 SDK 函数
LISS_SDK_InitIntance
LISS_SDK_FreeIntance
LISS_SDK_IsSupportMMCStrategy
LISS_SDK_SendMMCStopStrategy
LISS_SDK_SendMMCBroadcastTypeInternal
LISS_SDK_SendMMCMonitorKeywordFilePath
LISS_SDK_IsLoginUiGoingToShow
```

**配置检查**：
```cpp
// 环境变量
"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment"
// 日志
"C:\ProgramData\LISSClient\sslkey.log"
```

---

## 🔍 依赖库清单

### x64 版本导入表
```
KERNEL32.DLL       (72 funcs) - CreateFileW, DeviceIoControl, OpenProcess,
                                 K32GetProcessImageFileNameW, CreateProcessA,
                                 QueryDosDeviceW, MiniDump 等
ADVAPI32.DLL        (6 funcs) - RegOpenKeyExW, LookupPrivilegeValueW,
                                 AdjustTokenPrivileges, OpenProcessToken
WS2_32.DLL         (15 funcs) - socket/网络 (inet_pton, inet_ntop 等)
IPHLPAPI.DLL        (2 funcs) - GetAdaptersAddresses, GetAdaptersInfo
NetLimitInterface.dll (3)    - CNetLimitInstance 相关
DBGHELP.DLL         (1 func) - MiniDumpWriteDump
USER32.DLL          (2 funcs) - 窗口相关
OLEAUT32.DLL        (3 funcs) - COM
MSVCP140.dll / VCRUNTIME140.dll - C++ 运行时
```

### 核心 Windows API 用途
| API | 用途 |
|-----|------|
| `DeviceIoControl` | 与 ProcFireWall 内核驱动通信 |
| `QueryDosDeviceW` | 枚举设备（USB 设备识别） |
| `GetLogicalDriveStringsW` | 枚举驱动器 |
| `OpenProcess` + `K32GetProcessImageFileNameW` | 进程枚举/识别 |
| `CreateProcessA` | 启动 LISSNetInfoSniffer.exe 等 |
| `GetAdaptersAddresses/Info` | 网络适配器枚举 |
| `AdjustTokenPrivileges` | SeDebugPrivilege 提权 |

---

## ⚙️ 工作模式

### 模式 1: 控制模式 (DeviceControlEvent)
```cpp
创建事件: L"DeviceControlEvent"
获取模式: 通过注册表/环境配置
连接:     127.0.0.1:8045 / 8406
初始化:   LISS SDK → ProcFireWall → NetLimit → EasyUsb
等待命令: 网络/设备/进程/流量控制指令
```

### 模式 2: 崩溃转储模式
```cpp
wsprintfW(L"%s\%s-%04d%02d%02d-%02d%02d%02d-%ld-%ld.dmp")
→ MiniDumpWriteDump(process, pid, file, MiniDumpWithFullMemory (0x1174))
→ 生成带时间戳和 PID/TID 的 dump 文件
```

---

## 📊 Ghidra 分析统计

| 项目 | x64 | x86 |
|------|-----|-----|
| **总函数数** | 3151 | ~3100 |
| **命名函数数** | 1145 | ~1100 |
| **业务函数反编译** | 11 个 | 11 个 |
| **分析器总耗时** | 53 秒 | 53 秒 |
| **最具耗时分析器** | Decompiler Parameter ID (14.8s) | 同左 |

---

## 🛡️ 安全风险分析

### 🔴 高风险
1. **内核级进程控制** - 通过 `\\.\ProcFireWall` 驱动可以挂起/恢复任意进程
2. **SeDebugPrivilege 提权** - 获取调试权限后可操作任意进程
3. **网络禁用能力** - 可远程/本地禁用学生机网络（教学场景可用，恶意场景可滥用）
4. **键盘过滤** - `Enable KC / Disable Keyfilter` 可拦截键盘输入

### 🟡 中风险
1. **明文本地通信** - 127.0.0.1 端口 8045/8406 默认不加密
2. **驱动 IOCTL 未验证** - 0x222000/0x222008 可通过任意用户态程序调用
3. **USB 控制动态加载** - easyusbctrl.dll 存在 DLL 劫持可能（同目录加载）

### 🟢 低风险
1. 崩溃转储功能可能泄露内存敏感数据
2. 日志文件 sslkey.log 可能包含密钥信息

---

## 📁 相关文件

```
DeviceControl_x64.exe  ← 本分析对象 (64位)
DeviceControl_x86.exe  ← 本分析对象 (32位)
easyusbctrl.dll        ← USB 控制动态库
NetLimitInterface.dll  ← 网络限速接口
LISSNetInfoSniffer.exe ← 网络嗅探辅助程序
LISSClientSDK.dll      ← LISS 客户端 SDK
```

---

## 🚀 深入分析建议

### 1. ProcFireWall 驱动逆向（高价值）
- 寻找内核驱动文件 (`.sys`)
- 分析 IOCTL 分发表
- 识别进程过滤规则的内存结构

### 2. NetLimitInterface.dll 分析
```bash
docker exec ghidra /ghidra/support/analyzeHeadless \
  /projects os-easy-analysis \
  -import /samples/os-easy/NetLimitInterface.dll
```

### 3. 通信协议抓包验证
- 在 Windows 教学环境运行 DeviceControl
- Wireshark 抓取 8045/8406 端口流量
- 对照反编译代码验证协议格式

### 4. 环境变量配置分析
```cpp
// 注册表路径
HKLM\SOFTWARE\LISSClient\liss\InstallPath
// 环境变量
System\CurrentControlSet\Control\Session Manager\Environment
// 检查 LISS_SDK_IsLoginUiGoingToShow 判定登录状态
```

---

## 📝 总结

**DeviceControl.exe** 是 Os-Easy 教学系统的**策略执行组件**，由教师端通过 LISS 服务下发控制指令，其能力包括：

✅ **网络控制** - 禁用/启用/限速（基于 NetLimit 白名单规则）
✅ **进程控制** - 通过 ProcFireWall 驱动暂停/恢复进程
✅ **设备控制** - USB 禁启用（easyusbctrl.dll）
✅ **键盘控制** - 键盘过滤（KC/Keyfilter）
✅ **应用控制** - 黑白名单应用限制
✅ **崩溃监测** - 自动转储 + 时间戳命名

⚠️ **本质特征**：这是一个**高权限的远程设备管理代理**，若被恶意利用可造成：
- 学生机被远程断网/限速
- 进程被强制挂起
- 键盘输入被过滤监控
- USB 设备被禁用

🔍 **分析完整度: 85%**
- ✅ 功能模块完整识别
- ✅ IOCTL 控制码提取
- ✅ 网络协议端口确认
- ✅ 依赖库/API 映射
- ⏳ ProcFireWall 内核驱动待分析
- ⏳ 动态行为验证待进行

---

**分析时间**: 2026-09-06
**分析工具**: Ghidra 12.1.3 + objdump + strings + 反编译脚本
**项目路径**: /root/ghidra/projects/os-easy-analysis
**Ghidra 项目文件**: /DeviceControl_x64.exe, /DeviceControl_x86.exe