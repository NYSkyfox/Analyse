# MultiClient.exe - 深度分析报告

## 📋 基本信息

| 项目 | 详情 |
|------|------|
| **文件名** | MultiClient.exe |
| **文件大小** | 1.2 MB |
| **文件类型** | PE32 executable (GUI) Intel 80386 |
| **架构** | x86 32位 |
| **入口点** | 0x004dc97a |
| **编译器** | Visual Studio 2015 (MSVC140) |
| **分析耗时** | 115 秒 |
| **分析状态** | ✅ 完成 |

## 🔧 技术栈分析

### 开发框架
- **C++ STL** (std::string, std::vector, iostream)
- **Boost.Beast** - WebSocket 库 (版本 2.90)
- **Boost.Asio** - 异步 I/O 网络库
- **Windows MFC/Win32 API**

### 核心依赖库

#### 系统库
```
KERNEL32.dll    - Windows 核心 API
USER32.dll      - 窗口管理和消息处理
SHELL32.dll     - Shell 功能
OLEAUT32.dll    - COM 自动化
```

#### 运行时库
```
MSVCP140.dll      - Visual C++ 2015 C++ 标准库
VCRUNTIME140.dll  - Visual C++ 2015 运行时
api-ms-win-crt-*.dll - Universal CRT (ucrt)
```

#### 网络库
```
WS2_32.dll      - Windows Socket 2.0
IPHLPAPI.DLL    - IP Helper API (网络适配器信息)
```

## 🌐 网络通信分析

### WebSocket 通信

MultiClient.exe 使用 **Boost.Beast WebSocket** 进行通信：

```cpp
// 发现的关键字符串
"boost.beast.websocket"
"Boost.Beast/290"
"server_max_window_bits"
"server_no_context_takeover"
"websocket resolve coroutine failed:%s"
"websocket read coroutine failed:%s"
```

### 网络功能

1. **Socket 操作**
   - `socket()` - 创建套接字
   - `connect()` - 连接服务器
   - `send()` / `recv()` - 数据收发
   - `select()` - I/O 多路复用

2. **适配器枚举**
   ```cpp
   GetAdaptersAddresses() - 获取网络适配器信息
   GetAdaptersInfo()      - 获取适配器详细信息
   ```

3. **连接管理**
   ```
   connectIp:%s, studentIp:%s
   Connect to %s
   socket INVALID_SOCKET
   The socket was closed due to a timeout
   ```

### 支持的网络协议

- **WebSocket** (主要通信协议)
- **TCP/IP**
- **HTTP/HTTPS** (通过 WebSocket 握手)
- **IPv4/IPv6** (inet_pton/inet_ntop)

## 🔍 核心功能识别

### 1. 多客户端管理

```cpp
// 关键字符串
"connectip"
"test1604 connectIp:%s, studentIp:%s,bInVdiWindowClient:%d"
"send-broadcast-type"
"recv fullscreen: %d"
"recv pmgb"  // 可能是 "屏幕广播" 的缩写
"recv qygb"  // 可能是 "请求广播" 的缩写
```

### 2. 设备控制

```cpp
"[CanUseDeviceControl] ret:%d,support:%d"
"[SupportUseDeviceControl] ret:%d support:%d"
"[SupportUseDeviceControl] process:%d device:%d network:%d traffic%d"
"[SupportUseDeviceControl] No LissSDK"
```

可能支持的控制类型：
- 进程控制
- 设备控制
- 网络控制
- 流量控制

### 3. 屏幕广播

```cpp
"recv fullscreen: %d"
"AudioRender.exe"  // 音频渲染程序
"Barrage" / "BarrageExit" / "BARRAGE start" // 弹幕功能
```

### 4. 桌面切换

```cpp
// USER32.dll 导入的函数
OpenDesktopW()      - 打开桌面
OpenDesktopA()      - 打开桌面 (ANSI)
CreateDesktopA()    - 创建桌面
GetThreadDesktop()  - 获取线程桌面
SwitchDesktop()     - 切换桌面
OpenInputDesktop()  - 打开输入桌面
```

### 5. 钩子注入

```cpp
SetWindowsHookExW()     - 安装钩子
UnhookWindowsHookEx()   - 卸载钩子
CallNextHookEx()        - 调用下一个钩子
```

## 📊 Ghidra 分析统计

### 分析器耗时分布

```
Decompiler Parameter ID              34.639 秒  (最耗时)
Stack Analysis                       13.975 秒
Decompiler Switch Analysis           10.478 秒
Function ID                          10.070 秒
x86 Constant Reference Analyzer      10.661 秒
Windows x86 PE Exception Handling     6.801 秒
Windows x86 PE RTTI Analyzer          3.926 秒
Decompiler Switch Analysis            3.396 秒
Scalar Operand References             3.231 秒
Create Function                       2.322 秒
Disassemble                           2.858 秒
其他分析器                           < 2 秒

总耗时: 115 秒
```

### 代码特征

- ✅ **异常处理**: Windows SEH (Structured Exception Handling)
- ✅ **RTTI**: C++ 运行时类型信息
- ✅ **虚函数**: 大量 C++ 类和虚函数表
- ⚠️ **PDB 缺失**: 无符号文件，需要手动逆向

## 🛡️ 安全分析

### 潜在安全问题

#### 1. 网络通信安全

⚠️ **WebSocket 连接可能未加密**
```
- 未发现 SSL/TLS 相关字符串
- 可能使用明文 WebSocket (ws://) 而非 wss://
- 建议抓包验证加密情况
```

#### 2. 权限提升风险

⚠️ **桌面切换和钩子注入需要较高权限**
```cpp
CreateDesktopA()        // 创建桌面需要管理员权限
SetWindowsHookExW()     // 全局钩子需要特权
```

#### 3. 远程控制能力

⚠️ **可能被滥用于远程监控**
```
- 屏幕广播
- 设备控制
- 进程控制
- 网络流量控制
```

### 推荐的深入分析方向

#### 1. 网络协议逆向

```bash
# 在 Ghidra 中搜索这些函数
- WSAStartup
- socket
- connect
- send/recv
- websocket handshake 相关代码
```

**目标**:
- 确定 WebSocket 消息格式
- 查找加密/认证机制
- 识别命令协议

#### 2. 命令处理分析

搜索关键字符串:
```
"recv pmgb"
"recv qygb"
"send-broadcast-type"
"connectip"
```

**目标**:
- 找到命令解析函数
- 识别所有支持的命令类型
- 分析命令执行流程

#### 3. 配置文件分析

```cpp
"ConfigHelper::GetConfigValue:RegisterType [%d]"
```

**目标**:
- 查找配置文件路径
- 分析配置格式
- 查找硬编码的服务器地址

#### 4. 认证机制分析

**目标**:
- 查找登录/认证相关函数
- 分析密码存储方式
- 检查会话管理机制

## 🔧 使用 Ghidra 进行深入分析

### 启动 Ghidra GUI

```bash
# 方法1: 在有图形界面的机器上
ghidraRun
# File → Open Project → /root/ghidra/projects/os-easy-analysis
# 然后打开 MultiClient.exe

# 方法2: 使用 VNC 连接到服务器
# 连接 45.207.220.121:5900
# 在桌面启动 Ghidra
```

### 关键分析点

#### 1. 查找入口点

```
地址: 0x004dc97a
在 Ghidra 中按 G 键跳转到该地址
```

#### 2. 搜索字符串引用

```
Search → For Strings...
过滤关键词: websocket, connect, send, recv
右键 → References → Show References to Address
```

#### 3. 分析函数调用图

```
选中函数 → Graph → Function Call Graph
```

#### 4. 导出反编译代码

```
Window → Decompile
右键 → Copy C Code
```

## 📦 相关文件

### Os-Easy 系统组件

```
Teacher.exe       - 教师控制端 (已分析)
Student.exe       - 学生接收端 (已分析)
MultiClient.exe   - 多客户端管理器 (当前文件)
AudioRender.exe   - 音频渲染器
VideoTechConsole.exe - 视频技术控制台
FileTransferApp.exe  - 文件传输程序
```

### 推荐分析顺序

1. ✅ Teacher.exe - 了解服务端架构
2. ✅ Student.exe - 了解客户端协议
3. ✅ MultiClient.exe - 了解多客户端管理 (当前)
4. ⏭️ AudioRender.exe - 分析音频传输
5. ⏭️ VideoTechConsole.exe - 分析视频传输

## 🎯 下一步行动建议

### 立即可做

1. **在 Ghidra 中打开 MultiClient.exe**
   - 查看反编译代码
   - 分析主函数流程
   - 识别关键类和函数

2. **搜索关键函数**
   ```
   - WebSocket 握手函数
   - 命令处理函数
   - 配置读取函数
   ```

3. **对比三个程序**
   - Teacher.exe vs Student.exe vs MultiClient.exe
   - 找出共用的网络协议库
   - 识别协议差异

### 需要环境支持

1. **动态调试**
   - 使用 x64dbg / WinDbg
   - 设置断点在关键函数
   - 观察运行时行为

2. **网络抓包**
   - Wireshark 捕获 WebSocket 流量
   - 分析消息格式
   - 验证加密情况

3. **模拟环境测试**
   - 搭建教学系统测试环境
   - 观察实际通信行为
   - 测试各种命令

## 📝 总结

MultiClient.exe 是 Os-Easy 多播教学系统的**客户端管理组件**，主要功能包括：

✅ **核心能力**
- WebSocket 网络通信
- 多客户端连接管理
- 屏幕广播接收
- 设备控制支持
- 桌面切换和钩子注入

⚠️ **安全关注点**
- 可能使用明文通信
- 需要较高系统权限
- 具有远程控制能力
- 缺少符号文件增加分析难度

🔍 **分析完整度: 70%**
- ✅ 基本信息收集完成
- ✅ 依赖库识别完成
- ✅ 核心功能识别完成
- ⏳ 协议细节待深入
- ⏳ 认证机制待分析
- ⏳ 漏洞挖掘待进行

---

**分析时间**: $(date '+%Y-%m-%d %H:%M:%S')
**分析工具**: Ghidra 12.1.3 + objdump + strings
**项目路径**: /root/ghidra/projects/os-easy-analysis
