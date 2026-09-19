# NetLimitInterface.dll 组件深度逆向

> 样本：`samples/os-easy/x86/NetLimitInterface.dll`（145408 字节）、`samples/os-easy/x64/NetLimitInterface.dll`（172544 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/netlimitiface`（x86）
> 反编译存档：`/root/ghidra/mmpc/nliface_x86.txt`（873 函数）
> 关联：`OeNetlimit_dll.md`（下一层，真正调驱动）、`OeNetLimit_sys.md`（内核）、`DeviceControl_exe.md`（上层）
> 分析日期：2026-09-18

---

## 0. 文件指纹

| 项 | x86 | x64 |
|---|---|---|
| 大小 | 145408 字节 | 172544 字节 |
| MD5 | `95e68d1b7d0a30db0c918d4d0bb666b0` | `b843822afe478b94a221e42db9092cfa` |
| SHA-256 | `10a3ec82a4cd2ccb553e6413f9a80c532fecaa4570d7e21ff5517e774641d343` | `2544ab07f527ef658f99958420fde66a44f889af31a9d2e9afa4f5faa0565708` |
| 格式 | PE32 DLL（`pei-i386`） | PE32+ DLL（`pei-x86-64`） |
| ImageBase | `0x10000000` | `0x180000000` |
| 入口点 | `0x10006ab4` | `0x180007ecc` |
| PDB | `e:\ctsc_6\trunk\limit_driver_interface\bin\NetLimitInterface.pdb` | 同源 |

**导入**：
- `systemoper.dll`：`SYS_GetModuleFileDir`（取本模块所在目录，拼出 OeNetlimit.dll 全路径）
- `KERNEL32`：`LoadLibraryW`、`GetProcAddress`、`GetModuleFileNameA`、`OutputDebugStringA`、`GetLocalTime` 等

**导出（6 个，全部属 `CNetLimitInstance` 类）**：

| # | mangled | 还原 |
|---|---|---|
| 0 | `??0CNetLimitInstance@@QAE@XZ` | 构造函数 `CNetLimitInstance()` |
| 1 | `??1CNetLimitInstance@@QAE@XZ` | 析构函数 `~CNetLimitInstance()` |
| 2 | `??4CNetLimitInstance@@QAEAAV0@ABV0@@Z` | 拷贝赋值 |
| 3 | `?GetNetSpeed@...PAUNET_SPEED@@` | `GetNetSpeed(NET_SPEED*)` |
| 4 | `?SetNetSpeed@...PAUNET_SPEED@@` | `SetNetSpeed(NET_SPEED*)` |
| 5 | `?SetWhiteRule@...PAUNET_LIMIT_INFO@@` | `SetWhiteRule(NET_LIMIT_INFO*)` |

---

## 1. 角色概述

NetLimitInterface.dll 是 **`OeNetlimit.dll` 的 C++ 适配/封装层**（源码目录名 `limit_driver_interface`）。它自身**不直接**操作内核：

```
构造 CNetLimitInstance()
  → SYS_GetModuleFileDir(dir)          // 本模块所在目录
  → LoadLibraryW(dir + "OeNetlimit.dll")  // 延迟加载下一层（FUN_10001580）
各方法 = GetProcAddress(OeNetlimit.dll, "<导出名>") 后转发调用 + 错误日志
```

即：DeviceControl 面向的是这套**语义化的 C++ 接口**（`NET_SPEED`/`NET_LIMIT_INFO` + `GetNetSpeed`/`SetNetSpeed`/`SetWhiteRule`），NetLimitInterface 再翻译成 `OeNetlimit.dll` 的 14 个底层 API。

## 2. 加载下一层（`FUN_10001580`）

```c
SYS_GetModuleFileDir(dir, 0x104);           // 得到 NetLimitInterface.dll 所在目录
path = dir + "OeNetlimit.dll";
h = LoadLibraryW(path);
if (!h) log("LoadLibrary OeNetlimit.dll faild, error is %d");
// h 存于 this 基址，后续 GetProcAddress(this->h, name)
```

## 3. 三个公开方法

### `GetNetSpeed(NET_SPEED* s)` → `FUN_100016b0`
依次 `GetProcAddress` 取 `OeNetlimit.dll` 的 `GetSpeed`、`GetLimitSpeed` 并调用，结果写入 `NET_SPEED`：

| NET_SPEED 偏移 | 含义 | 来源 |
|---|---|---|
| `+8`  | 当前下行速率 | `GetSpeed` 返回值 `[0]` |
| `+4`  | 当前上行速率 | `GetSpeed` 返回值 `[1]` |
| `+0x10` | 限制下行速率 | `GetLimitSpeed` 返回值 `[0]` |
| `+0xC`  | 限制上行速率 | `GetLimitSpeed` 返回值 `[1]` |
| `+0`  | 限下行标志 | `GetLimitSpeed` 第 2 参 |
| `+1`  | 限上行标志 | `GetLimitSpeed` 第 3 参 |

### `SetNetSpeed(NET_SPEED* s)` → `FUN_10001900`
取 `OeNetlimit.dll!SetSpeed`，把 `s->limit_up(+0x10)`/`s->limit_down(+0xC)` 组成 8 字节限速值，连同 `s[0]`/`s[1]` 两个标志字节，调用 `SetSpeed(8B, byte, byte)`。

### `SetWhiteRule(NET_LIMIT_INFO* p)` → `FUN_10001a30`（核心）
按 `NET_LIMIT_INFO` 字段依次转发到 `OeNetlimit.dll`：

| 步骤 | 转发 | 来源字段 |
|---|---|---|
| 1 | `SetWhiteIP(ipPtr, ipCount)` | `p+7`（IP 数组）、`p[6]`（个数） |
| 2 | `SetWhitePort(portArr, portCount)` | `p+0x3A`（端口数组）、`p[0x39]`（个数） |
| 3 | 遍历 URL 列表 → `SetWhiteUrl(...)` | `p[0x53]`（URL 个数），每条 stride `0x40`、内容在 `+0x54` |
| 4 | 按 `p[0]` 模式调网控开关： | 见下 |

**`p[0]`（模式）**：

| 值 | 行为 |
|---|---|
| `1` | `DisableNet(serverIp = p+1)` → "disable all internet true, server ip %s" |
| `2` | `DisableInternet(serverIp = p+1)` → "disable internet true, server ip %s" |
| `3` | `EnableNet()` → 恢复网络 |

即 **`SetWhiteRule` = "下发白名单（IP/端口/URL）+ 选择网络封锁模式（全断/断外网/放开，并保留 serverIp 放行）"**。

## 4. 日志

统一走 `FUN_10004a20`，格式：
```
[%4d-%02d-%02d %02d:%02d:%02d:%03d][ERROR][%s,%d] <msg>
```
关键日志串：`LoadLibrary OeNetlimit.dll faild`、`GetSpeed GetProcAddress faild`、`get cur/limit speed faild`、`set speed limit faild`、`set white ip/port/url faild!`、`disable (all) internet faild/true, server ip %s`、`enable internet faild`。日志目录引用 `log\`。

## 5. 与体系的关系

```
DeviceControl.exe（回环 UDP 8454，收教师端指令）
  → NetLimitInterface.dll（本组件：CNetLimitInstance，语义化接口 + NET_SPEED/NET_LIMIT_INFO）
      → OeNetlimit.dll（CArpMgr：DeviceIoControl(\\.\OeNetLimit) 0x122044/0x122048）
          → OeNetLimit.sys（WFP/NDIS 网络过滤 + 白名单执行）
```

NetLimitInterface 是 **DeviceControl 与驱动之间唯一的"网络规则"桥接**：把教师端下发的一条 `NET_LIMIT_INFO` 规则，拆解为 IP/端口/URL 白名单 + 网络封锁模式，落到 OeNetlimit.dll 的底层 API。

## 6. 关键函数索引（x86）

| 地址 | 职责 |
|---|---|
| 0x10001020 | `CNetLimitInstance::CNetLimitInstance`（构造，内含加载 OeNetlimit.dll） |
| 0x10001040 | `GetNetSpeed` |
| 0x100010b0 | `SetNetSpeed` |
| 0x10001120 | `SetWhiteRule` |
| 0x10001580 | `LoadLibraryW(dir+"OeNetlimit.dll")` |
| 0x100016b0 | GetNetSpeed 实现（GetSpeed+GetLimitSpeed） |
| 0x10001900 | SetNetSpeed 实现（SetSpeed） |
| 0x10001a30 | SetWhiteRule 实现（IP/端口/URL + 模式分派） |
| 0x10001c50 | DisableNet / DisableInternet 转发 |
| 0x10001e00 | EnableNet 转发 |
| 0x10001e80 | SetWhiteIP 转发 |
| 0x10001f10 | SetWhitePort 转发 |
| 0x10001fa0 | SetWhiteUrl 转发 |
| 0x10004a20 | 日志（带时间戳/文件行号） |

## 7. 未决项

1. `NET_SPEED` / `NET_LIMIT_INFO` 的**完整**字段布局（本报告仅覆盖 DeviceControl 实际读写的字段；`NET_LIMIT_INFO` 中 `+0x3A`/`+0x54` 之前的大量字段未在此 DLL 使用，可能供黑名单或其它规则扩展）。
2. `NET_LIMIT_INFO[0]` 模式值是否还有 `>3` 的分支（本报告仅见 1/2/3）。

---

*本文覆盖：NetLimitInterface.dll 指纹与 6 导出、对 OeNetlimit.dll 的延迟加载、GetNetSpeed/SetNetSpeed/SetWhiteRule 的字段级转发逻辑、NET_SPEED 与 NET_LIMIT_INFO 结构、网络封锁模式（全断/断外网/放开 + serverIp）、日志、与 DeviceControl/OeNetlimit/OeNetLimit.sys 的关系、函数索引。*