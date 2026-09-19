# OeNetlimit.dll（x86）组件深度逆向

> 样本：`samples/os-easy/x86/OeNetlimit.dll`（372368 字节，PE32 DLL，`pei-i386`）
> 同源 x64：`samples/os-easy/x64/OeNetlimit.dll`（见 `../x64/OeNetlimit_dll.md`）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/oenetlimitdll`（x86）
> 反编译存档：`/root/ghidra/mmpc/oenetlimitdll_x86.txt`（1996 函数）
> 关联：`../OeNetLimit_sys.md`（内核驱动）、`../../DeviceControl_exe.md`（上层）、`../OeNetLimitSetup_exe.md`（驱动安装器）
> 分析日期：2026-09-18（重组 2026-09-19）

---

## 0. 文件指纹

| 项 | 值 |
|---|---|
| 大小 | 372368 字节 |
| MD5 | `0914ffa0abac65e1aecad7e10c5d0d9f` |
| SHA-256 | `fce4ba6a0a233ff737ec879367d11d53f3bc273d0ac496e9ecf8cf40c6c26f1c` |
| 格式 | PE32 DLL（`pei-i386`） |
| ImageBase | `0x10000000` |
| 入口点 | `0x10011206` |
| PDB | `d:\win_drv\new_drv\network\UpdateNetworkdriver\OeNetLimit_Dll_Sys\WonArpDllProject\WonArpDll\WonArpDll\bin\OeNetLimit.pdb` |

**导入**：
- `SETUPAPI`：`SetupCopyOEMInfW`、`SetupOpenInfFileW`、`SetupFindFirstLineW`、`SetupGetStringFieldW`、`SetupCloseInfFile`、`SetupDiGetClassDevsA`、`SetupDiEnumDeviceInfo`、`SetupDiGetDeviceRegistryPropertyA`、`SetupDiGetDeviceInstanceIdW`、`SetupDiDestroyDeviceInfoList`
- `ADVAPI32`：`OpenProcessToken`、`GetTokenInformation`、`AllocateAndInitializeSid`、`EqualSid`、`FreeSid`
- `SensApi`：`IsNetworkAlive`
- `WS2_32`（按序号）、`ole32`（`CoInitializeEx`/`CoCreateInstance`）、`USER32`、`KERNEL32`
- 运行时 `LoadLibraryA` 动态取：`iphlpapi!SendARP` / `GetIpNetTable` / `DeleteIpNetEntry` / `NotifyAddrChange`、`GetAdaptersInfo`

**导出（14 个，x86/x64 同名）**：
`DisableAntiArp`、`EnableAntiArp`、`DisableInternet`、`DisableNet`、`EnableNet`、`GetLimitSpeed`、`GetSpeed`、`SetSpeed`、`SetBlackIP`、`SetBlackPort`、`SetBlackUrl`、`SetWhiteIP`、`SetWhitePort`、`SetWhiteUrl`

---

## 1. 角色概述

OeNetlimit.dll 是 **OeNetLimit 网络管控的用户态库**，内部由两类对象组成：

| 类 | 作用 |
|---|---|
| **`CArpMgr`**（全局单例 `g_ArpMgr` @`DAT_1005c670`） | 读写驱动 `SpeedControl`（经设备 `\\.\OeNetLimit`）+ **ARP 防攻击**（网关 MAC 监控） |
| **`CNetInstall`**（单例 @`DAT_1005c654`） | 用 INF 安装/更新 OeNetLimit 驱动（`SetupCopyOEMInfW` 等） |

对外 14 个导出 = "读 SpeedControl → 改字段 → 写回" 的封装；另含日志（`c:\NetLimitLog.txt`）。

---

## 2. 设备通信（DeviceIoControl）

打开设备（`FUN_10001500`）：

```c
CreateFileA("\\\\.\\OeNetLimit", GENERIC_READ|GENERIC_WRITE(0xC0000000), 0, NULL,
            OPEN_EXISTING(3), FILE_ATTRIBUTE_NORMAL(0x80), NULL);   // 句柄存于 this+8
```

读写（`CArpMgr` 方法）：

```c
// 读  — FUN_10005c40
DeviceIoControl(hDev, 0x122044, NULL, 0, out, 0xF534, &ret, NULL);

// 写  — FUN_10005cd0
DeviceIoControl(hDev, 0x122048, in, 0xF534, NULL, 0, &ret, NULL);
```

**DLL 内出现的 IOCTL 编目**：

| IOCTL | 输入/输出 | 用途（观测） |
|---|---|---|
| `0x122044` | out `0xF534` | **GET SpeedControl** |
| `0x122048` | in `0xF534` | **SET SpeedControl** |
| `0x122004` | in `0x18` | 特定子项设置（3 处调用） |
| `0x122009` | — | 无参操作 |
| `0x12200C` | — | 无参操作 |
| `0x122010` | in `0x18` | 特定子项设置 |
| `0x12201C` / `0x122024` / `0x122028` / `0x122030` | — | 无参操作（开/关类） |

> 与 `OeNetLimit.sys`（`../OeNetLimit_sys.md`）对应：驱动侧 `IRP_MJ_DEVICE_CONTROL` 明确处理 `0x122044`/`0x122048`（结构 `0xF534`）；DLL 使用的其余 `0x12200x~0x122030` 属附加操作码（不同驱动版本/伴随通道，见 §11 未决项）。

---

## 3. SpeedControl 结构（0xF534 字节）

由读写路径与导出函数共同确定的关键字段（偏移以结构基址计）：

| 偏移 | 字段 | 依据 |
|---|---|---|
| `+0x00` | **AntiArp 开关**（1=启用） | `EnableAntiArp` 置位、`DisableAntiArp` 清零 |
| `+0x3F` / `+0x40` | 两个"禁网/禁 Internet"开关字节 | `DisableNet`/`DisableInternet`/`EnableNet` 成对写入（与 x64 驱动中 `disableNet`/`disableInternet` 字段一致） |
| 限速字段 | 上/下行限速（`GetSpeed`/`GetLimitSpeed`/`SetSpeed` 读写若干 DWORD） | `GetLimitSpeed(&v,&a,&b)`、`SetSpeed(&v,byte,byte)` |
| 白名单 | **端口**（`WORD[100]`）、**IP**（`DWORD[100]`）、**URL** 列表（存字符串） | `SetWhitePort`（最多 100 项）、`SetWhiteIP`、`SetWhiteUrl` |
| 黑名单 | 同上端口/IP/URL 列表 | `SetBlackPort`/`SetBlackIP`/`SetBlackUrl` |

> 例：`SetWhitePort(int* ports, int count)` 把 `count`（≤100）个 `WORD` 端口拷入结构中的端口数组后 `SetSpeedControl`；`DisableInternet("1.2.3.4")` 用 `inet_addr` 把 IP 串转 `DWORD` 加入 100 项数组（`Ordinal_11`）。

---

## 4. 导出 API 语义

| 导出 | 行为 |
|---|---|
| `EnableAntiArp` | `sc[0]=1` → SetSpeedControl（开启 ARP 防攻击） |
| `DisableAntiArp` | `sc[0]=0` → SetSpeedControl |
| `DisableInternet(url)` | 置"禁 Internet"字节；把 url/IP 加入限制列表 → 写回 |
| `DisableNet(ip)` | 置"禁网"字节；把 ip 加入列表 → 写回 |
| `EnableNet` | 清"禁网/禁 Internet"字节 → 写回 |
| `GetSpeed(&sc)` | 读结构，返回限速值 |
| `GetLimitSpeed(&v,&a,&b)` | 读结构，返回限速与两个标志 |
| `SetSpeed(&v,byte,byte)` | 写限速字段 → 写回 |
| `SetWhitePort/SetBlackPort(p,count)` | 写端口白/黑名单（≤100 项） |
| `SetWhiteIP/SetBlackIP(p,count)` | 写 IP 白/黑名单 |
| `SetWhiteUrl/SetBlackUrl(p,count)` | 写 URL 白/黑名单（`vecWUrl:%s` 调试） |

失败日志：`GetSpeedControl error` / `SetSpeedControl error` / `SetSpeedControl ok` / `SetBlackPort error` / `SetWhitePort error`。

---

## 5. CArpMgr（ARP 防攻击 + 网关监控）

初始化 `FUN_100013e0`：

```c
LoadLibraryA("iphlpapi.dll")  → GetProcAddress: SendARP / GetIpNetTable / DeleteIpNetEntry / NotifyAddrChange / GetAdaptersInfo
GetVersionExA → 记录 OS 平台/版本
```

监控流程（`FUN_10001660` 读 SpeedControl 后）：

```
IsNetworkAlive(&flags)                    // 网络是否在线（SensApi）
  → 未连接：日志 "not connected"
GetSpeedControl(&sc)
取适配器信息（网关）
SendARP / GetIpNetTable                   // 查询网关 MAC
日志 "gateway mac" / "gateway mac: "
FUN_10001880 / FUN_10001980               // 比对/纠正网关 MAC
DeleteIpNetEntry                          // 清除伪造的 ARP 表项
FUN_10001a70 / FUN_10001ae0               // 周期任务开关
NotifyAddrChange                          // IP 变化通知
```

即 **ARP 防火墙**：周期性获取正确的网关 MAC，并在发现 ARP 表项被污染时纠正/删除对应条目。

## 6. CNetInstall（用 INF 安装驱动）

- 使用 `SetupOpenInfFileW` / `SetupFindFirstLineW` / `SetupGetStringFieldW` 解析 INF，`SetupCopyOEMInfW` 将驱动注册进驱动库；
- `SetupDiGetClassDevsA` / `SetupDiEnumDeviceInfo` / `SetupDiGetDeviceRegistryPropertyA` / `SetupDiGetDeviceInstanceIdW` 枚举设备实例；
- 管理员权限校验：`OpenProcessToken` → `GetTokenInformation` → `AllocateAndInitializeSid` / `EqualSid`（判断是否 Administrators）；
- 这与 `OeNetLimitSetup.exe`（`../OeNetLimitSetup_exe.md`）职责互补：Setup 负责首次部署，`CNetInstall` 供运行期按需安装/更新。

## 7. 日志与配置

| 项 | 值 |
|---|---|
| 日志文件 | `c:\NetLimitLog.txt`；另引用 `log.txt`、`Log file open failed.` |
| 日志类 | `FileLogger`、`Logger` |
| INI 读写 | `GetPrivateProfileIntA/StringA/SectionA/SectionNamesA`、`WritePrivateProfileStringA/SectionA`（读写教学软件配置） |
| 调试输出 | `OutputDebugStringA/W`、`AllocConsole` + `WriteConsoleA/W` |

## 8. 类与单例（工厂 `FUN_100078a0`）

```
按名实例化并缓存：
  "CArpMgr"     → 0x20 字节 → g_ArpMgr   (@DAT_1005c670，实际使用点)
  "CNetInstall" → 4 字节    → @DAT_1005c654
未命中 → 返回 0
```

`CArpMgr` 对象布局（观测）：`+8` 设备句柄、`+0xC` 事件、`+0x10` 另一句柄、`+0x14` `VirtualAlloc`+`VirtualLock` 的工作缓冲（`VirtualFree` 长度 `0x31AC`）。

## 9. 与体系的关系

```
DeviceControl.exe
  → NetLimitInterface.dll（CNetLimitInstance::SetWhiteRule / NET_LIMIT_INFO）  →  ../x86/NetLimitInterface_dll.md
      → OeNetlimit.dll（本组件：14 个网络限制 API + CArpMgr + CNetInstall）
          → \\.\OeNetLimit  IOCTL 0x122044/0x122048（SpeedControl 0xF534）
              → OeNetLimit.sys（WFP/NDIS 过滤）
          → SetupCopyOEMInfW + OeNetLimit.inf/netsf.inf（按需安装驱动）
```

## 10. 关键函数索引（x86）

| 地址 | 职责 |
|---|---|
| 0x100013e0 | CArpMgr 构造（加载 iphlpapi、OS 判定） |
| 0x10001500 | 打开 `\\.\OeNetLimit` |
| 0x10001540 / 0x100015a0 | 取数据（事件等待）/ 关闭释放 |
| 0x10001660 | 读 SpeedControl（带同步） |
| 0x10001880 / 0x10001980 | 网关 MAC 比对/纠正 |
| 0x10001a70 / 0x10001ae0 | ARP 周期任务开关 |
| **0x10005c40** | **GetSpeedControl**（IOCTL 0x122044） |
| **0x10005cd0** | **SetSpeedControl**（IOCTL 0x122048） |
| 0x100078a0 | 工厂（CArpMgr / CNetInstall 单例） |
| 0x10005f20 / 0x10005f30 | CNetInstall 构造/vftable |
| 0x1000b6e0…0x1000c6d0 | 14 个导出（Enable/Disable/Get/Set/White/Black…） |

## 11. 未决项

1. ~~`0x122004/0x122009/0x12200C/0x122010/0x12201C/0x122024/0x122028/0x122030` 的确切语义~~ **已确认**：配套的 `OeNetLimit.sys`（`../OeNetLimit_sys.md`）的 IRP 分发函数 `FUN_00011b10`（`IRP_MJ_DEVICE_CONTROL`）**只处理 `0x122044`/`0x122048`**（且校验 in/out 长度必须为 `0xF534`，否则 `DbgPrint("IOCTL_*_SpeedControl invalid length")`），其余控制码一律走默认分支返回 `STATUS_UNSUCCESSFUL(0xC0000001)`。因此 DLL 中出现的 `0x122004~0x122030` 在**当前配套驱动版本下不被实现**——属于 DLL 侧预留/历史接口或对应另一驱动版本，实际下发这些码会得到 `0xC0000001`。真正生效的通道只有 `0x122044`/`0x122048` 两条 SpeedControl。
2. SpeedControl 中白/黑名单数组的精确偏移与条目格式（端口 `WORD[100]` 之外，IP/URL 的元素数与编码）。
3. `CNetInstall` 使用的具体 INF 名与安装触发时机（运行期哪一条件触发重装）。

---

*本文覆盖：OeNetlimit.dll（x86）指纹与导出、设备 `\\.\OeNetLimit` 通信与 IOCTL 编目、SpeedControl（0xF534）字段、14 个 API 语义、CArpMgr（ARP 防攻击/网关监控）、CNetInstall（INF 装驱动+管理员校验）、日志/配置、类单例工厂、与 OeNetLimit.sys 及 DeviceControl/NetLimitInterface 的关系、函数索引。*