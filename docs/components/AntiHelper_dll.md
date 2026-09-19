# AntiHelper.dll 组件深度逆向

> 样本：`samples/os-easy/AntiHelper.dll`（44032 字节）
> 工具：Ghidra 12.1.3 headless（docker `ghidra`）+ objdump + strings
> 工程：`/projects/antihelper-analysis`（程序 `/AntiHelper.dll`，函数 384 个）
> 反编译存档：`/root/ghidra/mmpc/ah_all.txt`（全函数反编译）、`ah_str.txt`（字符串交叉引用）
> 分析日期：2026-09-18

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 44032 字节 |
| MD5 | `8889293e61af93f68704894dd8e6c8ce` |
| SHA-256 | `4472fb7de041ffb0212be6c7d8dfcd743afbae4f0d4e670e7a1441ca55253f5b` |
| 格式 | PE32，32 位 DLL（`pei-i386`） |
| ImageBase | `0x10000000` |
| 入口点 | `0x10008080`（`entry` → `dllmain_dispatch`） |
| PDB | `D:\dmt\master\10.9\Output\Release\AntiHelper.pdb` |
| 节表 | `.text` 0x7cdc / `.rdata` 0x1f54 / `.data` 0x200 / `.rsrc` 0x1e0 / `.reloc` 0x534 |

**导出（4 个）**：`AddProcessPid`、`DelProcessPid`、`ResetProtectDirectory`、`SetProtectDirectory`
（地址 `0x10006610 / 0x10006670 / 0x10006710 / 0x10006760`）

**导入**（关键）：
- `KERNEL32`：`DeviceIoControl`、`CreateFileA`、`QueryDosDeviceW`、`LoadLibraryW`、`GetProcAddress`、`GetModuleFileNameW`、`FormatMessageW`
- `FLTLIB.DLL`：`FilterConnectCommunicationPort`、`FilterSendMessage`（过滤管理器用户态 API）
- `ADVAPI32`：`OpenSCManagerW`、`CreateServiceW`、`OpenServiceW`、`StartServiceW`、`ControlService`、`QueryServiceStatusEx`、`RegCreateKeyExW`、`RegSetValueExW`、`RegFlushKey`

---

## 1. 角色概述

AntiHelper.dll 是 **MMPC 自我保护的用户态代理**：
- 提供 4 个导出，供 MMPC 保护/解除 **进程 PID** 与 **受保护目录**；
- 通过两条内核通道下达指令：**设备 `\\.\mtpcpt_link`（DeviceIoControl）** 与 **微过滤器端口 `\MmcProtectPort`（FilterSendMessage）**；
- **在被加载（DllMain `DLL_PROCESS_ATTACH`）时自动安装并启动两个驱动服务**，`DETACH` 时停止。

---

## 2. 导出接口

### 2.1 `AddProcessPid(DWORD pid)` @0x10006610

```c
HANDLE h = CreateFileA("\\\\.\\mtpcpt_link", GENERIC_WRITE(0x40000000), 0, NULL,
                       CREATE_ALWAYS(2), FILE_ATTRIBUTE_NORMAL(0x80), NULL);
if (h != INVALID_HANDLE_VALUE) {
    DeviceIoControl(h, 0x22A400, &pid, 4, NULL, 0, &ret, NULL);   // 加入保护
    CloseHandle(h);
}
```

### 2.2 `DelProcessPid(DWORD pid)` @0x10006670

同上设备，`DeviceIoControl(h, 0x22A404, &pid, 4, NULL, 0, &ret, NULL)` —— 解除保护。

### 2.3 IOCTL 编码

| IOCTL | DeviceType | Access | Function | Method | 含义 |
|---|---|---|---|---|---|
| `0x22A400` | 0x22（FILE_DEVICE_UNKNOWN） | 1（FILE_WRITE_ACCESS） | 0x900 | 0（METHOD_BUFFERED） | 保护进程 PID |
| `0x22A404` | 同上 | 同上 | 0x901 | 同上 | 解除进程 PID |

入参 = 4 字节 PID（`METHOD_BUFFERED`），无输出缓冲。

### 2.4 `SetProtectDirectory(LPCWSTR path)` @0x10006760

1. 取路径前 2 个字符作为盘符（如 `C:`），`QueryDosDeviceW("C:", buf, 0x104)` 得到 NT 设备路径（如 `\Device\HarddiskVolume3`）。
2. 将盘符之后的剩余部分拼到 NT 设备路径后 → 得到 NT 绝对路径（如 `\Device\HarddiskVolume3\dir`）。
3. 调 `FUN_100040b0(ntpath)` 下发（见 §3.2）。

### 2.5 `ResetProtectDirectory(void)` @0x10006710

清零 520 字节缓冲后调 `FUN_100040b0("")` —— 向微过滤端口发送**空串**，令驱动复位目录保护。

---

## 3. 两条内核通信通道

### 3.1 设备 `\\.\mtpcpt_link`（DeviceIoControl）

- 由驱动 **`mtpcpt.sys`** 创建（对应服务 `ssdtTookit`）。
- AntiHelper 对每个 PID 开一次设备句柄、发一次 IOCTL、关句柄。
- 用途：**进程级保护**（Add/Del ProcessPid）。

### 3.2 微过滤器端口 `\MmcProtectPort`（FilterSendMessage）

`FUN_100040b0(path)` @0x100040b0：

```c
HRESULT hr = FilterConnectCommunicationPort(L"\\MmcProtectPort", 0, NULL, 0, NULL, &hPort);
if (hr >= 0) {
    DWORD len = wcslen(path) * 2;                       // 字节数（不含结尾 NUL）
    FilterSendMessage(hPort, path, len, NULL, 0, &ret);
    CloseHandle(hPort);
}
```

- 由微过滤器 **`mtdrpt.sys`**（服务 `mmcprotect`）注册的通信端口。
- 用途：**目录级保护**（Set/Reset ProtectDirectory）；载荷为 NT 路径宽字符串。

---

## 4. 驱动安装 / 卸载（DllMain 自动执行）

**加载即安装**：`dllmain_dispatch` 在 `DLL_PROCESS_ATTACH(1)` 时调用 `FUN_100066d0(hInst,1)`；`DLL_PROCESS_DETACH(0)` 时调用 `FUN_100066d0(hInst,0)`。

`FUN_100066d0(param, reason)` @0x100066d0：

```c
if (reason == 0) FUN_10004440();    // 卸载：停止两个服务
else if (reason == 1) FUN_10004280();// 安装：装并启两个驱动
return 1;
```

### 4.1 安装 `FUN_10004280` @0x10004280

1. `FUN_10006060()` = `IsWow64Process` 探针：
   - 64 位 OS → `x64\mtpcpt.sys` / `x64\mtdrpt.sys`
   - 否则 → `x86\mtpcpt.sys` / `x86\mtdrpt.sys`
   （`FUN_10003f40` 负责拼 "DLL 所在目录 + 相对名"，即安装根目录）
2. **服务 `ssdtTookit`**：`FUN_10006930("ssdtTookit", <mtpcpt.sys路径>)`
   - 若已存在则跳过；
   - 否则 `CreateServiceW("ssdtTookit","ssdtTookit", SERVICE_ALL_ACCESS(0xf01ff), SERVICE_KERNEL_DRIVER(1), SERVICE_DEMAND_START(3), SERVICE_ERROR_NORMAL(1), <mtpcpt.sys路径>, NULL, NULL, NULL, NULL, NULL)` —— **普通内核驱动**。
   - 成功后 `FUN_100071c0("ssdtTookit")` 启动。
3. **服务 `mmcprotect`**：`FUN_100069d0("mmcprotect", <mtdrpt.sys路径>, L"370160")`
   - `CreateServiceW("mmcprotect","mmcprotect", 0xf01ff, SERVICE_FILE_SYSTEM_DRIVER(2), SERVICE_DEMAND_START(3), 0, <路径>, L"FSFilter Activity Monitor", NULL, L"FltMgr", NULL, NULL)` —— **文件系统微过滤器**，依赖 `FltMgr`，组 `FSFilter Activity Monitor`。
   - 写注册表 `HKLM\SYSTEM\CurrentControlSet\Services\mmcprotect`：
     - `DefaultInstance`（REG_SZ）
     - 子键 `Instances`：`DefaultInstance`、`Instances\<name>` 
     - `Instances\<name>`：`Altitude`（REG_SZ = `370160`）、`Flags`（REG_DWORD = 0）
   - 成功后 `FUN_100071c0("mmcprotect")` 启动。

### 4.2 卸载 `FUN_10004440` @0x10004440

```
FUN_100073e0(L"mmcprotect");   // 停止
FUN_100073e0(L"ssdtTookit");   // 停止
```

`FUN_100073e0` @0x100073e0：`OpenSCManagerW("ServicesActive")` → `OpenServiceW` → `QueryServiceStatusEx`；
- RUNNING(4) → `ControlService(SERVICE_CONTROL_STOP=1)` 后轮询至 STOPPED；
- STOP_PENDING(3) → 轮询等待；
- STOPPED(1) → 直接返回。
（该模块**不导入 `DeleteService`**：卸载仅停服务，服务/文件删除由外部卸载程序负责。）

### 4.3 服务启动 `FUN_100071c0` @0x100071c0

`OpenServiceW` → `QueryServiceStatusEx`：
- STOPPED(1) → `StartServiceW`；
- STOP_PENDING(3) → 轮询至 STOPPED 再 `StartServiceW`；
- RUNNING(4) → `ControlService(STOP)`，轮询至 STOPPED 再 `StartServiceW`（先停后起，确保生效）。

---

## 5. 辅助函数

| 函数 | 作用 |
|---|---|
| `FUN_10006060` @0x10006060 | `IsWow64Process` 探针（选 x86/x64 驱动） |
| `FUN_10003f40` @0x10003f40 | `GetModuleFileNameW` 取自身目录 + 相对名 → 绝对路径 |
| `FUN_10005a90` @0x10005a90 | 取 `std::wstring` 的 `c_str()` |
| `FUN_10007160` @0x10007160 | 服务是否已存在（`OpenServiceW`） |
| `FUN_10004200` @0x10004200 | `FormatMessageW` 错误码转字符串（日志/异常） |
| `FUN_10006930` @0x10006930 | 创建普通内核驱动服务 |
| `FUN_100069d0` @0x100069d0 | 创建微过滤器服务 + 写 Instances/Altitude/Flags |
| `FUN_100066d0` @0x100066d0 | DllMain 分发：0=卸载、1=安装 |

---

## 6. 与 MMPC 的联动

| MMPC 侧 | AntiHelper 导出 | 落到内核 |
|---|---|---|
| `FUN_00437a40(pid)` | `AddProcessPid(pid)` | `\\.\mtpcpt_link` IOCTL 0x22A400 |
| `FUN_00437f80(pid)` | `DelProcessPid(pid)` | `\\.\mtpcpt_link` IOCTL 0x22A404 |
| `FUN_0043ae20(path)` | `SetProtectDirectory(path)` | `\MmcProtectPort` FilterSendMessage |
| `FUN_0043a9f0()` | `ResetProtectDirectory()` | `\MmcProtectPort`（空串） |

MMPC 通过 `LoadLibraryW("AntiHelper.dll")` + `GetProcAddress` 调用上述导出；由于 AntiHelper 的 DllMain 会自动安装驱动，所以 **MMPC 一加载该 DLL，保护驱动即被安装并启动**。`protect.map`（=`Student.exe`）指明被守护的主目标；MMPC 亦用 `SetProtectDirectory("548861465")` 作为复位/解锁动作。

---

## 7. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x100040b0 | FilterSendMessage（端口 `\MmcProtectPort`） |
| 0x10006610 | AddProcessPid（导出） |
| 0x10006670 | DelProcessPid（导出） |
| 0x100066d0 | DllMain 安装/卸载分发 |
| 0x10006710 | ResetProtectDirectory（导出） |
| 0x10006760 | SetProtectDirectory（导出，路径规范化） |
| 0x10006930 | 创建内核驱动服务 |
| 0x100069d0 | 创建微过滤器服务 + 注册表 Instances/Altitude/Flags |
| 0x10006060 | IsWow64Process 探针 |
| 0x10003f40 | 自身目录 + 相对名拼路径 |
| 0x10007160 | 服务存在性检查 |
| 0x100071c0 | 启动/确保运行服务 |
| 0x100073e0 | 停止服务 |
| 0x10004280 | 安装两驱动 |
| 0x10004440 | 卸载两驱动 |
| 0x10008080 | entry → dllmain_dispatch |

---

## 8. 字符串 / 常量表

| 地址 | 内容 | 用途 |
|---|---|---|
| 0x10009508 / 0x10009518 | `\\.\mtpcpt_link` | 设备路径 |
| 0x10009528 | `\MmcProtectPort` | 微过滤通信端口 |
| 0x10009610 / 0x10009628 / 0x10009640 | `mmcprotect` | 服务名（微过滤器） |
| 0x100096cc / 0x100096ec | `ServicesActive` | SCM 数据库锁 |
| 0x1000971c | `FSFilter Activity Monitor` | 微过滤器组 |
| 0x10009750 / 0x100097e8 | `SYSTEM\CurrentControlSet\Services\` | 注册表前缀 |
| `ssdtTookit` | 宽串常量（.rdata） | 内核驱动服务名 |

---

## 9. 未决项

1. **驱动内部行为**（`mtpcpt.sys` / `mtdrpt.sys` 的进程保护与目录保护实现、IOCTL 具体处理、`\MmcProtectPort` 消息格式）需单独逆向两个 `.sys`。
2. 微过滤器 `Altitude = 370160`、组 `FSFilter Activity Monitor` 的选型来源与过滤点（IRP_MJ_*）待驱动侧确认。
3. `SetProtectDirectory` 对非法盘符（如 MMPC 传入的 `548861465`）的实际归一化结果需运行态验证。

---

*本文覆盖：文件指纹、导出接口与 IOCTL 编码、双内核通道（`\\.\mtpcpt_link` / `\MmcProtectPort`）、DllMain 自动装/卸驱动、两个服务（`ssdtTookit` 内核驱动 / `mmcprotect` 微过滤器，Altitude 370160）、注册表 Instances 结构、与 MMPC 的联动、函数与常量索引。*
