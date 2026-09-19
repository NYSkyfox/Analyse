# tdifilter.sys 组件深度逆向

> 来源：`DriverInstall.exe` NSIS 解包
> 样本：`samples/di_flat/tdifilter.sys`（28856 字节，x86 内核驱动）
> 反编译存档：`/root/ghidra/mmpc/di/di_tdifilter.sys.txt`（40 函数）
> 安装器：`OeNetLimitSetup.exe` 的 TDI 部分（`"tdifilter"` 服务）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 28856 字节 |
| MD5 | `71b41e97b9930253287348e96c2ce76d` |
| SHA-256 | `a83a5c637aaeeafa47fddd5e799ecff0c6cce67297d85758214b8f981f8fd426` |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 入口点 | `0x123be` |
| 导入 | `ntoskrnl.exe`、`HAL.dll` |

## 1. 角色

**TDI 网络过滤驱动**：在 TCP/UDP 传输层（TDI）挂过滤，实现**按进程 + 端口白名单**的网络访问控制；白名单进程名单来自 `\SystemRoot\WhiteProcessPath.txt`。

## 2. 设备与装载

```
IoCreateDevice(type = FILE_DEVICE_NETWORK(0x12), Characteristics = 0x100)
设备：\Device\TdiFltDev（另有 \Device\TcpFltDev、\Device\UdpFltDev）
符号链接：\??\tdifilter
IoAttachDeviceToDeviceStackSafe 到 \Device\Tcp 与 \Device\Udp   // 挂 TDI 过滤
PsSetCreateProcessNotifyRoutine(FUN_00010778, 0)
读取白名单：\SystemRoot\WhiteProcessPath.txt（ZwOpenFile/ZwReadFile）
日志文件：\SystemRoot\log.txt
（同时引用 \Device\OeNetLimit）
```

## 3. 白名单逻辑（调试串）

| 串 | 含义 |
|---|---|
| `[ReadConfig] ZwOpenFile failed / ZwQueryInformationFile Failed / ZwReadFile failed / ExAllocate Pool failed` | 白名单配置读取 |
| `[CreateProcess]Added White Process Name is %s,PID is %d` | 进程创建时登记白名单进程 |
| `[CreateProcess]Not Record White Process PID is %d,Name is %s` | 非白名单进程记录 |
| `[CreateProcess]PID=%d,White Process Name Or Path is %s` | 匹配 |
| `[PrintProcessList]PID=%d;Process Name is %s` | 打印进程表 |
| `[Print]PID=%d;White Port is %d` | 打印端口白名单 |
| `[Bind]Added White Port is %u,PID is %d` | 绑定端口时登记 |
| `[Bind]Add White Port is failed, Port is %d` / `[Bind]pAddPort is NULL` | 绑定路径异常 |
| `[Bind]Not Record White Process PID is %d` / `[Bind]White Process Name is %s,PID=%d` | 绑定判定 |
| `[CleanUp]Deleted  White Port is %d;PID is %d` | 连接释放清理 |
| `Not Record Port is %u` | 未登记端口 |
| `TransportAddress` | 传输地址结构 |
| `%s,Error Code is %x` | 通用错误 |

## 4. 关键函数索引

| 地址 | 职责 |
|---|---|
| 0x123be | entry |
| 0x10486 | 初始化/入口辅助 |
| 0x1056c | 主分发/装载 |
| 0x10758 / 0x10778 | **进程创建通知**（登记白名单进程） |
| 0x10908 / 0x10960 | 端口/Bind 处理 |
| 0x10a42 | 端口白名单管理 |
| 0x10b04 / 0x10b56 / 0x10ba8 | 配置读取/打印 |
| 0x10d0a / 0x10e16 | 传输地址/连接处理 |

## 5. 与上层联动

- 与 `OeNetLimit.sys`（WFP 层）**互补**：tdifilter 在 **TDI 层**做进程/端口白名单，OeNetLimit 在 **WFP/NDIS 层**做放行/阻断。
- 两者都读同一份白名单 `\SystemRoot\WhiteProcessPath.txt`（由 `ManagerWhtProcPath.exe` 维护）。

## 6. 未决项

1. TDI 过滤的具体挂钩点（`\Device\Tcp` 的 IRP_MJ_INTERNAL_DEVICE_CONTROL / TDI_* 请求）需细读分发函数。
2. 白名单条目格式（`WhiteProcessPath.txt` 的行结构与端口项）待确认。

---

*本文覆盖：tdifilter.sys 指纹、设备/TDI 挂载、白名单配置读取、过滤串与函数索引、与 OeNetLimit/白名单文件的互补关系。*