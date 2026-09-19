# npf.sys 组件说明（第三方 WinPcap/Npcap）

> 来源：`DriverInstall.exe` NSIS 解包 → `$_12_/npf.sys`
> 样本：46264 字节，PE32 内核驱动（`pei-i386`）
> 反编译存档：`/root/ghidra/mmpc/di/di_npf.sys.txt`（67 函数）

---

## 0. 样本信息

| 项 | 值 |
|---|---|
| 大小 | 46264 字节 |
| MD5 | `fc364f245f2e47efabd1d54b3b9fea97` |
| 格式 | PE32 内核驱动（`pei-i386`） |
| 导入 | `ntoskrnl.exe`、`HAL.dll`、`NDIS.SYS` |
| 随附 | `wpcapSetup.exe`（安装器）、`Packet.dll`/`wpcap.dll`（用户态，见 `x86/` 目录） |

## 1. 角色

**第三方抓包驱动**——`npf.sys` = **NetGroup Packet Filter**，即 **WinPcap / Npcap** 的内核抓包过滤器（NDIS 协议驱动）。Os-Easy 用它为 **`LISSNetInfoSniffer.exe`** 和 `DeviceControl` 的网络嗅探/流量统计提供底层抓包能力。

## 2. 安装

- 由 `wpcapSetup.exe` 安装为 NDIS 协议服务（服务名 `NPF`），创建设备 `\Device\NPF_{GUID}`（每个网卡一个实例）。
- 与本安装包其它驱动的区别：**非 Os-Easy 自研**，是公开的 WinPcap 发行版；仅被 Os-Easy 复用。

## 3. 与 Os-Easy 体系的关系

```
DeviceControl_x64.exe ──start-lissNet──▶ LISSNetInfoSniffer.exe ──▶ npf.sys（抓包）
DeviceControl ──[SupportUseDeviceControl] networktraffic 探测────▶ 依赖此抓包能力
NetLimitInterface/OeNetLimit（限速/阻断）与 npf.sys（抓包）职责不同，互不依赖
```

## 4. 备注

- 该驱动为**第三方组件**，本报告只做定位与用途说明，不做逐函数逆向；如需可另行深入（其源码公开）。

---

*本文：npf.sys（WinPcap/Npcap 抓包驱动）的定位、安装方式与在 Os-Easy 中的作用。*