# KbFilter.sys 组件深度逆向（键盘过滤驱动）

> 样本：`samples/os-easy/KbFilter.sys`（36376 字节，PE32+ x86-64 内核驱动）
> 反编译：Ghidra 12.1.3 headless，39 函数，存档 `/root/ghidra/mmpc/KbFilter_run_x64.txt`
> 样本 MD5：`3187675245b5e8e96dddc9df64e7a7e6`
> 内嵌 PDB：`E:\work\four\KbFilter\x64\Release\KbFilter.pdb`
> 另有**同源 x86 架构**样本 `samples/di_flat/KbFilter.sys`（=`samples/driverinstall/$_12_/KbFilter.sys`，驱动安装程序解包出的内置副本，33816 字节，MD5 `7c42b6343b7e400d074298382bd6485d`；PDB 为同一源码树的 `E:\work\four\KbFilter\Release\KbFilter.pdb`），独立分析见 `driver-install/KbFilter_sys.md`。二者**同源码同版本，仅目标架构不同**。

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/KbFilter.sys` |
| 大小 | 36376 字节 |
| 架构/类型 | PE32+ x86-64 内核驱动（Kbdclass filter） |
| MD5 | `3187675245b5e8e96dddc9df64e7a7e6` |
| SHA-256 | `03896f68c0ac88f3920e5017abc90bd2a79af91d4523e21e8310d3b7d08ec15b` | — |
| 内嵌 PDB | `E:\work\four\KbFilter\x64\Release\KbFilter.pdb` |

## 1. 定位

**键盘（KBD 类）过滤驱动**：以 filter driver 挂到键盘类设备栈上，在内核态**逐扫描码改写/拦截按键 IRP**，实现"键盘锁/键位屏蔽/组合键拦截"。与用户态 `LockKeyboard.dll`（MultiClient 侧）互补——本驱动是真正的内核落点，能拦用户态钩子拦不到的按键。

## 2. 设备与挂载

| 项 | 值 |
|---|---|
| 设备对象 | `\Device\DevOeKbdFilter`（`IoCreateDevice` deviceType `0xb`=FILE_DEVICE_KEYBOARD，deviceExtSize 8） |
| 符号链接 | `\DosDevices\OeKbdFilter`（两处：DriverEntry 建/卸载删） |
| 挂载方式 | **`AddDevice`（FUN_140006000）：`IoCreateDevice + IoAttachDeviceToDeviceStack`** —— 挂到 PnP 传入的键盘功能设备（Kbdclass）栈上 |
| 日志 | `\SystemRoot\log.txt`（`RtlInitUnicodeString`，DEBUG 输出） |

## 3. IRP 处理（键盘数据路径）

`AddDevice` 时把 **PnP 栈 +0x48 处的 IRP 头**与 `+0x43` 的调用计数挂进自身设备扩展；数据 IRP（`IRP_MJ_INTERNAL_DEVICE_CONTROL`/KbdData）由 **`FUN_140001060`** 处理：

```
遍历 KBD_INPUT_DATA 数组（stride 0xc: +0 长度, +2 扫描码(USHORT), +4 makeflags）:
  makeflags = *(ushort*)(lVar2+4);  scancode = *(ushort*)(lVar2+2)
  1) DAT_140004b60 != 0 → FUN_140001bdc(scancode, flags)   // 按键记录/日志
  2) 按"模式" DAT_140004000 (0..7) 过滤:
     mode 0: 全放行
     mode 1: 全禁 (DAT_140004000==0 时 scancode=0 全部丢弃)
     mode 2: 位掩码白名单 —— scancode-0x1c 落在
              0x800000014004003U 掩码内才保留（字母/数字区放行，其余丢弃）
     mode 3: 多段位掩码 —— <0x1a:0x3ff4ffc / 0x1c..0x52:0x7bba00007f07fd /
              0x1d(回车)按makebit / <0x10:0xb002 / 0x1a..0x58:0x22110001be03e00b
     mode 4/5: FUN_140001724 双查（make/break 两态）不通过则丢弃
     mode 6: "Current Keyboard state err" 回退
     mode 7: FUN_140001dbc/f70/f00/e44 组合判定（自定义键表）不通过则丢弃
  3) 修饰键跟踪: 0x1d=Ctrl, 0x2a/0x36=左右Shift, 0x38=Alt
     (DAT_140004b64/b6c/b68 记录按下态)
  4) Ctrl+组合拦截: Ctrl 按下 & Shift 按下 & (scancode==0x53 Alt 或 scancode==1 Esc)
     → 强制 scancode=0（禁 Alt+Ctrl / Esc 在特定组合下逃逸）
  5) 单键开关组 DAT_140004048..0x459（每 1 字节一个扫描码禁用位:
     0x1d回车 / 0x5b左Win / 0x5c右Win / 0x38Alt / 0x2a0x36Shift / 0x0fF1 /
     0x01Esc / 0x3b..0x44 F5-F12 / 0x57 / 0x58 ...）置位则该键丢弃
  6) "白名单进程" 通道: 某键(==1/0x3b/0x3c/0x3d/0x3e/0x3f/0x40/0x41/0x42/0x43/0x57/0x58)
     命中 DAT_14000404d..0453 时丢弃（教师端下发"只允许这些键/禁止这些键"）
丢弃 = 把 scancode 写 0，IRP 继续下发（按键"消失"）
```

即：**7 种锁定模式 + 修饰键组合拦截 + 30+ 个单键开关 + 白名单进程键控**，全部在内核态对 KBD_INPUT_DATA 原地改写。

## 4. DeviceIoControl（`FUN_140001780` 区，控制面）

控制码（FILE_DEVICE_KEYBOARD `0xb` 基础）：

| IOCTL | 动作 | 日志 |
|---|---|---|
| `0xb2004` | **KEYBOARD_ALL_DISABLE**（全禁键盘） | `"OEDRV KbFilter OEDRV_IsPassProcess"` + `PsGetProcessImageFileName` 记录调用进程 |
| `0xb2008` | 设模式（DAT_140004000） | 记录调用进程映像名 |
| `0xb200c` | 设单键开关组 | 同上 |
| `0xb2010` / `0xb2014` | 其它状态位 | — |
| `0xb2018` | 查询/复位 | — |
| `0xb201c` | 状态查询 | — |
| `0xb2020` / `0xb2024` | 扩展控制 | — |
| `0xb2019` 以上 | 无效 → `STATUS_INVALID_DEVICE_REQUEST(0xC0000022)` | — |

每次控制码执行前都 `PsGetProcessImageFileName` + `sprintf → FUN_140001ffc`（写 `\SystemRoot\log.txt`）——**审计谁动了键盘锁**。

## 5. 体系位置

```
Teacher → MainLogic.dll::SetKeyBoardLock / SetLockAfterNetWorkBroken
  → WS 广播 → 学生 MultiClient.exe (LoadKeyboardLock)
  → DeviceControl.exe → CreateFile(\\.\OeKbdFilter) + DeviceIoControl(0xb2004/08/0c)
  → KbFilter.sys (本驱动, 挂 Kbdclass 栈):
      内核态逐扫描码改写 KBD_INPUT_DATA → 锁定键"消失"
```

## 6. 函数索引

| 地址 | 功能 |
|---|---|
| `0x140001060` | **键盘数据 IRP 过滤核心**（7 模式 + 组合键 + 单键开关） |
| `0x140001780` 区 | DeviceIoControl 分发（0xb2004..0xb2024） |
| `0x140006000` | AddDevice（IoCreateDevice + IoAttachDeviceToDeviceStack） |
| `0x140006110` | RemoveDevice（IoDetachDevice + IoDeleteDevice） |
| `0x140001bdc/f70/f00/e44/1724` | 按键记录/组合判定子函数 |
| `0x140001ffc` | 审计日志写 log.txt |
| `DAT_140004000` | 锁定模式（0-7） |
| `DAT_140004048..0x459` | 单键禁用开关组 |
| `DAT_140004b60/4b64/4b68/4b6c` | 按键记录标志 + Ctrl/Alt/Shift 跟踪 |

## 7. 未决项

1. 7 种模式与教师端 `SetKeyBoardLock`/`SetLockAfterNetWorkBroken` 参数的一一映射；
2. `FUN_140001bdc` 按键记录是否上行（供教师端监控按键行为）；
3. 与 `driver-install/` 目录样本（安装程序内置 **x86** 副本，33816B）已确认为**同源同版本、仅目标架构不同**；
4. 是否同时挂载鼠标类（字符串只见 Kbd，`IoAttach` 目标由 PnP 传入，未显式限定）。