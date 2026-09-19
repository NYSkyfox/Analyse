# FbdATS.sys 组件深度逆向（文件系统资产过滤驱动）

> 样本：`samples/os-easy/FbdATS.sys`（43032 字节，PE32+ x86-64 内核驱动）
> 反编译：Ghidra 12.1.3 headless，63 函数，存档 `/root/ghidra/mmpc/FbdATS_run_x64.txt`
> 样本 MD5：`0eefb419a79af5f6b7cffc13d02e2962`
> 内嵌 PDB：`z:\win_drv\new_drv\fbdats\objfre_win7_amd64\amd64\FbdATS.pdb`
> 另有**同源 x86 架构**样本 `samples/di_flat/FbdATS.sys`（=`samples/driverinstall/$_12_/FbdATS.sys`，驱动安装程序 `DriverInstall.exe` NSIS 解包出的内置副本，38936 字节，MD5 `8094dc20609d439e21d50bda45871430`；PDB 为同一源码树的 `…objfre_win7_x86\i386\…`），独立分析见 `driver-install/FbdATS_sys.md`。二者**同源码同版本，仅目标架构不同**。

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/FbdATS.sys` |
| 大小 | 43032 字节 |
| 架构/类型 | PE32+ x86-64 内核驱动（SFilter/FSFilter） |
| MD5 | `0eefb419a79af5f6b7cffc13d02e2962` |
| SHA-256 | `76a4a36a82d5dd5cffc0986e78050d34bea1e9382710520937e04d7329530af4` | — |
| 内嵌 PDB | `z:\win_drv\new_drv\fbdats\objfre_win7_amd64\amd64\FbdATS.pdb` |

## 1. 定位

**文件系统过滤驱动（FSFilter / SFilter 框架）**，对**磁盘卷/光驱/虚拟盘**做挂载级过滤，按"进程白名单位图"决定放行或 `STATUS_ACCESS_DENIED`。名称中的 **ATS = Assets**（资产）——针对教学/考试**素材文件**（课件、试卷、答案资源）做访问管控。

## 2. 标识与设备

| 项 | 值 |
|---|---|
| 过滤框架注册名 | `\FileSystem\Filters\SFilterOEAssets` / `\FileSystem\SFilterOEAssets` |
| 注册 API | `FsRtlRegisterFileSystemFilterCallbacks` |
| 设备 | `\DosDevices\FbdAssets`（`IoCreateDevice`，deviceType `0x8599`） |
| 池标签 | `0x6c754653`（"SFuL"，SFilter 经典标签） |
| 日志 | `SFilter!SfFsNotification` / `SfAttachToFileSystemDevice` / `SfFsControlMountVolume` 等（SFilter 框架调试串） |

## 3. 挂载目标（卷匹配）

`FUN_0001145c` 区按设备名前缀匹配（`wcsncmp`）以下几类：

| 目标 | 说明 |
|---|---|
| `\Device\HarddiskVolume` / `\Device\HarddiskVolume1` | 本地固定盘/分区 |
| `\Device\venetdisk` | **虚拟磁盘**（VDI/云桌面，"venetdisk"） |
| `\Device\CdRom` / `\Device\CdRom0` | 光驱 |
| `\Device\RawDisk` / `\Device\RawCdRom` | 原始设备（直读绕过） |
| `\Driver\VolSnap` | 卷影快照 |
| `\??\C:` | 盘符卷 |
| `\Device\HarddiskVolume*` | 全部分区 |

并对 `FsRtlRegisterFileSystemFilterCallbacks` 回调做 `SfFsNotification`（文件系统挂载/加载通知）、`SfAttachToFileSystemDevice`（附加到 FS 设备）、`SfFsControlMountVolume`（卷挂载控制）——即 **SFilter 示例框架的自定义改造版**。

## 4. IRP 分发与 IOCTL（`FUN_00011008`）

| IOCTL | 方向 | 处理 |
|---|---|---|
| `0x8599000C`（= `-0x7a66fff4`） | in | **SET pass-process 位图**：要求 inLen>3 → `DAT_00013178 = *puVar2`；日志 `"OEDRV FbdATS OEDRV_IsPassProcess"` |
| `0x85990010`（= `-0x7a66fff0`） | out | **GET pass-process 位图**：要求 outLen>=4 → `*puVar5 = DAT_00013178`；返回长度 4 |
| 其它 | — | 无效 → `STATUS_INVALID_PARAMETER(0xC0000023)` |

**文件访问门控（核心）**：对非本设备的 IRP，检查
```
(DAT_00013178 & *(uint*)(devExt+0xa4)) != 0    // 进程位图 & 设备标志
  && *(short*)(devExt+0xa0) != 0               // 设备名非空
  && *(longlong*)(devExt+8) != 0               // 有下挂设备
  && *(uint*)(devExt+0xa4) == 0x10             // 特定类别位
  && MajorFunction == 0x4d014                  // 自定义主功能码
→ FUN_000111a0(DAT_00013178, 0x10) 判定
  未通过 → STATUS_ACCESS_DENIED(0xC0000022)
  通过   → 交给下层（FUN_00011154 → IofCallDriver）
```
即：**对特定主功能（`0x4D014`，自定义/直读类操作）按 进程位图 ⊕ 设备位图 决定放行/拒绝**，拒绝时直接返回 `ACCESS_DENIED`，绕过下层文件系统。

## 5. 与体系的关联

FbdATS 与 ProcFireWall / KbFilter / OeNetLimit 同属 **"OEDRV" 驱动族**（都有 `OEDRV_IsPassProcess` 日志）——共享**统一进程白名单**语义：
- **ProcFireWall**：进程创建维度（能不能启动某进程）
- **KbFilter**：输入维度（键盘键位）
- **OeNetLimit**：网络维度（进程/DNS 放行）
- **FbdATS**：文件维度（能不能读/写受保护资产，磁盘/VDI/光驱）

`DAT_00013178` 是对应的"放行位图"，由用户态（DeviceControl）经 IOCTL `0x8599000C` 下发。

## 6. 函数索引

| 地址 | 功能 |
|---|---|
| `0x11008` | IRP 分发（IOCTL 0x8599000C/10 + 文件访问门控） |
| `0x11154` | 放行 → 下发下层 |
| `0x111a0` | 进程位图判定（IsPassProcess） |
| `0x1145c` | 卷/设备名匹配（HarddiskVolume/venetdisk/CdRom/RawDisk/VolSnap） |
| `0x11634` | SFilter FS 通知/挂载回调 |
| `0x118xx` | SfFsNotification / SfAttachToFileSystemDevice / SfFsControlMountVolume |
| `0x15014+` | SFilter 框架函数（attach/detach/load/unload） |
| `DAT_00013178` | pass-process 位图（IOCTL 收发） |

## 7. 未决项

1. `MajorFunction == 0x4D014` 的语义（自定义 IOCTL vs 特定 FastIO/直读路径）；
2. `devExt+0xa4` 位图类别与 `0x10` 位的确切含义（按设备类型分组的放行位）；
3. 受保护"资产"的具体文件/目录特征（是否按扩展名/目录名，需结合用户态侧配置）；
4. 与 `driver-install/` 目录样本（安装程序内置 **x86** 副本，38936B）已确认为**同源同版本、仅目标架构不同**（PDB 同源码树），无需再比对；
5. `SFilter` 框架的 FastIO 旁路是否也做了门控（`SfFastIoDetachDevice` 可见，但读/写 FastIO 入口未逐一确认）。