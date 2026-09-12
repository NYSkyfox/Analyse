# 06 DeviceControl 设备管控程序深挖

## 一、程序定位

| 文件 | 架构 | 说明 |
|---|---|---|
| `DeviceControl_x64.exe` | x64 | 设备管控执行程序（x64） |
| `DeviceControl_x86.exe` | x86 | 设备管控执行程序（x86） |

编译路径：`D:\dmt\master\10.9\Source\DeviceControl\bin\DeviceControl.pdb`

该程序由 MMPC 守护进程管理（`kill-deviceControl` 指令杀它），是**行为管控在用户态的执行器**，通过 LISS SDK 接收指令并下发给驱动。

## 二、指令分发函数

反编译 `DeviceControl_x64.exe FUN_140021bd0`（指令分发，参数含 `NET_LIMIT_INFO` 网络限制结构）与 `FUN_140029310`、`FUN_140025830`。

## 三、设备管控指令全集（逐个指令）

### 3.1 网络控制

| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable NetWork` | 启用网络 | OeNetLimit.sys |
| `Disable NetWork` | 禁用网络（断网） | OeNetLimit.sys |

### 3.2 应用程序限制

| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable Application Limit` | 启用应用限制 | ProcFireWall.sys |
| `Disable Application Limit` | 禁用应用限制 | ProcFireWall.sys |
| `Enable Application White Mode` | 应用白名单模式 | ProcFireWall.sys |
| `Enable Application Black Mode` | 应用黑名单模式 | ProcFireWall.sys |

### 3.3 设备控制

| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable DUOC` | 启用设备使用控制（Device Use Control） | easyusbflt.sys |

### 3.4 键盘控制

| 指令 | 作用 | 对应驱动 |
|---|---|---|
| `Enable KC` | 启用键盘控制（Key Control） | KbFilter.sys |
| `Disable Keyfilter` | 禁用键盘过滤 | KbFilter.sys |

### 3.5 停止指令（`FUN_140025830`）

| 指令 | 作用 |
|---|---|
| `stop-device-control` | 停止设备控制 |
| `stopnetworktraffic` | 停止网络流量管控 |
| `stopnetwork` | 停止网络管控 |
| `stopdevice` | 停止设备管控 |
| `stopprocess` | 停止进程管控 |

### 3.6 支持性指令

| 指令 | 作用 |
|---|---|
| `support-use-device-control` | 查询是否支持设备控制（`FUN_140025aa0`） |

## 四、进程管控（直接 API）

| 函数 | 作用 |
|---|---|
| `ZwSuspendProcess`（FUN_140032e30） | 挂起进程 |
| `ZwResumeProcess`（FUN_140032aa0） | 恢复进程 |

## 五、USB 控制（easyusbctrl.dll）

| 函数 | 作用 |
|---|---|
| `EasyUsb_StartWorking`（FUN_140033730） | 启动 USB 管控 |
| `EasyUsb_StopWorking`（FUN_140033850） | 停止 USB 管控 |

加载 `easyusbctrl.dll`，失败日志 `load libray easyusbctrl.dll failed!error:%d`。

## 六、LISS SDK 交互

```
LISS_SDK_IsSupportMMCStrategy        // 是否支持 MMC 策略
LISS_SDK_SendMMCStopStrategy         // 发送 MMC 停止策略
LISS_SDK_SendBroadcastTypeInternal   // 发送广播类型
```

## 七、能力探测日志

```
[CanUseDeviceControl] ret:%d,support:%d
[SupportUseDeviceControl] process:%d device:%d network:%d traffic%d
[SupportUseDeviceControl] No LissSDK
[StopDeviceControl] %d:%d:%d:%d
```

四个维度：**process（进程）/ device（设备）/ network（网络）/ traffic（流量）**。

## 八、网络限制类

字符串中存在 `SetWhiteRule@CNetLimitInstance`，说明有 `CNetLimitInstance` 类负责网络限制，通过 `NET_LIMIT_INFO` 结构配置白名单规则。

## 九、总结

DeviceControl 是行为管控的**统一执行器**，将教师端下发的逻辑指令（启用/禁用网络、应用限制、USB、键盘）映射到对应的内核驱动（OeNetLimit、ProcFireWall、easyusbflt、KbFilter），并支持进程级挂起/恢复（ZwSuspendProcess/ZwResumeProcess）。所有指令经 LISS SDK 通道下发。
