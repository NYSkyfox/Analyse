# Os-Easy 电子教室 完整运行流程图

```mermaid
sequenceDiagram
    autonumber

    participant T as Teacher.exe<br/>教师端
    participant Tcfg as MultiMediaConfig<br/>教师配置
    participant SC as ScrCapture.exe<br/>屏幕采集
    participant Net as 注册服务器<br/>RegisterServer

    participant S as Student.exe<br/>学生端
    participant Scfg as MultiMediaConfig<br/>学生配置
    participant ML as MainLogic.dll<br/>业务逻辑
    participant SL as StudentLogic.dll<br/>锁定逻辑

    participant MMPC as MMPC.exe<br/>广播调度服务
    participant MC as MultiClient.exe<br/>HTTP通信客户端
    participant SR as ScreenRender.exe<br/>屏幕渲染
    participant DC as DeviceControl.exe<br/>设备管控
    participant BS as BlackSlient.exe<br/>黑屏执行器

    participant LK as LockKeyboard.dll<br/>键盘锁定库
    participant EU as easyusbctrl.dll<br/>USB控制库

    participant KB as KbFilter.sys<br/>键盘过滤驱动
    participant NF as OeNetLimit.sys<br/>WFP网络过滤
    participant PF as ProcFireWall.sys<br/>进程防火墙
    participant UB as easyusbflt.sys<br/>USB过滤驱动
    participant FB as FbdATS.sys<br/>文件系统过滤

    rect rgb(230, 245, 230)
        Note over T,Net: === 第一阶段：启动与注册 ===
    end

    Tcfg->>T: 配置频道/班级/分组
    T->>Net: RegisterServerIp + Port + MAC<br/>教师端注册到服务器
    Net-->>T: AuthLogin 验证通过

    Scfg->>S: 配置频道/教师IP
    S->>MMPC: 启动 MMPC 服务
    MMPC->>MMPC: 创建 Global 互斥体<br/>com.morningcloud.tcloud.multimedia
    MMPC->>MMPC: 绑定 UDP 端口<br/>oseasy.mmc.udp
    S->>ML: 初始化 WebSocket 服务器
    ML->>ML: 绑定 TCP 5039/5099

    rect rgb(255, 245, 220)
        Note over T,FB: === 第二阶段：教师发现学生 ===
    end

    T->>MMPC: UDP 组播搜索学生
    MMPC-->>T: 上报学生信息<br/>班级/姓名/学号/MAC
    T->>T: 学生列表显示

    S->>S: 触发电子点名<br/>RegisterServerIp + 班级信息
    S->>MC: 启动 MultiClient
    MC->>MC: HTTP/WebSocket 连接教师

    rect rgb(220, 230, 255)
        Note over T,FB: === 第三阶段：屏幕广播 ===
    end

    T->>T: 教师点击"屏幕广播"
    T->>SC: 启动 ScrCapture 采集屏幕
    SC->>SC: GDI/BitBlt 或 D3D 采集<br/>FFmpeg H.264 编码
    T->>MMPC: LISS_SDK_SendBroadcastType

    MMPC->>MMPC: CanBroadcast 校验
    MMPC->>SR: 启动 ScreenRender
    MMPC->>MMPC: 创建 Global/Render_StuSharedMemory<br/>写入广播参数 JSON

    SR->>MMPC: 读取共享内存参数<br/>decoderName/h264 fullscreen/1<br/>remote/229.1.x.x port/7778
    SR->>SR: SDL2 + FFmpeg avcodec 解码<br/>MultiRenderWindowClass 全屏窗口<br/>m_nFullScreen:1

    MMPC->>S: broadcasttype 通知
    S->>SL: start-screen
    SL->>BS: 触发 BlackSilent
    BS->>LK: MouseAndKeyBoardLock Enable
    LK->>KB: DeviceIoControl<br/>---.OeKbdFilter

    KB->>KB: IRP_MJ_READ 拦截键盘<br/>KEYBOARD_ALL_DISALE
    Note over SR,KB: 视觉层全屏覆盖 + 输入层内核锁死

    rect rgb(255, 230, 230)
        Note over T,FB: === 第四阶段：行为管控 ===
    end

    T->>T: 教师执行管控操作

    par 黑屏肃静
        T->>S: 下发黑屏命令
        S->>BS: BlackSilent 执行
        BS->>LK: MouseAndKeyBoardLock Enable
        LK->>KB: KEYBOARD_ALL_DISALE
        BS->>BS: StuLockWnd.xml 锁屏界面
    and 断网
        T->>DC: Disable NetWork
        DC->>NF: IOCTL_SET_SpeedControl<br/>disableInternet:1 disableNet:1
        NF->>NF: WFP Callout 拦截<br/>ALE资源分配+IPv4出入站
        NF->>PF: OEDRV_IsPassProcess<br/>非白名单进程 BLOCK
    and 禁用USB
        T->>DC: Disable USB
        DC->>EU: EasyUsb_StartWorking
        EU->>UB: DeviceIoControl ---.EasyUsbflt<br/>白名单外设备 IRP 拦截
    and 远程关机
        T->>S: RemoteShutdown
        S->>S: shutdown -s -t 1
    end

    rect rgb(240, 240, 240)
        Note over T,FB: === 第五阶段：考试流程 ===
    end

    T->>T: 编辑/导入试卷<br/>ExameditingTool 或 Word 转换
    T->>S: SendExam 下发试卷
    S->>S: 学生答题
    S->>T: 提交试卷 SubmitFile
    T->>T: ExamStat 统计成绩<br/>导出 Excel

    rect rgb(230, 245, 245)
        Note over T,FB: === 第六阶段：文件传输 ===
    end

    T->>MC: FileTransfer 下发作业
    MC->>MC: FTP MmcFtp 传输<br/>FtpServerCachePath
    MC-->>T: 传输完成

    S->>MC: SumbitFile 提交作业
    MC->>MC: HTTPS GetHttpsData<br/>文件上传

    rect rgb(255, 240, 240)
        Note over T,FB: === 第七阶段：驱动安装 ===
    end

    Note over FB,KB: 安装由 DriverInstall.exe 统一调度

    FB->>FB: FsRtlRegisterFileSystemFilterCallbacks<br/>SFilter 附加到文件系统<br/>AntiHelper SetProtectDirectory 目录保护
    UB->>UB: IoAttachDeviceToDeviceStack<br/>附加到 usbhub/USBSTOR/hidusb<br/>白名单过滤
    PF->>PF: PsSetCreateProcessNotifyRoutine<br/>监控进程创建
    NF->>NF: FwpsCalloutRegister + FwpmCalloutAdd<br/>4个WFP Callout注册
    KB->>KB: IoAttachDeviceToDeviceStack<br/>附加到键盘设备栈<br/>UpperFilters 注册表注册<br/>8种键盘状态控制

    Note over NF,KB: 安装后强制重启生效<br/>KbDriver 写入 Keyboard 类 UpperFilters
```

---

## 图例说明

| 颜色 | 阶段 |
|---|---|
| 🟢 绿色 | 启动与注册 |
| 🟠 橙色 | 教师发现学生 |
| 🔵 蓝色 | 屏幕广播（核心） |
| 🔴 红色 | 行为管控 |
| ⬜ 灰色 | 考试流程 |
| 🩵 青色 | 文件传输 |
| 🩷 粉色 | 驱动安装 |

## 组件分组

```
┌─────────────────────────────┐
│  教师端                      │
│  Teacher + ScrCapture + Cfg │
└──────────┬──────────────────┘
           │ 注册服务器 / UDP组播
           ▼
┌─────────────────────────────┐
│  MMPC 服务（广播调度中枢）     │
└──────────┬──────────────────┘
           │ 共享内存 / 进程拉起
           ▼
┌─────────────────────────────┐
│  学生端用户态                 │
│  Student → MultiClient      │
│  ScreenRender → BlackSlient │
│  DeviceControl              │
└──────────┬──────────────────┘
           │ DeviceIoControl
           ▼
┌─────────────────────────────┐
│  内核驱动层                   │
│  KbFilter | OeNetLimit      │
│  easyusbflt | ProcFireWall  │
│  FbdATS                     │
└─────────────────────────────┘
```
