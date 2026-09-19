# ScreenSender.exe 组件深度逆向（屏幕广播/远程监视上行编码器）

> 样本：`samples/os-easy/ScreenSender.exe`（544256 字节，PE32 i386 **console**）
> 反编译：Ghidra 12.1.3 headless，4216 函数，存档 `/root/ghidra/mmpc/screensender_x86.txt`

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/ScreenSender.exe` |
| 大小 | 544256 字节 |
| 架构/类型 | PE32 i386 console（FFmpeg 编码 + UDP 推流） |
| MD5 | `4ef62de8ec22eaf0720fc2151b2c5876` |

## 1. 定位与职责

**学生端屏幕"上行"推流器**：把本机屏幕（或摄像头/外部源）编码后经 **UDP**（可选 TCP）推给教师端，用于教师端**远程监视（看学生屏幕）**与屏幕广播采集。由 `StudentLogic.dll`/`Student.exe` 按需拉起，命令行由 `StudentLogic` 的 `FUN_10088ca0` 构造：

```
--mouse %d --protocol %s --bindip %s --bindport %d --remote %s --port %d
--encoderType %s --quality %d --waitseconds %d --width %d --height %d
```

与 `ScreenRender.exe`（下行解码渲染）方向相反：Sender 是**学生→教师**，Render 是**教师→学生**。

## 2. 技术栈

| 依赖 | 用途 |
|---|---|
| **FFmpeg**（avcodec-57 / avformat-57 / avdevice-57 / avutil-55 / swscale-4） | 屏幕/视频编码（H264）、摄像头采集 |
| **boost.asio**（静态，`win_iocp_socket_service<udp>`） | UDP 异步推流（IOCP） |
| WS2_32 | socket 底层 |
| GDI32 / USER32 | `GetDesktopWindow` / `GetDC` / `BitBlt` 屏幕抓取 |
| boost program_options | 命令行参数解析 |

## 3. 架构（RTTI 类名还原出的数据流管线）

```
DataSource (抽象基类)
 ├─ DisplayDataSource   ← 本机屏幕: GetDesktopWindow→GetDC→BitBlt 抓帧
 ├─ CameraDataSource    ← 摄像头: avdevice/avformat (av_find_input_format/av_read_frame)
 └─ OuterDataSource     ← 外部源 (outer_port 接收, 供级联/转发)
        │  (boost bind: DataSource::Run → 回调)
        ▼
   IEncoder
 ├─ FFmpegEncoder       ← H264 (avcodec_find_encoder / av_frame_alloc / av_init_packet; 参数 H264Quality/quality)
 ├─ NoneEncoder         ← 原始帧不编码
 └─ CropRet 裁剪回调     ← mf2(IEncoder, CropRet, bool)
        ▼
   IPacker (vftable @47032)
 ├─ UdpImagePacker      ← UDP 分包 (bindip/bindport/remote/port)
 └─ TcpImagePacker      ← TCP 打包 (vftable @47072)
        ▼
   UdpSender            ← boost::asio udp socket, IOCP 异步
```

`boost::bind` 模板符号明确：`mf0(DisplayDataSource)` 抓帧回调、`mf1(UdpSender, string)`、`mf2(IEncoder, CropRet, bool)`、`mf2(UdpSender, ptr, u8, u16)`、`mf2(UdpSender, string, u32, u8, u16)` —— 即"数据源→编码器→打包→UDP 发送"三级回调串联，多协程并发（`thread_data` × MainApp/DisplayDataSource/UdpSender/Encoder）。

## 4. 命令行参数（program_options 名）

| 参数 | 含义 |
|---|---|
| `dataSource` | 数据源类型（display/camera/outer；不支持时报 `not support dataSource:`） |
| `encoderType` | 编码器（H264/none；`not support Encoder format:`） |
| `quality` / `H264Quality` | 编码质量 |
| `mouse` | 是否采集鼠标 |
| `protocol` | udp / tcp（`not Support this TransferType`） |
| `bindip` / `bindport` | 本地绑定（`bindip:%s`/`new bindip:%s`/`bind failed:`） |
| `remote` / `port` | 目标（教师端）地址/端口 |
| `outer_port` | 外部源接收端口 |
| `verfityPort` / `ScreenUdpVerityPort` | UDP 校验端口（双端口机制：数据 + 校验，防丢包/同步） |
| `waitseconds` | 等待秒数 |
| `width` / `height` | 分辨率；`[ResolutionChanged]currentWidth:%d,currentHeight:%d` 自适应 |

## 5. socket 生命周期（应用函数）

`create socket failed` → `bind socket failed` → `socket listen failed`（UDP "listen" 即 bind）→ `CreateSubRemotes`（`CreateSubRemotes bind failed:` / `create failed:` —— **多目标/子远程**，支持一对多推流到多个教师端接收点）。

## 6. 体系位置

```
教师端远程监视:
  Teacher(教师请求看学生A) → MainLogic.dll → WS 下发"启动推流" → StudentLogic
  → CreateProcess ScreenSender.exe --dataSource display --protocol udp
     --remote <教师IP> --port <N> --bindip <学生IP> --bindport <M>
     --encoderType H264 --quality X --mouse 1 --width W --height H
  → 学生屏 BitBlt → H264 → UdpImagePacker → UDP(数据port + verfityPort) → 教师端 ScreenRender/接收
```

## 7. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `0x401010/0x401018` | av_init_packet / av_free_packet（FFmpeg 帧包） |
| `0x44ecd0` | `verfityPort` 配置读取 |
| `0x40aa20` | 日志/错误（create/bind/listen socket failed） |
| `0x47032` | `IPacker` vftable |
| `0x47072` | `TcpImagePacker` vftable |
| `~0x44fxxx`（51072 行区） | socket 创建/bind 序列 |

## 8. 未决项

1. UDP 数据帧的**确切字节格式**（帧头/序号/时间戳布局）——需与 ScreenRender 接收侧对拍或实抓；
2. `ScreenUdpVerityPort` 校验端口的协议内容（心跳/ACK/重传？）；
3. `CreateSubRemotes` 多目标的具体寻址（广播/组播/单播列表）；
4. CameraDataSource 的 avdevice 输入格式与 Display 的切换逻辑。