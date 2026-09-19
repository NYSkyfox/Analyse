# ScreenRender.exe 组件深度逆向（屏幕广播/远程桌面下行渲染器）

> 样本：`samples/os-easy/ScreenRender.exe`（450048 字节，PE32 i386 GUI）
> PDB：`D:\dmt\master\10.9\Output\Release\ScreenRender.pdb`（V10.9 构建）
> 反编译：Ghidra 12.1.3 headless，3016 函数，存档 `/root/ghidra/mmpc/screenrender_x86.txt`

## 0. 样本信息

| 项 | 值 |
|---|---|
| 路径 | `samples/os-easy/ScreenRender.exe` |
| 大小 | 450048 字节 |
| 架构/类型 | PE32 i386 GUI（FFmpeg 解码 + SDL2 渲染） |
| MD5 | `76cfa20119b247685827d9341132570a` |
| SHA-256 | `f7f750908edf7a748b22b4d9dc054ff56859007acf5aca0f5354fbf4086d7729` | — |
| 内嵌 PDB | `D:\dmt\master\10.9\Output\Release\ScreenRender.pdb`（V10.9） |

## 1. 定位与职责

**屏幕"下行"接收渲染器**：接收教师端（或级联节点）推来的屏幕码流，**FFmpeg 解码 → SDL2 全屏渲染**，用于：
- **屏幕广播**（教师桌面 → 全体/分组学生屏幕，全屏幕蔽显示）；
- **远程桌面/演示**（教师看学生时反向、或教师演示机渲染学生画面）。

由 `StudentLogic.dll`/`Student.exe` 按需拉起（命令行与 ScreenSender 同源：`--mouse --protocol --bindip --bindport --remote --port --encoderType --quality --waitseconds --width --height`，本进程主要消费 `remote/port/bindport/fullscreen/mouse/width/height`）。

与 `ScreenSender.exe` 方向相反：**Render = 教师→学生**（收+解+显），**Sender = 学生→教师**（抓+编+发）。

## 2. 技术栈

| 依赖 | 用途 |
|---|---|
| **SDL2**（`SDL_Init/CreateWindowFrom/CreateRenderer/CreateTexture/UpdateYUVTexture/RenderClear/RenderCopy/RenderPresent/SetWindowSize/SetWindowPosition`） | 窗口 + 渲染 + 显示 |
| **FFmpeg**（avcodec-57/avformat-57/avutil-55/swscale-4） | 解码（`avcodec_decode_video2` / `avcodec_find_decoder`，参数 `decoderName`）+ YUV→RGB 转换 |
| boost.asio | UDP 接收（IOCP 协程） |
| WS2_32 | socket |
| GDI32/USER32 | 鼠标/窗口辅助 |

## 3. 渲染管线

```
UDP 接收 (asio, bindport; 双端口: 数据+verfity)
  → FFmpeg 解码: avcodec_find_decoder(decoderName) → avcodec_decode_video2
      (帧缓冲: free decoded_frame / render:0x%08x)
  → swscale YUV→纹理
  → SDL: SDL_UpdateYUVTexture → SDL_RenderClear → SDL_RenderCopy → SDL_RenderPresent
```

窗口策略（`~29595` 行）：
1. `SDL_CreateWindowFrom(hwnd)` —— **可附着到既有 HWND**（宿主窗口内嵌显示，对应 MultiClient 的广播窗口）；
2. 失败/独立模式：`SDL_CreateRenderer`（硬件）→ 失败回退 `"Create SoftWare Render"`（`SDL_RENDERER_SOFTWARE`）；
3. 全屏：`fullscreen` / `m_nFullScreen:%d` + `SDL_SetWindowSize`/`SDL_SetWindowPosition` + `currentWidth:%d,currentHeight:%d` 自适应；
4. 鼠标：`The mouse is currently in the hide state %d` —— **广播模式下默认隐藏本地鼠标**（显示的是教师端远程鼠标，`--mouse` 控制）。

`ScreenRenderApp` 主类（`boost::_bi::mf3<void,ScreenRenderApp,string,short,string>` 四参回调：数据串 + 端口/类型 + 控制串，对应接收/控制双通道）。

## 4. 命令行/参数消费

| 参数 | 用途 |
|---|---|
| `remote` / `port` | 教师端地址（接收校验/控制回连） |
| `bindport` | 本机接收端口 |
| `fullscreen` | 全屏模式 |
| `mouse` | 是否显示/跟踪远程鼠标 |
| `width` / `height` | 初始分辨率 |
| `decoderName` | 指定解码器 |
| `waitseconds` | 等待窗口就绪 |

## 5. 体系位置（屏幕广播闭环）

```
屏幕广播(下行):
  Teacher.exe(教师点广播) → MainLogic.dll::BroadCastRect/SwitchOnWhiteboard
  → WS 下发 → 学生 MultiClient 收到 StartCheckDesktop/FullScreen/dmt_screen_open
  → StudentLogic 拉起 ScreenRender.exe --fullscreen 1 --mouse 0 --remote <教师IP> --port N
  → 教师端 ScreenSender(教师机) BitBlt 教师屏 → H264 → UDP 广播/单播
  → 学生 ScreenRender 解码 → SDL2 全屏(隐藏本地鼠标) → 显示教师画面
  → 教师 StopBlackScreen/StopBroadcast → 杀 ScreenRender → 恢复学生桌面
远程监视(上行, 对偶): 学生 ScreenSender → 教师端接收渲染
```

## 6. 函数索引（关键锚点）

| 地址 | 功能 |
|---|---|
| `0x401028` | avcodec_decode_video2 导入桩 |
| `~0x43c290/0x439530`（24529 行） | `decoderName` 配置读取 |
| `~0x41xxxx`（29595 行） | SDL 窗口/渲染器创建（WindowFrom + 软渲染回退） |
| `~0x41xxxx`（29629 行） | 解码帧释放（`free decoded_frame`） |
| `~0x41xxxx`（29924 行） | 鼠标隐藏状态日志 |
| `0x4096a0` / `0x41ec50` | 错误/日志（`bind Failed` / `bind failed:%d`） |
| `0x450563~0x45059x` | SDL2 导入桩区（CreateWindowFrom/CreateRenderer/UpdateYUVTexture…） |

## 7. 未决项

1. UDP 帧格式与 ScreenSender 的对拍（帧头/序号/YUV 布局）——需实抓或交叉比对两侧 Packer 代码；
2. `SDL_CreateWindowFrom` 的宿主 HWND 来源（MultiClient 窗口句柄如何传入，推测经命令行/父窗口）；
3. 控制通道（`mf3` 四参回调中的 control string）内容——广播启停/鼠标事件回传；
4. 多学生同时广播时的组播/单播策略（教师端 ScreenSender `CreateSubRemotes` 侧对应）。