# Os-Easy 多播教学系统 - Ghidra 分析报告

## 📊 分析完成情况

✅ **Teacher.exe** (教师端) - 分析耗时: 291秒
✅ **Student.exe** (学生端) - 分析耗时: 148秒

## 📁 文件统计

总目录大小: 768M
可执行文件: 72 个
动态链接库: 712 个

## 🔍 关键可执行文件

- AssistHelper.exe
- AudioDirectRepeater.exe
- AudioOrVideoBroadcast.exe
- AudioPlayRender.exe
- AudioRecordSender.exe
- AudioRender.exe
- AudioRepeater.exe
- AudioSender.exe
- BlackSlient.exe
- client_console.exe
- ConfBackupRestore.exe
- ConvertWordToXml.exe
- ConvertXmlToWord.exe
- DriverInstall.exe
- easyusbinstall.exe
- ffmpeg.exe
- FileTransferApp.exe
- InstallEx.exe
- InstallFbdATS.exe
- InstallServer.exe
- KbDriver.exe
- LissHelper.exe
- LoadDriver.exe
- ManagerWhtProcPath.exe
- MediaFileSender.exe
- MMPC.exe
- ModifyLimitConfig.exe
- MultiClient.exe
- MultiMediaConfig.exe
- MultiMediaConfigForTradition.exe

## 🗄️ Ghidra 项目信息

项目路径: /root/ghidra/projects/os-easy-analysis.rep/
项目大小: 267M

## 🔧 技术特征

- **开发框架**: MFC (Microsoft Foundation Classes)
- **编译器**: Visual Studio 2012
- **架构**: x86 (32位 PE)
- **语言**: C++
- **异常处理**: Windows SEH
- **类型信息**: 大量 RTTI 虚函数表

## 📝 关键组件说明

### Teacher.exe - 教师控制端
主程序，负责：
- 屏幕广播和录制
- 学生端管理和监控
- 远程控制功能
- 文件分发

### Student.exe - 学生接收端
客户端程序，负责：
- 接收教师端广播
- 执行远程命令
- 提交作业和反馈

### 辅助模块
- AudioDirectRepeater.exe
- AudioOrVideoBroadcast.exe
- AudioPlayRender.exe
- AudioRecordSender.exe
- AudioRender.exe
- AudioRepeater.exe
- AudioSender.exe
- FileTransferApp.exe
- VideoTechConsole.exe
- VideoTechUi.exe

## 🚀 使用 Ghidra 进行深入分析

### 方法1: 使用 Ghidra GUI
```bash
# 在有图形界面的系统上启动 Ghidra
ghidraRun
# 然后打开项目: /root/ghidra/projects/os-easy-analysis
```

### 方法2: 使用 Headless 模式导出
```bash
docker exec ghidra /ghidra/support/analyzeHeadless /projects os-easy-analysis -process Teacher.exe -postScript YourScript.java
```

## 🔐 安全分析建议

1. **网络协议逆向**
   - 搜索 socket/WSA 相关函数调用
   - 分析数据包结构和加密算法
   - 查找硬编码的密钥或凭证

2. **权限提升检查**
   - 查找 CreateProcess/ShellExecute 调用
   - 检查文件操作权限
   - 分析服务安装逻辑

3. **漏洞挖掘方向**
   - 缓冲区溢出 (strcpy, sprintf 等不安全函数)
   - 命令注入 (system, exec 等)
   - 路径遍历 (文件传输模块)
   - 认证绕过 (登录验证逻辑)

---
报告生成时间: 2026-09-06 12:06:54