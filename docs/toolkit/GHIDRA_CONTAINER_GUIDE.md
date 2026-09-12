# Ghidra 独立容器使用指南

## 📦 容器信息

- **容器名称**: `ghidra`
- **镜像**: `blacktop/ghidra:latest`
- **Ghidra 版本**: 12.1.3
- **Java 版本**: OpenJDK 21.0.11 LTS
- **端口映射**: 13100-13101（Ghidra Server）

## 📁 目录挂载

- `/root/ghidra/projects` → `/projects` (Ghidra 项目)
- `/root/ghidra/samples` → `/samples` (待分析文件)
- `/root/ghidra/scripts` → `/scripts` (自定义脚本)

## 🚀 常用命令

### 1. 无头分析（Headless Analysis）

```bash
# 分析单个二进制文件
docker exec ghidra /ghidra/support/analyzeHeadless \
  /projects MyProject \
  -import /samples/binary_file \
  -postScript ExportScript.py

# 批量分析目录
docker exec ghidra /ghidra/support/analyzeHeadless \
  /projects MyProject \
  -import /samples/ \
  -recursive
```

### 2. 容器管理

```bash
# 查看容器状态
docker ps | grep ghidra

# 查看容器日志
docker logs ghidra

# 进入容器交互式 shell
docker exec -it ghidra bash

# 重启容器
docker restart ghidra

# 停止容器
docker stop ghidra

# 启动容器
docker start ghidra
```

### 3. 文件操作

```bash
# 将待分析文件复制到 samples 目录
cp /path/to/binary /root/ghidra/samples/

# 查看分析结果
ls -la /root/ghidra/projects/
```

## 🎯 快速开始示例

```bash
# 1. 准备待分析文件
echo "将你的二进制文件放到 /root/ghidra/samples/ 目录"

# 2. 运行分析
docker exec ghidra /ghidra/support/analyzeHeadless \
  /projects test_project \
  -import /samples/your_binary \
  -overwrite

# 3. 查看结果
ls -la /root/ghidra/projects/test_project.rep/
```

## ⚙️ 与 AstrBot 的区别

- ✅ **独立运行**: 不依赖 AstrBot 容器
- ✅ **版本稳定**: 不会因为 AstrBot 更新而丢失
- ✅ **专用工具**: 专门用于逆向分析任务
- ✅ **资源隔离**: 独立的内存和 CPU 配额（MAXMEM=2G）

---

**部署时间**: 2026-09-06  
**管理员**: root