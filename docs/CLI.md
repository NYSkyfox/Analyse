# CLI 使用指南

## 运行方式

### 直接运行（从项目根目录，无需安装）

```bash
python main.py --cli
python main.py --cli --help
```

### 安装为可执行命令后

```bash
pip install -e .
manager
```

### 基本用法

```bash
# 显示帮助信息
python main.py --cli --help

# 处理数据
python main.py process "你的输入数据"

# 处理数据并保存到文件
python main.py process "你的输入数据" -o output.txt

# 显示状态
python main.py status

# 显示版本
python main.py --cli --version
```

## 命令详解

### process 命令

处理输入数据并返回结果。

```bash
python main.py process [选项] <输入数据>
```

**选项:**
- `-o, --output FILE` - 将结果保存到文件

**示例:**
```bash
python main.py process "Hello World"
python main.py process "数据" -o result.txt
```

### status 命令

显示应用状态信息。

```bash
python main.py status
```

## 全局选项

- `-v, --verbose` - 显示详细输出（调试信息）
- `--version` - 显示版本号
- `--cli` - 强制使用 CLI 模式
- `--gui` - 尝试使用 GUI 模式（GUI 不可用时自动降级到 CLI）

## 环境变量

可以通过环境变量配置应用行为：

```bash
export MANAGER_DEBUG=true
export MANAGER_LOG_LEVEL=DEBUG
python main.py process "test"
```

## 在脚本中使用

```python
from src.core.engine import Engine

engine = Engine()
result = engine.process("your input")
print(result)
```