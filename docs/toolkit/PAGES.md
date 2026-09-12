# 多页面自动发现系统

## 概述

Manager 采用**零配置**的多页面架构：开发者只需按约定创建页面文件，应用启动时会自动扫描、注册、生成导航栏。

**核心特性：**
- 📁 **约定优于配置**：文件名即配置
- 🔍 **自动发现**：无需手动注册
- 🔄 **热插拔**：新增页面无需修改主窗口代码
- 📊 **顺序控制**：数字前缀决定导航栏顺序

---

## 快速开始

### 1. 创建页面文件

在 `src/gui/pages/` 目录下创建文件，命名格式：

```
[数字]_[页面名]_page.py
```

**示例：**
```bash
touch src/gui/pages/03_settings_page.py
```

**命名规则：**
- `数字`：两位数字（如 `01`、`02`），决定导航栏显示顺序
- `页面名`：小写英文单词（如 `home`、`settings`、`user_profile`）
- 后缀：必须是 `_page.py`

### 2. 编写页面代码

继承 `BasePage` 并实现三个核心接口：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""设置页面"""

import tkinter as tk
from tkinter import ttk
from .base_page import BasePage


class SettingsPage(BasePage):
    """设置页面"""

    @property
    def title(self) -> str:
        """导航栏显示的文字"""
        return "设置"

    @property
    def icon(self) -> str:
        """导航栏显示的图标（emoji）"""
        return "⚙️"

    def build_ui(self):
        """构建页面内容（只调用一次）"""
        ttk.Label(
            self, 
            text="这是设置页面", 
            font=("", 16)
        ).pack(padx=20, pady=20)

    def on_enter(self):
        """进入页面时调用（可选）"""
        print("进入设置页")

    def on_leave(self):
        """离开页面时调用（可选）"""
        print("离开设置页")
```

### 3. 重启应用

```bash
python main.py
```

应用会自动：
1. 扫描 `pages/` 目录
2. 发现 `03_settings_page.py`
3. 加载 `SettingsPage` 类
4. 在导航栏生成 "⚙️ 设置" 按钮

---

## BasePage 接口说明

### 必须实现的属性

#### `title` (property)
- **类型**：`str`
- **用途**：导航栏显示的文字
- **示例**：`"首页"`、`"关于"`

#### `icon` (property)
- **类型**：`str`
- **用途**：导航栏显示的图标（推荐使用 emoji）
- **示例**：`"🏠"`、`"ℹ️"`、`"⚙️"`

#### `build_ui()` (method)
- **用途**：构建页面 UI（只会被调用一次）
- **注意**：在这里创建所有控件，不要在 `__init__` 中创建
- **示例**：
  ```python
  def build_ui(self):
      self.columnconfigure(0, weight=1)
      ttk.Label(self, text="内容").pack()
  ```

### 可选实现的生命周期方法

#### `on_enter()`
- **触发时机**：页面被切换到时
- **用途**：刷新数据、更新状态
- **示例**：
  ```python
  def on_enter(self):
      self.refresh_data()
  ```

#### `on_leave()`
- **触发时机**：页面被切换离开时
- **用途**：保存状态、清理资源
- **示例**：
  ```python
  def on_leave(self):
      self.save_draft()
  ```

### 可用的成员变量

- `self.parent`：父容器（`tk.Frame`）
- `self.app_controller`：主窗口控制器（`MainWindow` 实例）

---

## 页面间交互

### 访问其他页面

```python
# 在页面内访问主窗口
main_window = self.app_controller

# 获取其他页面实例
home_page = main_window.pages.get('home')
if home_page:
    home_page.refresh()
```

### 切换到其他页面

```python
# 通过主窗口控制器切换
self.app_controller._switch_page('settings')
```

---

## 完整示例

### 示例 1：数据展示页

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""数据页面"""

import tkinter as tk
from tkinter import ttk
from .base_page import BasePage
from src.core.engine import Engine


class DataPage(BasePage):
    """数据页面"""

    def __init__(self, parent, app_controller, **kwargs):
        super().__init__(parent, app_controller, **kwargs)
        self.engine = Engine()

    @property
    def title(self) -> str:
        return "数据"

    @property
    def icon(self) -> str:
        return "📊"

    def build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # 标题
        ttk.Label(
            self, 
            text="数据总览", 
            font=("", 18, "bold")
        ).grid(row=0, column=0, sticky=tk.W, padx=20, pady=20)

        # 数据框架
        self.data_text = tk.Text(self, height=15)
        self.data_text.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        # 刷新按钮
        ttk.Button(
            self, 
            text="刷新", 
            command=self.refresh
        ).grid(row=2, column=0, pady=(0, 20))

    def on_enter(self):
        self.refresh()

    def refresh(self):
        status = self.engine.get_status()
        self.data_text.delete("1.0", tk.END)
        self.data_text.insert("1.0", str(status))
```

### 示例 2：表单页

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""表单页面"""

import tkinter as tk
from tkinter import ttk, messagebox
from .base_page import BasePage


class FormPage(BasePage):
    """表单页面"""

    @property
    def title(self) -> str:
        return "表单"

    @property
    def icon(self) -> str:
        return "📝"

    def build_ui(self):
        self.columnconfigure(1, weight=1)

        # 输入字段
        ttk.Label(self, text="名称:").grid(
            row=0, column=0, sticky=tk.W, padx=20, pady=(20, 8)
        )
        self.name_entry = ttk.Entry(self)
        self.name_entry.grid(
            row=0, column=1, sticky="ew", padx=(0, 20), pady=(20, 8)
        )

        ttk.Label(self, text="描述:").grid(
            row=1, column=0, sticky=tk.W, padx=20, pady=8
        )
        self.desc_entry = ttk.Entry(self)
        self.desc_entry.grid(
            row=1, column=1, sticky="ew", padx=(0, 20), pady=8
        )

        # 提交按钮
        ttk.Button(
            self, 
            text="提交", 
            command=self.submit
        ).grid(row=2, column=1, sticky=tk.E, padx=20, pady=20)

    def submit(self):
        name = self.name_entry.get()
        desc = self.desc_entry.get()
        messagebox.showinfo("提交", f"名称: {name}\n描述: {desc}")
```

---

## 目录结构

```
src/gui/pages/
├── __init__.py              # 导出 BasePage、PageRegistry
├── base_page.py            # 页面基类
├── discovery/              # 自动发现引擎
│   ├── __init__.py
│   ├── scanner.py          # 文件扫描器
│   ├── loader.py           # 动态加载器
│   └── registry.py         # 页面注册表
├── 01_home_page.py         # 首页
├── 02_about_page.py        # 关于页
└── 03_settings_page.py     # 设置页（你的新页面）
```

---

## 工作原理

### 启动流程

```
应用启动
    ↓
MainWindow.__init__()
    ↓
_load_all_pages()
    ↓
PageRegistry.get_all()  ← 首次调用触发扫描
    ↓
scanner.scan_pages()  ← 扫描 pages/ 目录
    ↓
发现: [01_home_page.py, 02_about_page.py, 03_settings_page.py]
    ↓
loader.load_page_class()  ← 动态导入每个模块
    ↓
提取: {home: HomePage, about: AboutPage, settings: SettingsPage}
    ↓
registry 缓存结果
    ↓
MainWindow 实例化所有页面 + 生成导航栏
    ↓
切换到第一个页面（home）
```

### 文件扫描规则

`scanner.py` 会：
1. 列出 `pages/` 目录下所有 `.py` 文件
2. 匹配模式：`^\d+_([a-z_]+)_page\.py$`
3. 提取数字、页面名、文件名
4. 按数字排序返回

### 类加载规则

`loader.py` 会：
1. 构建模块名：`src.gui.pages.01_home_page`
2. 动态 `import_module()`
3. 推断类名：`HomePage`（页面名首字母大写 + `Page`）
4. 从模块中提取该类
5. 验证是否继承自 `BasePage`

---

## 常见问题

### Q: 页面没有自动出现在导航栏？

**检查清单：**
1. 文件名是否符合格式：`[数字]_[名称]_page.py`
2. 类名是否正确：如 `home` → `HomePage`
3. 是否继承自 `BasePage`
4. 是否实现了 `title`、`icon`、`build_ui`
5. 重启应用

### Q: 如何调整页面顺序？

修改文件名的数字前缀：
```bash
mv 03_settings_page.py 01_settings_page.py  # 设置页移到最前
mv 01_home_page.py 02_home_page.py          # 首页后移
```

### Q: 如何隐藏某个页面？

重命名文件，去掉 `_page.py` 后缀：
```bash
mv 03_settings_page.py 03_settings_page.py.disabled
```

### Q: 如何在页面中调用核心业务逻辑？

遵循分层原则：
```python
from src.core.engine import Engine

class MyPage(BasePage):
    def __init__(self, parent, app_controller, **kwargs):
        super().__init__(parent, app_controller, **kwargs)
        self.engine = Engine()  # 实例化核心引擎
    
    def process_data(self):
        result = self.engine.process("数据")  # 调用业务层
        # 更新 UI
```

---

## 最佳实践

1. **分层清晰**：页面只做展示，业务逻辑放在 `src/core/`
2. **懒加载数据**：在 `on_enter()` 中刷新，不要在 `build_ui()` 中
3. **清理资源**：在 `on_leave()` 中保存状态、停止定时器
4. **命名一致**：文件名 `user_profile_page.py` → 类名 `UserProfilePage`
5. **emoji 统一**：使用单个 emoji 图标，保持风格一致