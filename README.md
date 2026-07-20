# 用户管理系统 — SQL 注入漏洞修复版

## 项目说明

Flask + SQLite 用户管理系统，包含登录、注册、搜索功能。
已修复全部 3 处 SQL 注入漏洞，使用参数化查询 + 输入过滤 + 密码哈希。

## 修复内容

| 漏洞位置 | 修复前 | 修复后 |
|---------|--------|--------|
| 搜索功能 | f-string 拼接 SQL | 参数化查询 LIKE ? |
| 注册功能 | f-string 拼接 SQL | 参数化查询 + 密码 SHA-256 哈希 |
| 登录功能 | f-string 拼接 SQL | 参数化查询 + 哈希比对 |
| 输入处理 | 无过滤 | sanitize_input() 正则过滤 |
| 密码存储 | 明文 | SHA-256 哈希 |

## 快速启动

```bash
pip install flask
python app.py
```

访问 http://127.0.0.1:5000
默认账号: admin / admin123

## 文件结构

```
├── app.py                          # 主程序（已修复）
├── static/css/style.css            # 样式文件
├── templates/
│   ├── base.html                   # 基础模板
│   ├── index.html                  # 首页
│   ├── login.html                  # 登录页
│   ├── register.html               # 注册页
│   └── search_results.html         # 搜索结果页
└── data/users.db                   # SQLite 数据库（运行时自动创建）
```
