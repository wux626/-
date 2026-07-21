# 用户管理系统 - 安全加固版

Flask + SQLite 用户管理系统，包含登录、注册、搜索、头像上传功能。

## 安全加固内容

### 第一轮：SQL注入修复
- 参数化查询替代f-string拼接
- 输入过滤 sanitize_input()
- 密码 SHA-256 哈希存储

### 第二轮：文件上传安全加固
- 文件后缀白名单（仅图片格式）
- MIME 类型校验
- Magic Number 魔数验证
- 恶意代码内容深度检测
- 路径穿越防护（basename提取）
- UUID 重命名（防覆盖）
- 隐藏文件过滤（拒.htaccess等）
- 文件大小限制 2MB

## 快速启动
```bash
pip install flask
python app.py
```
访问 http://127.0.0.1:5000
默认账号：admin / admin123

