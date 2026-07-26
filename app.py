from flask import Flask, render_template, render_template_string, request, redirect, session
import sqlite3
import os
import re
import hashlib
import subprocess
import platform

import uuid
import secrets
from markupsafe import escape as html_escape
from functools import wraps

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB

# 确保上传目录存在
UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 文件上传安全配置
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
# 常见图片格式魔数（Magic Number）
IMAGE_MAGIC_NUMBERS = {
    b"\x89PNG": "png",
    b"\xff\xd8": "jpg/jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}


def validate_image_file(file):
    """对上传文件进行多维安全校验，返回 (是否合法, 错误信息)"""
    # 1. 检查文件名是否存在
    if not file or not file.filename:
        return False, "未选择文件"

    # 2. 路径穿越防护：仅提取纯文件名，丢弃路径信息
    safe_name = os.path.basename(file.filename)
    if safe_name != file.filename:
        return False, "文件名包含非法路径"

    # 3. 检查隐藏文件（以 . 开头）
    if safe_name.startswith("."):
        return False, "不支持上传隐藏文件"

    # 4. 检查文件后缀白名单
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"不支持的文件类型 .{ext}，仅支持：{', '.join(ALLOWED_EXTENSIONS)}"

    # 5. 检查 MIME 类型
    if file.content_type not in ALLOWED_MIMETYPES:
        return False, f"不支持的 MIME 类型：{file.content_type}"

    # 6. 检查文件内容魔数（Magic Number）并验证是否包含恶意内容
    file.seek(0)
    content = file.read()
    file.seek(0)

    # 6a. Magic Number 校验
    magic = content[:4]
    matched_format = None
    for header_bytes, fmt in IMAGE_MAGIC_NUMBERS.items():
        if magic.startswith(header_bytes):
            matched_format = fmt
            break
    if not matched_format:
        return False, "文件内容与图片格式不匹配，请上传真实图片文件"

    # 6b. 深度校验：检测是否嵌入脚本代码
    # 真实图片文件通常不含 PHP/JSP/ASP/JavaScript 代码标记
    suspicious_patterns = [b"<?php", b"<?=", b"<%", b"<script", b"javascript:", b"onload=",
                          b"onerror=", b"onclick=", b"system(", b"exec(", b"eval("]
    for pattern in suspicious_patterns:
        if pattern in content:
            return False, f"文件包含非法内容（检测到：{pattern.decode('utf-8', errors='replace')}），疑似恶意文件"

    # 6c. WebP 文件需要额外校验 RIFF 后的格式标识
    if matched_format == "webp":
        if content[8:12] not in [b"WEBP", b" webp"]:
            return False, "WebP 文件格式不正确"

    # 7. UUID 重命名：防止文件名冲突和路径穿越
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    return True, new_filename


def hash_password(password):
    """使用 SHA-256 哈希密码（生产环境应使用 bcrypt）"""
    return hashlib.sha256(password.encode()).hexdigest()


def sanitize_input(text, max_len=100):
    """过滤输入：去除危险字符，限制长度"""
    if not text:
        return ""
    # 只允许字母、数字、中文、@、.、-、_ 和空格
    text = re.sub(r'[^\w一-鿿@.\-\s]', '', str(text))
    return text[:max_len]


# ── CSRF 防护 ──
def generate_csrf_token():
    """生成并存储 CSRF Token 到 session"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(f):
    """CSRF Token 校验装饰器：验证请求中的 Token 是否与 session 中的一致"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return f(*args, **kwargs)
        # 从表单或请求头获取 CSRF Token
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        stored = session.get("csrf_token")
        if not token or not stored or not secrets.compare_digest(token, stored):
            return "CSRF Token 无效或缺失 — 请刷新页面重试", 403
        return f(*args, **kwargs)
    return wrapper


# ── Referer/Origin 来源校验 ──
def validate_referer():
    """检查请求来源是否为本站点，拒绝跨站请求"""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    allowed_host = request.host
    # 允许同源请求（无Origin/Referer的内部请求）
    if not origin and not referer:
        return True
    # 校验 Origin
    if origin:
        from urllib.parse import urlparse
        try:
            o = urlparse(origin)
            if o.hostname == allowed_host.split(":")[0] or o.hostname in ("localhost", "127.0.0.1"):
                return True
        except:
            pass
        return False
    # 校验 Referer
    if referer:
        from urllib.parse import urlparse
        try:
            r = urlparse(referer)
            if r.hostname == allowed_host.split(":")[0] or r.hostname in ("localhost", "127.0.0.1"):
                return True
        except:
            pass
        return False
    return True


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        balance REAL DEFAULT 0
    )""")
    # 兼容旧表：如果 balance 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    # 初始用户密码使用哈希存储
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", hash_password("admin123"), "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", hash_password("alice2025"), "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()


@app.route("/csrf-token")
def csrf_token():
    """返回 CSRF Token，供前端使用"""
    token = generate_csrf_token()
    return {"csrf_token": token}


# 全局注入 CSRF Token 到所有模板
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 使用参数化查询 — 安全
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            user = dict(row)
        conn.close()
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not validate_referer():
            return "请求来源不合法", 403
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 参数化查询 — 安全
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            stored_hash = row["password"]
            # 支持两种密码格式：哈希后的和新注册的明文（兼容过渡期）
            if stored_hash == hash_password(password) or stored_hash == password:
                session["username"] = row["username"]
                user = dict(row)
                conn.close()
                return render_template("index.html", user=user)
        conn.close()
        error = "用户名或密码错误"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
@validate_csrf
def register():
    msg = None
    if request.method == "POST":
        if not validate_referer():
            return "请求来源不合法", 403
        username = sanitize_input(request.form.get("username", ""), 30)
        password = request.form.get("password", "")
        email = sanitize_input(request.form.get("email", ""), 50)
        phone = sanitize_input(request.form.get("phone", ""), 20)

        # 基本校验
        if len(username) < 2:
            msg = "用户名至少 2 个字符"
        elif len(password) < 6:
            msg = "密码至少 6 个字符"
        else:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            try:
                # 参数化查询 — 安全
                c.execute(
                    "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                    (username, hash_password(password), email, phone)
                )
                conn.commit()
                msg = "注册成功，请登录"
            except sqlite3.IntegrityError:
                msg = "用户名已存在"
            except Exception as e:
                msg = f"注册失败: {e}"
            conn.close()
        return render_template("register.html", msg=msg)
    return render_template("register.html", msg=msg)


@app.route("/search")
def search():
    keyword = sanitize_input(request.args.get("keyword", ""))
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 参数化查询 — 安全
        like_pattern = f"%{keyword}%"
        c.execute(
            "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?",
            (like_pattern, like_pattern)
        )
        for row in c.fetchall():
            results.append(dict(row))
        conn.close()
    return render_template("search_results.html", keyword=keyword, results=results)


@app.route("/upload", methods=["GET", "POST"])
@validate_csrf
def upload():
    if "username" not in session:
        return redirect("/login")

    msg = None
    file_url = None

    if request.method == "POST":
        if not validate_referer():
            return "请求来源不合法", 403
        f = request.files.get("file")
        if not f or not f.filename:
            msg = "上传失败：未选择文件"
        else:
            is_valid, result = validate_image_file(f)
            if not is_valid:
                msg = f"上传失败：{result}"
            else:
                safe_filename = result  # UUID 重命名后的文件名
                save_path = os.path.join(UPLOAD_DIR, safe_filename)
                f.save(save_path)
                file_url = f"/static/uploads/{safe_filename}"
                msg = f"上传成功！文件：{safe_filename}"

    return render_template("upload.html", msg=msg, file_url=file_url)


@app.route("/profile")
def profile():
    # 从 session 获取当前登录用户名
    username = session.get("username")
    if not username:
        return redirect("/login")

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # 从 session 获取 user_id，不从 URL 参数获取
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return "用户不存在"

    return render_template("profile.html", user=dict(user))


@app.route("/recharge", methods=["POST"])
@validate_csrf
def recharge():
    if not validate_referer():
        return "请求来源不合法", 403
    # 从 session 获取当前登录用户
    username = session.get("username")
    if not username:
        return redirect("/login")

    amount = request.form.get("amount")
    if not amount:
        return "缺少参数：amount"

    try:
        amount = float(amount)
    except ValueError:
        return "金额格式错误"

    # 金额必须为正数
    if amount <= 0:
        return "充值金额必须为正数"

    # 单次充值上限
    if amount > 99999:
        return "单次充值金额不能超过 99999"

    conn = sqlite3.connect("data/users.db")
    # 基于当前登录用户更新余额，不信任前端传的 user_id
    conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    conn.commit()
    conn.close()

    # 重定向到个人中心（不带参数，从 session 获取身份）
    return redirect("/profile")


@app.route("/change-password", methods=["POST"])
@validate_csrf
def change_password():
    if not validate_referer():
        return "请求来源不合法", 403
    # 只要 session 中有登录状态即可操作
    if "username" not in session:
        return redirect("/login")

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return "缺少参数：username 或 new_password"

    # 直接更新密码字段，不验证原密码
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?",
              (hash_password(new_password), username))
    conn.commit()
    conn.close()

    return redirect("/profile")


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return "缺少参数：name"

    # [安全修复] 白名单机制：仅允许预定义的页面名称
    ALLOWED_PAGES = {"help", "about", "terms", "faq", "contact"}
    if name not in ALLOWED_PAGES:
        return "页面不存在"

    # [安全修复] 路径规范化：确保路径在 pages/ 目录内
    safe_name = name.replace("../", "").replace("..\\", "")
    safe_name = os.path.basename(safe_name)
    page_path = os.path.join("pages", safe_name)

    # 读取内容并进行 XSS 过滤
    if os.path.isfile(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            raw = f.read()
        # 过滤危险的 HTML 标签和事件处理器
        safe_content = re.sub(r'<script[^>]*>.*?</script>', '', raw, flags=re.DOTALL | re.IGNORECASE)
        safe_content = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', '', safe_content, flags=re.IGNORECASE)
        safe_content = re.sub(r'javascript\s*:', '', safe_content, flags=re.IGNORECASE)
        return render_template("index.html", page_content=safe_content)

    # 尝试加 .html 后缀
    page_path_html = page_path + ".html"
    if os.path.isfile(page_path_html):
        with open(page_path_html, "r", encoding="utf-8") as f:
            raw = f.read()
        # [XSS修复] 过滤危险脚本标签和事件处理器
        safe_content = re.sub(r'<script[^>]*>.*?</script>', '', raw, flags=re.DOTALL | re.IGNORECASE)
        safe_content = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', '', safe_content, flags=re.IGNORECASE)
        safe_content = re.sub(r'javascript\s*:', '', safe_content, flags=re.IGNORECASE)
        return render_template("index.html", page_content=safe_content)

    return "页面不存在"


# ── 个性化页面 ──

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "亲爱的用户")
    # 安全：使用 render_template 传参，用户输入不会被解析为模板代码
    return render_template("welcome.html", name=name)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # 安全：使用 render_template 传参，用户输入不会被解析为模板代码
        return render_template("feedback_result.html", name=name, message=message)

    # GET — 显示反馈表单（无用户输入，安全）
    return render_template_string("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户反馈</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-left">
            <a href="/" class="brand">用户管理系统</a>
        </div>
        <div class="nav-right">
            <a href="/" class="nav-link">首页</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
            <a href="/search" class="nav-link">搜索</a>
        </div>
    </nav>
    <main class="container">
        <div class="card">
            <h2 class="card-title">用户反馈</h2>
            <form method="post" action="/feedback" class="form">
                <div class="form-group">
                    <label for="name">您的姓名</label>
                    <input type="text" id="name" name="name" class="form-input" placeholder="请输入姓名" required>
                </div>
                <div class="form-group">
                    <label for="message">留言内容</label>
                    <textarea id="message" name="message" class="form-input" rows="5" placeholder="请输入您的意见或建议" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">提交反馈</button>
            </form>
        </div>
    </main>
</body>
</html>""")


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")

    result = None
    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            # [修复1] IP白名单校验：只允许IP地址格式
            if not re.match(r'^[\d.]+$', ip):
                result = "错误：IP地址格式不正确，请检查输入"
            else:
                try:
                    # [修复2] 列表传参，禁用 shell=True，彻底阻断命令注入
                    cmd = ["ping", "-c", "3", ip]
                    output = subprocess.check_output(cmd, timeout=30, stderr=subprocess.STDOUT)
                    result = output.decode("utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    result = "错误：Ping 超时（30秒）"
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace")
                except Exception as e:
                    result = f"错误：{str(e)}"

    return render_template("ping.html", result=result, ip=request.form.get("ip", ""))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
