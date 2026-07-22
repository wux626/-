from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
import re
import hashlib

import uuid

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
def register():
    msg = None
    if request.method == "POST":
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
def upload():
    if "username" not in session:
        return redirect("/login")

    msg = None
    file_url = None

    if request.method == "POST":
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
def recharge():
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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
