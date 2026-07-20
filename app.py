from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
import re
import hashlib

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"


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
        phone TEXT
    )""")
    # 初始用户密码使用哈希存储
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", hash_password("admin123"), "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", hash_password("alice2025"), "alice@example.com", "13900139001"))
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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
