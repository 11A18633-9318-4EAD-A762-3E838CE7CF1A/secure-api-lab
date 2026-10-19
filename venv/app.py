import sqlite3
from flask import Flask, request, jsonify
from markupsafe import escape       # 用于 XSS 防护
import jwt, bcrypt, datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-prod'

# ----------------- 基础数据库配置 -----------------
def get_db():
    conn = sqlite3.connect('lab.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

# ----------------- 安全措施 ③：JWT 校验中间件 -----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# ----------------- 自选端点：注册（包含 SQLi 防护） -----------------
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    
    # 安全措施 ③：密码哈希
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = get_db()
    try:
        # 安全措施 ①：SQLi 防护（参数化查询）
        conn.execute('INSERT INTO users (login, password_hash) VALUES (?, ?)',
                     (login, hashed.decode('utf-8'))) 
        conn.commit()
        return jsonify({'message': 'registered'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'user exists'}), 400
    finally:
        conn.close()

# ----------------- 端点 1：登录（包含 SQLi 防护 + JWT 签发） -----------------
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    
    conn = get_db()
    # 安全措施 ①：SQLi 防护（参数化查询）
    user = conn.execute('SELECT * FROM users WHERE login = ?', (login,)).fetchone()
    conn.close()
    
    # 安全措施 ③：验证密码哈希 + 签发 JWT
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    
    return jsonify({'error': 'invalid credentials'}), 401

# ----------------- 端点 2：获取数据（包含 JWT 拦截 + XSS 防护） -----------------
@app.route('/api/data')
@token_required # 安全措施 ③：使用中间件拦截，必须带 Token 才能访问
def get_data():
    conn = get_db()
    users = conn.execute('SELECT id, login FROM users').fetchall()
    conn.close()
    
    # 安全措施 ②：XSS 防护（对返回的用户数据进行 HTML 转义）
    safe_users = [{'id': u['id'], 'login': str(escape(u['login']))} for u in users]
    return jsonify({'data': safe_users})

if __name__ == '__main__':
    app.run(debug=True, port=5000)