from ctypes import wintypes
from datetime import datetime
from functools import wraps
from math import ceil
import random
from flask import Flask, flash, jsonify, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
from cryptography.fernet import Fernet
import sqlite3
import subprocess
import configparser
import os
import ctypes
import win32security
import win32net
import win32netcon
import sys
import time




def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if os.name == 'nt' and not is_admin():
    print("请以管理员身份运行程序")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

# 读取配置文件
config = configparser.ConfigParser()
config.read('config.ini')

# 加密配置
cipher_suite = Fernet(config.get('security', 'encryption_key'))

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            encrypted_password BLOB,
            auth_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def create_system_user(username, password):
    try:
        if os.name == 'nt':
            # 转义特殊字符
            password = password.replace('"', r'\"')
            
            # 检查用户是否存在
            check_command = f'net user {username}'
            check_result = subprocess.run(
                check_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if "The command completed successfully" in check_result.stdout:
                app.logger.warning(f"用户 {username} 已存在")
                return False

            # 创建用户
            create_command = f'net user {username} "{password}" /ADD'
            result = subprocess.run(
                create_command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            app.logger.info(f"用户创建成功: {username}")
            return True
            
    except subprocess.CalledProcessError as e:
        error_msg = f"命令执行失败: {e.stderr.strip()}" if e.stderr else str(e)
        app.logger.error(f"用户创建失败: {error_msg}")
        return False
    except Exception as e:
        app.logger.error(f"系统错误: {str(e)}")
        return False

@app.route('/')
def index():
    return render_template('frontend/index.html')


# 生成随机字符串函数
def generate_random_string(length=4):
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(random.choice(chars) for _ in range(length))

import psutil
from flask import jsonify

@app.route('/api/system_status')
def system_status():
    # 获取CPU使用率
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # 获取内存信息
    mem = psutil.virtual_memory()
    mem_total = round(mem.total / (1024**3), 1)  # 转换为GB
    mem_used = round(mem.used / (1024**3), 1)
    mem_percent = mem.percent
    
    # 获取磁盘信息
    disk = psutil.disk_usage('/')
    disk_total = round(disk.total / (1024**3), 1)
    disk_used = round(disk.used / (1024**3), 1)
    disk_percent = disk.percent
    
    # 获取网络信息
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_recv = net_io.bytes_recv
    
    return jsonify({
        "cpu_percent": cpu_percent,
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "percent": mem_percent
        },
        "disk": {
            "total": disk_total,
            "used": disk_used,
            "percent": disk_percent
        },
        "network": {
            "sent": bytes_sent,
            "recv": bytes_recv
        },
        "timestamp": time.time()
    })
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 获取表单数据
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        auth_code = request.form.get('auth_code', '')
        user_captcha = request.form.get('captcha', '').upper()
        
        # 后端验证验证码
        server_captcha = session.get('captcha', '')
        if user_captcha != server_captcha:
            flash("验证码错误，请重新输入")
            return render_template('frontend/register.html',
                                 username=username,
                                 auth_code=auth_code,
                                 captcha_error=True)

        # 验证授权码
        if auth_code != config.get('security', 'auth_code'):
            flash("授权码错误")
            return render_template('frontend/register.html',
                                 username=username,
                                 auth_code=auth_code)

        try:
            # 数据库操作
            encrypted_pw = cipher_suite.encrypt(password.encode())
            conn = sqlite3.connect('database.db')
            conn.execute(
            "INSERT INTO users (username, encrypted_password, auth_code) VALUES (?, ?, ?)",
            (username, encrypted_pw, auth_code)
            )
            conn.commit()

            # 创建系统用户
            if create_system_user(username, password):
                flash("注册成功！")
                return redirect(url_for('index'))
            else:
                flash("系统用户创建失败，请联系管理员")
                conn.rollback()  # 回滚数据库操作

        except sqlite3.IntegrityError:
            flash("用户名已存在")
        except Exception as e:
            app.logger.error(f"注册错误: {str(e)}")
            flash("系统错误，请稍后再试")
        finally:
            if 'conn' in locals():
                conn.close()

        return render_template('frontend/register.html',
                             username=username,
                             auth_code=auth_code)
    
    # GET请求生成新验证码
    captcha = generate_random_string()
    session['captcha'] = captcha
    return render_template('frontend/register.html', captcha=captcha)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', next=request.url))
        return f(*args,**kwargs)
    return decorated_function

@app.template_filter('datetimeformat')
def datetimeformat_filter(value):
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M')
    except ValueError:
        return datetime.strptime(value, '%Y-%m-%d %H:%M').strftime('%Y-%m-%d %H:%M')


@app.context_processor
def inject_config():
    return dict(config=app.config)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        attempt_ip = request.remote_addr
        if request.form['secret_key'] == config.get('security', 'admin_secret'):
            # 记录成功日志
            app.logger.info(f'Admin login success from IP: {attempt_ip}')
            session['admin_logged_in'] = True
            session.permanent = True  # 启用持久会话
            flash('登录成功', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            # 记录失败尝试
            app.logger.warning(f'Admin login failed from IP: {attempt_ip}')
            return "密钥错误"
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # 获取总用户数
    total_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    # 获取最近24小时新增用户
    recent_users = c.execute(
        "SELECT COUNT(*) FROM users WHERE created_at > datetime('now', '-1 day')"
    ).fetchone()[0]
    
    # 分页查询
    offset = (page - 1) * per_page
    users = c.execute('''
        SELECT 
            id, 
            username, 
            auth_code, 
            strftime('%Y-%m-%d %H:%M', created_at) as formatted_date
        FROM users
        ORDER BY created_at DESC
    ''').fetchall()
    
    conn.close()
    
    # 分页对象
    pagination = Pagination(page=page, per_page=per_page, total=total_users)
    
    return render_template(
        'admin/dashboard.html',
        users=users,
        total_users=total_users,
        recent_users=recent_users,
        pagination=pagination
    )

class Pagination:
    def __init__(self, page, per_page, total):
        self.page = page
        self.per_page = per_page
        self.total = total
        self.pages = int(ceil(total / float(per_page)))
    
    def iter_pages(self, left_edge=2, left_current=2, right_current=5, right_edge=2):
        last = 0
        for num in range(1, self.pages + 1):
            if num <= left_edge or \
               (num > self.page - left_current - 1 and num < self.page + right_current) or \
               num > self.pages - right_edge:
                if last + 1 != num:
                    yield None
                yield num
                last = num

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    conn = sqlite3.connect('database.db')
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/refresh-captcha')
def refresh_captcha():
    new_captcha = generate_random_string()
    session['captcha'] = new_captcha
    return jsonify({'captcha': new_captcha})


@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.clear()
    flash('您已安全退出系统', 'success')
    return redirect(url_for('admin_login'))  # 改为跳转到登录页而不是首页

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


