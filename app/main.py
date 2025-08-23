from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import os
import requests
import hashlib

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    # 设置session密钥
    app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-for-development")

    # 从环境变量获取Supabase配置
    SUPABASE_URL = os.environ.get("SUPABASE_URL")
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
    
    # 检查环境变量
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("请设置SUPABASE_URL和SUPABASE_KEY环境变量")
    
    def load_member_data():
        """从Supabase加载成员数据，按ID排序"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
            
        try:
            # 构建请求URL，添加排序参数
            url = f"{SUPABASE_URL}/rest/v1/members?order=id"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            # 发送GET请求获取数据
            response = requests.get(url, headers=headers)
            
            if response.ok:
                members = response.json()
                return {"members": members}
            else:
                print(f"获取数据失败: {response.text}")
                return None
                
        except Exception as e:
            print(f"从Supabase加载数据时出错: {e}")
            return None

    def update_member_data(member_id, name, score, description):
        """更新Supabase中的成员数据"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/members?id=eq.{member_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            
            # 构造要更新的数据
            data = {
                "name": name,
                "score": score,
                "description": description
            }
            
            # 发送PATCH请求更新数据
            response = requests.patch(url, headers=headers, json=data)
            
            if response.ok:
                return True
            else:
                print(f"更新数据失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"更新Supabase数据时出错: {e}")
            return False

    def create_member(name, score, description):
        """在Supabase中创建新成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/members"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            
            # 构造要创建的数据
            data = {
                "name": name,
                "score": score,
                "description": description
            }
            
            # 发送POST请求创建数据
            response = requests.post(url, headers=headers, json=data)
            
            if response.ok:
                return True
            else:
                print(f"创建数据失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"创建Supabase数据时出错: {e}")
            return False

    def delete_member(member_id):
        """从Supabase中删除成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/members?id=eq.{member_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            # 发送DELETE请求删除数据
            response = requests.delete(url, headers=headers)
            
            if response.ok:
                return True
            else:
                print(f"删除数据失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"删除Supabase数据时出错: {e}")
            return False

    def verify_admin_user(username, password):
        """验证管理员用户"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 对密码进行哈希处理
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # 查询用户
            url = f"{SUPABASE_URL}/rest/v1/admin_users?username=eq.{username}&password=eq.{hashed_password}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.ok:
                users = response.json()
                return len(users) > 0
            else:
                print(f"验证用户失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"验证管理员用户时出错: {e}")
            return False

    def get_admin_user(username, password):
        """获取管理员用户信息（用于验证密码）"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
            
        try:
            # 对密码进行哈希处理
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # 查询用户
            url = f"{SUPABASE_URL}/rest/v1/admin_users?username=eq.{username}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.ok:
                users = response.json()
                if len(users) > 0:
                    return users[0]
                return None
            else:
                print(f"获取用户信息失败: {response.text}")
                return None
                
        except Exception as e:
            print(f"获取管理员用户信息时出错: {e}")
            return None

    def update_admin_password(username, old_password, new_password):
        """更新管理员密码"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 验证旧密码是否正确
            user = get_admin_user(username, old_password)
            if not user:
                return False
            
            # 对新密码进行哈希处理
            new_hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            # 构建请求URL，使用用户ID作为更新条件更准确
            url = f"{SUPABASE_URL}/rest/v1/admin_users?id=eq.{user['id']}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            
            # 构造要更新的数据
            data = {
                "password": new_hashed_password
            }
            
            # 发送PATCH请求更新密码
            response = requests.patch(url, headers=headers, json=data)
            
            if response.ok:
                return True
            else:
                print(f"更新密码失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"更新管理员密码时出错: {e}")
            return False

    def create_admin_user(username, password):
        """创建管理员用户"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 对密码进行哈希处理
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/admin_users"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            
            # 构造要创建的数据
            data = {
                "username": username,
                "password": hashed_password
            }
            
            # 发送POST请求创建数据
            response = requests.post(url, headers=headers, json=data)
            
            if response.ok:
                return True
            else:
                print(f"创建管理员用户失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"创建管理员用户时出错: {e}")
            return False

    def login_required(f):
        """登录验证装饰器"""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'admin_logged_in' not in session:
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/')
    def index():
        """渲染主页面"""
        data = load_member_data()
        if data is None:
            return "无法从Supabase加载数据", 500
        
        return render_template('index.html', members=data['members'], 
                              last_updated="未知")

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        """管理员登录页面"""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if username and password and verify_admin_user(username, password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                return redirect(url_for('admin'))
            else:
                return render_template('login.html', error='用户名或密码错误')
        
        return render_template('login.html')

    @app.route('/admin/logout')
    def admin_logout():
        """管理员登出"""
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        return redirect(url_for('admin_login'))

    @app.route('/admin')
    @login_required
    def admin():
        """渲染后台管理页面"""
        data = load_member_data()
        if data is None:
            return "无法从Supabase加载数据", 500
        
        return render_template('admin.html', members=data['members'])

    @app.route('/admin/change-password', methods=['GET', 'POST'])
    @login_required
    def admin_change_password():
        """管理员修改密码"""
        if request.method == 'POST':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not old_password or not new_password or not confirm_password:
                return render_template('change_password.html', error='所有字段都是必填的')
            
            if new_password != confirm_password:
                return render_template('change_password.html', error='新密码和确认密码不匹配')
            
            if len(new_password) < 6:
                return render_template('change_password.html', error='密码长度至少6位')
            
            username = session.get('admin_username')
            if update_admin_password(username, old_password, new_password):
                return redirect(url_for('admin'))
            else:
                return render_template('change_password.html', error='修改密码失败，请检查旧密码是否正确')
        
        return render_template('change_password.html')

    @app.route('/admin/update', methods=['POST'])
    @login_required
    def admin_update():
        """处理更新成员数据的请求"""
        member_id = request.form.get('id')
        name = request.form.get('name')
        score = request.form.get('score')
        description = request.form.get('description')
        
        if member_id and name and score:
            success = update_member_data(member_id, name, int(score), description)
            if success:
                return redirect(url_for('admin'))
            else:
                return "更新失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/create', methods=['POST'])
    @login_required
    def admin_create():
        """处理创建新成员的请求"""
        name = request.form.get('name')
        score = request.form.get('score')
        description = request.form.get('description')
        
        if name and score:
            success = create_member(name, int(score), description)
            if success:
                return redirect(url_for('admin'))
            else:
                return "创建失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/delete/<int:member_id>')
    @login_required
    def admin_delete(member_id):
        """处理删除成员的请求"""
        if member_id:
            success = delete_member(member_id)
            if success:
                return redirect(url_for('admin'))
            else:
                return "删除失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/api/members')
    def api_members():
        """提供API接口获取成员数据"""
        data = load_member_data()
        if data is None:
            return jsonify({'error': '无法从Supabase加载数据'}), 500
        
        return jsonify(data)

    return app