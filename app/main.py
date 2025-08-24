from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import os
import requests
import hashlib
from datetime import datetime
import pytz

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    # 设置session密钥
    app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-for-development")

    # 添加时间格式化过滤器
    @app.template_filter('format_datetime')
    def format_datetime(value):
        if value is None:
            return "未知"
        # 将时间字符串转换为datetime对象
        if isinstance(value, str):
            # 处理不同的时间格式
            if 'T' in value:
                if 'Z' in value:
                    dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
                else:
                    # 处理带毫秒的时间格式
                    if '.' in value:
                        dt = datetime.strptime(value.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    else:
                        dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
            else:
                dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        else:
            dt = value
            
        # 设置为东八区时间
        utc_dt = pytz.utc.localize(dt) if dt.tzinfo is None else dt
        china_tz = pytz.timezone('Asia/Shanghai')
        china_time = utc_dt.astimezone(china_tz)
        
        # 格式化为年-月-日 时:分:秒
        return china_time.strftime('%Y-%m-%d %H:%M:%S')

    # 从环境变量获取Supabase配置
    SUPABASE_URL = os.environ.get("SUPABASE_URL")
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
    
    # 检查环境变量
    if not SUPABASE_URL:
        print("错误: 未设置SUPABASE_URL环境变量")
    if not SUPABASE_KEY:
        print("错误: 未设置SUPABASE_KEY环境变量")
    
    def load_member_data(group_type=None):
        """从Supabase加载成员数据，按ID排序"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            if not SUPABASE_URL:
                print("SUPABASE_URL未设置")
            if not SUPABASE_KEY:
                print("SUPABASE_KEY未设置")
            return None
            
        try:
            # 构建请求URL，添加排序参数
            if group_type:
                # 将字符串类型的group_type转换为整数
                group_type_map = {
                    'wechat': 1,
                    'qq': 2,
                    'qq_channel': 3
                }
                group_type_int = group_type_map.get(group_type, 1)  # 默认为1(微信群)
                url = f"{SUPABASE_URL}/rest/v1/members?group_type=eq.{group_type_int}&order=id"
            else:
                url = f"{SUPABASE_URL}/rest/v1/members?order=id"
                
            print(f"正在请求URL: {url}")  # 调试信息
                
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            # 发送GET请求获取数据
            response = requests.get(url, headers=headers)
            print(f"响应状态码: {response.status_code}")  # 调试信息
            print(f"响应内容: {response.text}")  # 调试信息
            
            if response.ok:
                members = response.json()
                print(f"获取到 {len(members)} 条数据")  # 调试信息
                # 如果指定了group_type但没有找到数据，则获取所有数据作为后备方案
                if group_type and len(members) == 0:
                    print(f"未找到group_type为 {group_type} 的数据，尝试获取所有数据")  # 调试信息
                    # 尝试获取所有数据（兼容旧数据）
                    url_all = f"{SUPABASE_URL}/rest/v1/members?order=id"
                    response_all = requests.get(url_all, headers=headers)
                    print(f"所有数据请求状态码: {response_all.status_code}")  # 调试信息
                    if response_all.ok:
                        members = response_all.json()
                        print(f"获取到 {len(members)} 条总数据")  # 调试信息
                        # 为旧数据添加group_type字段
                        for member in members:
                            if 'group_type' not in member:
                                group_type_map = {
                                    'wechat': 1,
                                    'qq': 2,
                                    'qq_channel': 3
                                }
                                member['group_type'] = group_type_map.get(group_type, 1)
                return {"members": members}
            else:
                print(f"获取数据失败: {response.text}")
                print(f"请求URL: {url}")
                print(f"请求头: {headers}")
                return None
                
        except Exception as e:
            print(f"从Supabase加载数据时出错: {e}")
            import traceback
            traceback.print_exc()  # 打印详细的错误堆栈
            return None

    def update_member_data(member_id, name, score, description, group_type):
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
            
            # 将字符串类型的group_type转换为整数
            group_type_map = {
                'wechat': 1,
                'qq': 2,
                'qq_channel': 3
            }
            group_type_int = group_type_map.get(group_type)
            if group_type_int is not None:
                data["group_type"] = group_type_int
            
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

    def create_member(name, score, description, group_type=None):
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
            
            # 将字符串类型的group_type转换为整数
            if group_type is not None:
                group_type_map = {
                    'wechat': 1,
                    'qq': 2,
                    'qq_channel': 3
                }
                group_type_int = group_type_map.get(group_type)
                if group_type_int is not None:
                    data["group_type"] = group_type_int
            
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
        print("访问首页路由")  # 调试信息
        # 首页不加载特定群组的数据
        data = load_member_data()
        if data is None:
            print("无法从Supabase加载数据")
            return "无法从Supabase加载数据", 500
        
        # 显示所有成员数据
        print(f"首页加载了 {len(data['members'])} 条数据")  # 调试信息
        return render_template('index.html', members=data['members'], 
                              last_updated="未知", active_nav="home")

    @app.route('/wechat-members')
    def wechat_members():
        """渲染微信群成员页面"""
        print("访问微信群成员路由")  # 调试信息
        data = load_member_data('wechat')
        if data is None:
            print("无法从Supabase加载微信群成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出微信群成员（兼容旧数据）
        wechat_members = [member for member in data['members'] 
                         if member.get('group_type') == 1 or 'group_type' not in member]
        print(f"微信群成员页面加载了 {len(wechat_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=wechat_members, 
                              last_updated="未知", active_nav="wechat")

    @app.route('/qq-group')
    def qq_group():
        """渲染QQ群成员页面"""
        print("访问QQ群成员路由")  # 调试信息
        data = load_member_data('qq')
        if data is None:
            print("无法从Supabase加载QQ群成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出QQ群成员（兼容旧数据）
        qq_members = [member for member in data['members'] 
                     if member.get('group_type') == 2 or 'group_type' not in member]
        print(f"QQ群成员页面加载了 {len(qq_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=qq_members, 
                              last_updated="未知", active_nav="qq")

    @app.route('/qq-channel')
    def qq_channel():
        """渲染QQ频道成员页面"""
        print("访问QQ频道成员路由")  # 调试信息
        data = load_member_data('qq_channel')
        if data is None:
            print("无法从Supabase加载QQ频道成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出QQ频道成员（兼容旧数据）
        qq_channel_members = [member for member in data['members'] 
                             if member.get('group_type') == 3 or 'group_type' not in member]
        print(f"QQ频道成员页面加载了 {len(qq_channel_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=qq_channel_members, 
                              last_updated="未知", active_nav="qq_channel")

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
        # 获取查询参数中的群组类型
        group_type = request.args.get('group_type')
        
        # 如果有指定群组类型，则按群组类型加载数据
        if group_type:
            data = load_member_data(group_type)
        else:
            # 否则加载所有数据
            data = load_member_data()
            
        if data is None:
            return "无法从Supabase加载数据", 500
        
        # 根据群组类型过滤数据
        if group_type:
            group_type_map = {
                'wechat': 1,
                'qq': 2,
                'qq_channel': 3
            }
            group_type_int = group_type_map.get(group_type)
            if group_type_int:
                filtered_members = [member for member in data['members'] 
                                  if member.get('group_type') == group_type_int]
                data['members'] = filtered_members
        
        return render_template('admin.html', members=data['members'], 
                             selected_group_type=group_type)

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

    @app.route('/admin/create', methods=['POST'])
    @login_required
    def admin_create():
        """处理创建新成员的请求"""
        name = request.form.get('name')
        score = request.form.get('score')
        description = request.form.get('description')
        group_type = request.form.get('group_type')
        
        # 获取当前筛选的群组类型，用于重定向
        current_group_type = request.args.get('group_type')
        
        # 即使group_type为空也允许创建
        if name and score:
            success = create_member(name, int(score), description, group_type)
            if success:
                # 根据当前筛选的群组类型进行重定向
                if current_group_type:
                    return redirect(url_for('admin', group_type=current_group_type))
                else:
                    return redirect(url_for('admin'))
            else:
                return "创建失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/update', methods=['POST'])
    @login_required
    def admin_update():
        """处理更新成员数据的请求"""
        member_id = request.form.get('id')
        name = request.form.get('name')
        score = request.form.get('score')
        description = request.form.get('description')
        group_type = request.form.get('group_type')
        
        # 获取当前筛选的群组类型，用于重定向
        current_group_type = request.args.get('group_type')
        
        if member_id and name and score and group_type:
            success = update_member_data(member_id, name, int(score), description, group_type)
            if success:
                # 根据当前筛选的群组类型进行重定向
                if current_group_type:
                    return redirect(url_for('admin', group_type=current_group_type))
                else:
                    return redirect(url_for('admin'))
            else:
                return "更新失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/delete/<int:member_id>')
    @login_required
    def admin_delete(member_id):
        """处理删除成员的请求"""
        if member_id:
            # 获取当前筛选的群组类型，用于重定向
            current_group_type = request.args.get('group_type')
            
            success = delete_member(member_id)
            if success:
                # 根据当前筛选的群组类型进行重定向
                if current_group_type:
                    return redirect(url_for('admin', group_type=current_group_type))
                else:
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