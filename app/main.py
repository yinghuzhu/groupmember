from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import os
import requests
import hashlib
from datetime import datetime
import pytz
from app.logger import log_operation

# 群组类型映射常量
GROUP_ID_MAP = {
    'wechat': 1,
    'qq': 2,
    'qq_channel': 3
}

def resolve_group_id(group_type_input):
    """
    解析群组ID，统一处理字符串、数字字符串和整数
    :param group_type_input: 输入的群组类型（可能是 'wechat', '1', 1）
    :return: 对应的整数ID，如果无法解析则返回None
    """
    if group_type_input is None:
        return None
        
    if isinstance(group_type_input, int):
        return group_type_input
        
    if isinstance(group_type_input, str):
        if group_type_input.isdigit():
            return int(group_type_input)
        return GROUP_ID_MAP.get(group_type_input)
        
    return None

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
    
    def load_group_notice(group_id):
        """获取指定群组的最新公告"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
        try:
            url = f"{SUPABASE_URL}/rest/v1/group_notices?group_id=eq.{group_id}&order=updated_at.desc&limit=1"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, verify=False)
            if response.ok:
                notices = response.json()
                return notices[0] if notices else None
            else:
                print(f"获取群公告失败: {response.text}")
                return None
        except Exception as e:
            print(f"获取群公告时出错: {e}")
            return None

    def load_groups_data():
        """从Supabase加载群组数据"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
        try:
            url = f"{SUPABASE_URL}/rest/v1/groups?order=id"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, verify=False)
            if response.ok:
                groups = response.json()
                return groups
            else:
                print(f"获取群组数据失败: {response.text}")
                return None
        except Exception as e:
            print(f"从Supabase加载群组数据时出错: {e}")
            import traceback
            traceback.print_exc()  # 打印详细的错误堆栈
            return None

    def update_group_notice(group_id, notice, author=None):
        """更新或创建群公告（只保留最新一条）"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            now = datetime.utcnow().isoformat() + 'Z'
            # 先查是否有公告
            old_notice = load_group_notice(group_id)
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            if old_notice:
                # 更新
                url = f"{SUPABASE_URL}/rest/v1/group_notices?id=eq.{old_notice['id']}"
                data = {
                    "notice": notice,
                    "updated_at": now,
                }
                if author:
                    data["author"] = author
                response = requests.patch(url, headers=headers, json=data, verify=False)
            else:
                # 创建
                url = f"{SUPABASE_URL}/rest/v1/group_notices"
                data = {
                    "group_id": group_id,
                    "notice": notice,
                    "created_at": now,
                    "updated_at": now,
                }
                if author:
                    data["author"] = author
                response = requests.post(url, headers=headers, json=data, verify=False)
            return response.ok
        except Exception as e:
            print(f"更新群公告时出错: {e}")
            return False

    def load_member_data(group_type=None, search_query=None):
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
            base_url = f"{SUPABASE_URL}/rest/v1/members"
            params = ["order=id"]
            
            if group_type:
                group_type_int = resolve_group_id(group_type)
                if group_type_int is not None:
                    params.append(f"group_id=eq.{group_type_int}")
                else:
                    # 如果提供了无法解析的group_type，默认使用1(微信群)或忽略
                    params.append(f"group_id=eq.1")
            
            # 添加模糊搜索参数
            if search_query:
                # 使用 ilike 进行模糊搜索
                encoded_search = search_query.replace('%', '%25').replace('*', '%2A')
                params.append(f"or=(name.ilike.*{encoded_search}*,description.ilike.*{encoded_search}*)")
            
            url = f"{base_url}?{'&'.join(params)}"
                
            print(f"正在请求URL: {url}")  # 调试信息
                
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            # 发送GET请求获取数据
            response = requests.get(url, headers=headers, verify=False)
            print(f"响应状态码: {response.status_code}")  # 调试信息
            print(f"响应内容: {response.text}")  # 调试信息
            
            if response.ok:
                members = response.json()
                print(f"获取到 {len(members)} 条数据")  # 调试信息
                
                # 为旧数据添加group_type字段（向后兼容）
                for member in members:
                    if 'group_id' not in member and group_type:
                        member['group_id'] = resolve_group_id(group_type) or 1
                
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
            
            # 处理group_type，使用统一的解析函数
            if group_type:
                group_type_int = resolve_group_id(group_type)
                if group_type_int is not None:
                    data["group_id"] = group_type_int
            
            # 发送PATCH请求更新数据
            response = requests.patch(url, headers=headers, json=data, verify=False)
            
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
                "description": description,
                "group_id": resolve_group_id(group_type)
            }
            
            # 发送POST请求创建数据
            response = requests.post(url, headers=headers, json=data, verify=False)
            
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
            response = requests.delete(url, headers=headers, verify=False)
            
            if response.ok:
                return True
            else:
                print(f"删除数据失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"删除Supabase数据时出错: {e}")
            return False

    def update_group_name_data(group_id, name):
        """更新群组名称"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
            
        try:
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/groups?id=eq.{group_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            
            # 构造要更新的数据
            data = {
                "name": name
            }
            
            # 发送PATCH请求更新数据
            response = requests.patch(url, headers=headers, json=data, verify=False)
            
            if response.ok:
                return True
            else:
                print(f"更新群组名称失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"更新Supabase群组数据时出错: {e}")
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
            
            response = requests.get(url, headers=headers, verify=False)
            
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
            print("Supabase 配置缺失")
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
                
            response = requests.get(url, headers=headers, verify=False)
                
            if response.ok:
                users = response.json()
                if len(users) > 0:
                    return users[0]
                return None
            else:
                print(f"获取用户信息失败：{response.text}")
                return None
                    
        except Exception as e:
            print(f"获取管理员用户信息时出错：{e}")
            return None
    
    def get_current_admin_user(username):
        """获取当前管理员用户信息（不验证密码，只获取信息）"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase 配置缺失")
            return None
                
        try:
            # 查询用户
            url = f"{SUPABASE_URL}/rest/v1/admin_users?username=eq.{username}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
                
            response = requests.get(url, headers=headers, verify=False)
                
            if response.ok:
                users = response.json()
                if len(users) > 0:
                    return users[0]
                return None
            else:
                print(f"获取用户信息失败：{response.text}")
                return None
                    
        except Exception as e:
            print(f"获取管理员用户信息时出错：{e}")
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
            response = requests.patch(url, headers=headers, json=data, verify=False)
            
            if response.ok:
                return True
            else:
                print(f"更新密码失败: {response.text}")
                return False
                
        except Exception as e:
            print(f"更新管理员密码时出错: {e}")
            return False

    def create_admin_user(username, password, is_super_admin=False):
        """创建管理员用户
        :param is_super_admin: 是否为超级管理员（拥有所有权限）
        """
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase 配置缺失")
            return False
            
        try:
            # 对密码进行哈希处理
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # 构建请求 URL
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
                "password": hashed_password,
                "is_super_admin": is_super_admin  # 添加超级管理员字段
            }
            
            # 发送 POST 请求创建数据
            response = requests.post(url, headers=headers, json=data, verify=False)
            
            if response.ok:
                return True
            else:
                print(f"创建管理员用户失败：{response.text}")
                return False
                
        except Exception as e:
            print(f"创建管理员用户时出错：{e}")
            return False

    def load_all_admins_data():
        """加载所有管理员用户数据"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase 配置缺失")
            return None
            
        try:
            url = f"{SUPABASE_URL}/rest/v1/admin_users?order=id"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers, verify=False)
            
            if response.ok:
                admins = response.json()
                return admins
            else:
                print(f"获取管理员列表失败：{response.text}")
                return None
                
        except Exception as e:
            print(f"获取管理员列表时出错：{e}")
            return None

    def load_blacklist_data():
        """从Supabase加载黑名单数据"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
        try:
            url = f"{SUPABASE_URL}/rest/v1/blacklist?order=id"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, verify=False)
            if response.ok:
                blacklist = response.json()
                return blacklist
            else:
                print(f"获取黑名单数据失败: {response.text}")
                return None
        except Exception as e:
            print(f"从Supabase加载黑名单数据时出错: {e}")
            import traceback
            traceback.print_exc()  # 打印详细的错误堆栈
            return None

    def create_blacklist_member(name, reason=None, group_type=None, created_at=None):
        """创建黑名单成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            # 如果没有提供created_at，则使用当前时间
            if created_at is None:
                now = datetime.utcnow().isoformat() + 'Z'
            else:
                # 验证并格式化提供的created_at时间
                try:
                    # 尝试解析时间字符串
                    parsed_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    now = parsed_time.isoformat() + 'Z'
                except ValueError:
                    # 如果解析失败，使用当前时间
                    now = datetime.utcnow().isoformat() + 'Z'
            
            url = f"{SUPABASE_URL}/rest/v1/blacklist"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            data = {
                "name": name,
                "reason": reason,
                "created_at": now,
                "updated_at": now,
            }
            # 处理group_type，支持数字字符串和名称字符串
            if group_type:
                group_id = resolve_group_id(group_type)
                if group_id is not None:
                    data["group_id"] = group_id
            
            response = requests.post(url, headers=headers, json=data, verify=False)
            return response.ok
        except Exception as e:
            print(f"创建黑名单成员时出错: {e}")
            return False

    def delete_blacklist_member(blacklist_id):
        """删除黑名单成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            url = f"{SUPABASE_URL}/rest/v1/blacklist?id=eq.{blacklist_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.delete(url, headers=headers, verify=False)
            return response.ok
        except Exception as e:
            print(f"删除黑名单成员时出错: {e}")
            return False

    def update_blacklist_member(blacklist_id, name, reason=None):
        """更新黑名单成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            now = datetime.utcnow().isoformat() + 'Z'
            url = f"{SUPABASE_URL}/rest/v1/blacklist?id=eq.{blacklist_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            data = {
                "name": name,
                "reason": reason,
                "updated_at": now,
            }
            response = requests.patch(url, headers=headers, json=data, verify=False)
            return response.ok
        except Exception as e:
            print(f"更新黑名单成员时出错: {e}")
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
        data = load_member_data()
        groups = load_groups_data()
        # 获取所有群组公告（每个群组最新一条）
        group_notices = {}
        if groups:
            for group in groups:
                notice = load_group_notice(group['id'])
                group_notices[group['id']] = notice['notice'] if notice else ''
        if data is None:
            print("无法从Supabase加载数据")
            return "无法从Supabase加载数据", 500
        print(f"首页加载了 {len(data['members'])} 条数据")  # 调试信息
        return render_template('index.html', members=data['members'], groups=groups,
                              group_notices=group_notices, last_updated="未知", active_nav="home")

    @app.route('/admin/get-group-notice/<int:group_id>', methods=['GET'])
    @login_required
    def get_group_notice(group_id):
        """获取指定群组的公告"""
        notice = load_group_notice(group_id)
        
        if notice:
            return jsonify({'success': True, 'notice': notice['notice']})
        else:
            return jsonify({'success': True, 'notice': ''})

    @app.route('/admin/update-group-notice/<int:group_id>', methods=['POST'])
    @login_required
    def update_group_notice_api(group_id):
        """后台管理端更新群公告API"""
        data = request.get_json()
        notice = data.get('notice')
        author = session.get('admin_username')
        if not notice:
            return jsonify({'success': False, 'message': '公告内容不能为空'})
        success = update_group_notice(group_id, notice, author)
        if success:
            return jsonify({'success': True, 'message': '群公告更新成功'})
        else:
            return jsonify({'success': False, 'message': '群公告更新失败'})

    @app.route('/wechat-members')
    def wechat_members():
        """渲染微信群成员页面"""
        # 获取搜索参数
        search_query = request.args.get('search')
        
        print("访问微信群成员路由")  # 调试信息
        data = load_member_data('wechat', search_query)
        # 加载群组数据
        groups = load_groups_data()
        if data is None:
            print("无法从Supabase加载微信群成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出微信群成员（兼容旧数据）
        wechat_members = [member for member in data['members'] 
                         if member.get('group_id') == 1 or 'group_id' not in member]
        print(f"微信群成员页面加载了 {len(wechat_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=wechat_members, groups=groups,
                              last_updated="未知", active_nav="wechat", search_query=search_query)

    @app.route('/qq-group')
    def qq_group():
        """渲染QQ群成员页面"""
        # 获取搜索参数
        search_query = request.args.get('search')
        
        print("访问QQ群成员路由")  # 调试信息
        data = load_member_data('qq', search_query)
        # 加载群组数据
        groups = load_groups_data()
        if data is None:
            print("无法从Supabase加载QQ群成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出QQ群成员（兼容旧数据）
        qq_members = [member for member in data['members'] 
                     if member.get('group_id') == 2 or 'group_id' not in member]
        print(f"QQ群成员页面加载了 {len(qq_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=qq_members, groups=groups,
                              last_updated="未知", active_nav="qq", search_query=search_query)

    @app.route('/qq-channel')
    def qq_channel():
        """渲染QQ频道成员页面"""
        # 获取搜索参数
        search_query = request.args.get('search')
        
        print("访问QQ频道成员路由")  # 调试信息
        data = load_member_data('qq_channel', search_query)
        # 加载群组数据
        groups = load_groups_data()
        if data is None:
            print("无法从Supabase加载QQ频道成员数据")
            return "无法从Supabase加载数据", 500
        
        # 过滤出QQ频道成员（兼容旧数据）
        qq_channel_members = [member for member in data['members'] 
                             if member.get('group_id') == 3 or 'group_id' not in member]
        print(f"QQ频道成员页面加载了 {len(qq_channel_members)} 条数据")  # 调试信息
        
        return render_template('index.html', members=qq_channel_members, groups=groups,
                              last_updated="未知", active_nav="qq_channel", search_query=search_query)

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        """管理员登录页面"""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if username and password and verify_admin_user(username, password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                
                # 记录登录成功日志
                log_operation(
                    operation_type='login_success',
                    target_table='admin_users',
                    target_name=username,
                    action_details=f'管理员 {username} 登录成功'
                )
                
                return redirect(url_for('admin'))
            else:
                # 记录登录失败日志
                if username:
                    log_operation(
                        operation_type='login_failed',
                        target_table='admin_users',
                        target_name=username,
                        action_details=f'管理员登录失败：用户名 {username}'
                    )
                return render_template('login.html', error='用户名或密码错误')
        
        return render_template('login.html')

    @app.route('/admin/logout')
    def admin_logout():
        """管理员登出"""
        username = session.get('admin_username')
        if username:
            log_operation(
                operation_type='logout',
                target_table='admin_users',
                target_name=username,
                action_details=f'管理员 {username} 退出登录'
            )
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        return redirect(url_for('admin_login'))

    @app.route('/admin')
    @login_required
    def admin():
        """渲染后台管理页面"""
        # 获取查询参数中的群组类型和搜索关键词
        group_type = request.args.get('group_type')
        search_query = request.args.get('search')
            
        # 获取当前用户信息，判断是否为超级管理员
        current_username = session.get('admin_username')
        current_user = get_current_admin_user(current_username)
        is_super_admin = current_user.get('is_super_admin') if current_user else False
            
        # 加载群组数据
        groups = load_groups_data()
            
        # 加载黑名单数据
        blacklisted_members = load_blacklist_data()
            
        # 如果有指定群组类型或搜索关键词，则按条件加载数据
        data = load_member_data(group_type, search_query)
                
        if data is None:
            return "无法从 Supabase 加载数据", 500
            
        # 根据群组类型过滤数据
        if group_type:
            group_type_int = resolve_group_id(group_type)
            if group_type_int:
                filtered_members = [member for member in data['members'] 
                                  if member.get('group_id') == group_type_int]
                data['members'] = filtered_members
            
        # 加载所有管理员数据（仅超级管理员需要）
        admin_users = None
        if is_super_admin:
            admin_users = load_all_admins_data()
        
        # 获取当前管理员 ID
        current_admin_id = current_user.get('id') if current_user else None
            
        return render_template('admin.html', members=data['members'], groups=groups,
                             selected_group_type=group_type, search_query=search_query,
                             blacklisted_members=blacklisted_members, 
                             is_super_admin=is_super_admin, admin_users=admin_users,
                             current_admin_id=current_admin_id)

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

    @app.route('/admin/create-admin', methods=['GET', 'POST'])
    @login_required
    def admin_create_admin_user():
        """创建新的管理员账号（仅超级管理员可访问）"""
        # 验证当前用户是否为超级管理员
        current_username = session.get('admin_username')
        current_user = get_current_admin_user(current_username)
        
        if not current_user or not current_user.get('is_super_admin'):
            return jsonify({'success': False, 'message': '权限不足，仅超级管理员可创建新管理员'}), 403
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            is_super_admin = request.form.get('is_super_admin') == 'on'  # 获取是否超级管理员
            
            if not username or not password or not confirm_password:
                return redirect(url_for('admin'))
            
            if password != confirm_password:
                return redirect(url_for('admin'))
            
            if len(password) < 6:
                return redirect(url_for('admin'))
            
            # 检查用户名是否已存在
            existing_user = get_admin_user(username, '')
            if existing_user:
                return redirect(url_for('admin'))
            
            if create_admin_user(username, password, is_super_admin):
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('admin'))
        
        return redirect(url_for('admin'))
    
    @app.route('/admin/update-group-name', methods=['POST'])
    @login_required
    def update_group_name():
        """更新群组名称"""
        # 处理 JSON 数据
        data = request.get_json()
        group_id = data.get('group_id') if data else None
        name = data.get('name') if data else None
            
        if not group_id or not name:
            return jsonify({'success': False, 'message': '缺少必要参数'})
            
        # 更新群组名称
        success = update_group_name_data(group_id, name)
            
        if success:
            return jsonify({'success': True, 'message': '群组名称更新成功'})
        else:
            return jsonify({'success': False, 'message': '群组名称更新失败'})
    
    @app.route('/admin/update-admin-username', methods=['POST'])
    @login_required
    def update_admin_username():
        """更新管理员用户名（仅超级管理员可访问）"""
        # 验证当前用户是否为超级管理员
        current_username = session.get('admin_username')
        current_user = get_current_admin_user(current_username)
            
        if not current_user or not current_user.get('is_super_admin'):
            return jsonify({'success': False, 'message': '权限不足'}), 403
            
        admin_id = request.form.get('admin_id')
        new_username = request.form.get('username')
            
        if not admin_id or not new_username:
            return redirect(url_for('admin'))
            
        try:
            url = f"{SUPABASE_URL}/rest/v1/admin_users?id=eq.{admin_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            data = {"username": new_username}
            response = requests.patch(url, headers=headers, json=data, verify=False)
                
            if response.ok:
                return redirect(url_for('admin'))
            else:
                print(f"更新用户名失败：{response.text}")
                return redirect(url_for('admin'))
        except Exception as e:
            print(f"更新管理员用户名时出错：{e}")
            return redirect(url_for('admin'))
    
    @app.route('/admin/reset-admin-password', methods=['POST'])
    @login_required
    def reset_admin_password():
        """重置管理员密码（仅超级管理员可访问）"""
        # 验证当前用户是否为超级管理员
        current_username = session.get('admin_username')
        current_user = get_current_admin_user(current_username)
            
        if not current_user or not current_user.get('is_super_admin'):
            return jsonify({'success': False, 'message': '权限不足'}), 403
            
        admin_id = request.form.get('admin_id')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
            
        if not admin_id or not new_password or not confirm_password:
            return redirect(url_for('admin'))
            
        if new_password != confirm_password:
            return redirect(url_for('admin'))
            
        if len(new_password) < 6:
            return redirect(url_for('admin'))
            
        try:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            url = f"{SUPABASE_URL}/rest/v1/admin_users?id=eq.{admin_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            data = {"password": hashed_password}
            response = requests.patch(url, headers=headers, json=data, verify=False)
                
            if response.ok:
                return redirect(url_for('admin'))
            else:
                print(f"重置密码失败：{response.text}")
                return redirect(url_for('admin'))
        except Exception as e:
            print(f"重置管理员密码时出错：{e}")
            return redirect(url_for('admin'))
    
    @app.route('/admin/delete-admin/<int:admin_id>', methods=['POST'])
    @login_required
    def delete_admin(admin_id):
        """删除管理员账号（仅超级管理员可访问）"""
        # 验证当前用户是否为超级管理员
        current_username = session.get('admin_username')
        current_user = get_current_admin_user(current_username)
            
        if not current_user or not current_user.get('is_super_admin'):
            return jsonify({'success': False, 'message': '权限不足'}), 403
            
        # 不能删除自己
        if str(admin_id) == str(current_user.get('id')):
            return redirect(url_for('admin'))
            
        try:
            url = f"{SUPABASE_URL}/rest/v1/admin_users?id=eq.{admin_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.delete(url, headers=headers, verify=False)
                
            if response.ok:
                return redirect(url_for('admin'))
            else:
                print(f"删除管理员失败：{response.text}")
                return redirect(url_for('admin'))
        except Exception as e:
            print(f"删除管理员时出错：{e}")
            return redirect(url_for('admin'))

    @app.route('/admin/create', methods=['POST'])
    @login_required
    def admin_create():
        """处理创建新成员的请求"""
        name = request.form.get('name')
        score = request.form.get('score')
        description = request.form.get('description')
        group_type = request.form.get('group_type')
            
        # 获取当前筛选的群组类型和搜索关键词，用于重定向
        current_group_type = request.args.get('group_type')
        search_query = request.args.get('search')
            
        # 即使 group_type 为空也允许创建
        if name and score:
            success = create_member(name, int(score), description, group_type)
            if success:
                # 根据当前筛选的群组类型和搜索关键词进行重定向
                redirect_params = []
                if current_group_type:
                    redirect_params.append(f"group_type={current_group_type}")
                if search_query:
                    redirect_params.append(f"search={search_query}")
                    
                # 记录添加成员日志
                log_operation(
                    operation_type='add_member',
                    target_table='members',
                    target_name=name,
                    action_details=f'添加新成员：{name}，积分：{score}，群组：{group_type}',
                    new_value={'name': name, 'score': int(score), 'description': description, 'group_id': resolve_group_id(group_type)}
                )
                    
                if redirect_params:
                    return redirect(url_for('admin') + '?' + '&'.join(redirect_params))
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
        
        # 获取当前筛选的群组类型和搜索关键词，用于重定向
        current_group_type = request.args.get('group_type')
        search_query = request.args.get('search')
        
        if member_id and name and score and group_type:
            # 先获取旧数据用于日志记录
            old_data = load_member_data()
            old_member = None
            if old_data and 'members' in old_data:
                old_member = next((m for m in old_data['members'] if m['id'] == int(member_id)), None)
            
            success = update_member_data(member_id, name, int(score), description, group_type)
            if success:
                # 根据当前筛选的群组类型和搜索关键词进行重定向
                redirect_params = []
                if current_group_type:
                    redirect_params.append(f"group_type={current_group_type}")
                if search_query:
                    redirect_params.append(f"search={search_query}")
                
                # 记录更新成员日志
                if old_member:
                    changes = []
                    if old_member.get('name') != name:
                        changes.append(f"姓名：{old_member.get('name')} → {name}")
                    if str(old_member.get('score')) != str(score):
                        changes.append(f"积分：{old_member.get('score')} → {score}")
                    if old_member.get('description') != description:
                        changes.append(f"描述变化")
                    if str(old_member.get('group_id')) != str(resolve_group_id(group_type)):
                        changes.append(f"群组：{old_member.get('group_id')} → {resolve_group_id(group_type)}")
                    
                    log_operation(
                        operation_type='update_member',
                        target_table='members',
                        target_id=int(member_id),
                        target_name=name,
                        action_details=f'更新成员信息：{name}，变更内容：{"; ".join(changes)}',
                        old_value={'name': old_member.get('name'), 'score': old_member.get('score'), 'description': old_member.get('description'), 'group_id': old_member.get('group_id')},
                        new_value={'name': name, 'score': int(score), 'description': description, 'group_id': resolve_group_id(group_type)}
                    )
                
                if redirect_params:
                    return redirect(url_for('admin') + '?' + '&'.join(redirect_params))
                else:
                    return redirect(url_for('admin'))
            else:
                return "更新失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/delete/<int:member_id>', methods=['POST'])
    @login_required
    def admin_delete(member_id):
        """处理删除成员的请求"""
        if member_id:
            # 先获取旧数据用于日志记录
            old_data = load_member_data()
            old_member = None
            if old_data and 'members' in old_data:
                old_member = next((m for m in old_data['members'] if m['id'] == int(member_id)), None)
            
            # 获取当前筛选的群组类型和搜索关键词，用于重定向
            current_group_type = request.args.get('group_type')
            search_query = request.args.get('search')
            
            success = delete_member(member_id)
            if success:
                # 根据当前筛选的群组类型和搜索关键词进行重定向
                redirect_params = []
                if current_group_type:
                    redirect_params.append(f"group_type={current_group_type}")
                if search_query:
                    redirect_params.append(f"search={search_query}")
                
                # 记录删除成员日志
                if old_member:
                    log_operation(
                        operation_type='delete_member',
                        target_table='members',
                        target_id=member_id,
                        target_name=old_member.get('name'),
                        action_details=f'删除成员：{old_member.get("name")}（原群组 ID: {old_member.get("group_id")}，积分：{old_member.get("score")}）',
                        old_value={'name': old_member.get('name'), 'score': old_member.get('score'), 'description': old_member.get('description'), 'group_id': old_member.get('group_id')}
                    )
                
                if redirect_params:
                    return redirect(url_for('admin') + '?' + '&'.join(redirect_params))
                else:
                    return redirect(url_for('admin'))
            else:
                return "删除失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/admin/blacklist', methods=['POST'])
    @login_required
    def admin_create_blacklist_member():
        """添加黑名单成员"""
        name = request.form.get('name')
        reason = request.form.get('reason')
        group_type = request.form.get('group_type')
        created_at = request.form.get('created_at')
        
        # 将datetime-local格式转换为UTC时间格式
        if created_at:
            try:
                # datetime-local 输入格式为 "YYYY-MM-DDTHH:MM"
                dt = datetime.fromisoformat(created_at)
                # 转换为UTC时间并格式化为ISO格式
                created_at = dt.utcnow().isoformat() + 'Z'
            except ValueError:
                # 如果转换失败，设置为None，让create_blacklist_member使用默认时间
                created_at = None
        
        if name:
            # 处理group_type，支持数字字符串和名称字符串
            group_id = None
            if group_type:
                if isinstance(group_type, str) and group_type.isdigit():
                    # 如果是数字字符串，直接转换为整数
                    group_id = int(group_type)
                else:
                    # 如果是名称字符串，通过映射转换
                    group_type_map = {
                        'wechat': 1,
                        'qq': 2,
                        'qq_channel': 3
                    }
                    group_id = group_type_map.get(group_type)
            
            success = create_blacklist_member(name, reason, group_id, created_at)
            if success:
                return redirect(url_for('admin'))
            else:
                return "添加黑名单成员失败", 500
        else:
            return "姓名是必填项", 400

    @app.route('/admin/blacklist-from-members', methods=['POST'])
    @login_required
    def admin_create_blacklist_member_from_existing():
        """从现有成员中添加到黑名单"""
        member_id = request.form.get('member_id')
        reason = request.form.get('reason')
        group_type = request.form.get('group_type')  # 获取群组类型
        
        if member_id:
            # 获取现有成员信息
            member_data = load_member_data()
            if member_data and 'members' in member_data:
                member = next((m for m in member_data['members'] if m['id'] == int(member_id)), None)
                if member:
                    # 将成员添加到黑名单
                    name = member['name']
                    # 使用成员的群组ID，如果不存在则使用表单中的群组类型
                    group_id = member.get('group_id') or (int(group_type) if group_type else None)
                    success = create_blacklist_member(name, reason, group_id)
                    if success:
                        return redirect(url_for('admin'))
                    else:
                        return "添加黑名单成员失败", 500
            return "未找到指定成员", 400
        else:
            return "请选择一个成员", 400

    @app.route('/admin/blacklist/<int:blacklist_id>', methods=['POST'])
    @login_required
    def admin_delete_blacklist_member(blacklist_id):
        """删除黑名单成员"""
        # 检查是否是DELETE方法的模拟
        method = request.form.get('_method', request.method)
        
        if method == 'DELETE' and blacklist_id:
            success = delete_blacklist_member(blacklist_id)
            if success:
                return redirect(url_for('admin'))
            else:
                return "删除黑名单成员失败", 500
        else:
            return "缺少必要参数", 400

    @app.route('/api/members')
    def api_members():
        """提供API接口获取成员数据"""
        data = load_member_data()
        if data is None:
            return jsonify({'error': '无法从Supabase加载数据'}), 500
        
        return jsonify(data)

    @app.route('/blacklist')
    def public_blacklist():
        """公开黑名单页面，支持按群组与关键词筛选"""
        try:
            # 查询参数
            group_param = request.args.get('group')
            search_query = request.args.get('search')

            # 构建 Supabase 查询
            if not SUPABASE_URL or not SUPABASE_KEY:
                print("错误: Supabase配置缺失")
                return "无法从Supabase加载数据", 500

            base_url = f"{SUPABASE_URL}/rest/v1/blacklist"
            params = ["order=created_at.desc"]
            if group_param:
                params.append(f"group_id=eq.{group_param}")
            if search_query:
                encoded = search_query.replace('%', '%25').replace('*', '%2A')
                params.append(f"or=(name.ilike.*{encoded}*,reason.ilike.*{encoded}*)")

            url = f"{base_url}?{'&'.join(params)}"
            print(f"请求黑名单URL: {url}")  # 调试信息
            
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            resp = requests.get(url, headers=headers)
            print(f"黑名单响应状态: {resp.status_code}")  # 调试信息
            
            if not resp.ok:
                print(f"获取黑名单失败: {resp.text}")
                # 如果表不存在，返回空列表而不是错误
                if resp.status_code == 404:
                    blacklisted_members = []
                else:
                    return f"无法从Supabase加载数据: {resp.text}", 500
            else:
                blacklisted_members = resp.json()

            groups = load_groups_data()
            return render_template('blacklist_public.html',
                                   blacklisted_members=blacklisted_members,
                                   groups=groups,
                                   selected_group=group_param,
                                   search_query=search_query,
                                   active_nav='blacklist')
        except Exception as e:
            print(f"黑名单页面错误: {e}")
            import traceback
            traceback.print_exc()
            return f"服务器内部错误: {str(e)}", 500

    # ================= 黑名单管理 =================
    def load_blacklist_data():
        """从Supabase加载黑名单数据，按ID排序"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
        try:
            url = f"{SUPABASE_URL}/rest/v1/blacklist?order=id"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, verify=False)
            if response.ok:
                return response.json()
            else:
                print(f"获取黑名单失败: {response.text}")
                return None
        except Exception as e:
            print(f"从Supabase加载黑名单时出错: {e}")
            return None

    def create_blacklist_entry(name, reason, group_type, created_at: str | None = None):
        """创建黑名单成员，允许指定创建时间created_at(ISO8601, e.g. 2025-10-07T13:20:00Z)"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            url = f"{SUPABASE_URL}/rest/v1/blacklist"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            }
            # 允许传入 group_type 为字符串或数字
            group_id = None
            if isinstance(group_type, str) and group_type.isdigit():
                group_id = int(group_type)
            elif isinstance(group_type, int):
                group_id = group_type
            else:
                # 兼容传入 wechat/qq/qq_channel
                group_type_map = {'wechat': 1, 'qq': 2, 'qq_channel': 3}
                group_id = group_type_map.get(str(group_type))
            # 处理 created_at / updated_at（无触发器，代码负责）
            if created_at:
                # 允许传入 datetime-local 或 ISO8601，失败则回退到当前时间
                try:
                    # 支持 "YYYY-MM-DDTHH:MM" 或含秒的形式
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    iso_now = dt.isoformat().replace('+00:00', 'Z')
                except Exception:
                    iso_now = datetime.utcnow().isoformat() + 'Z'
            else:
                iso_now = datetime.utcnow().isoformat() + 'Z'

            data = {
                "name": name,
                "reason": reason,
                "group_id": group_id,
                "created_at": iso_now,
                "updated_at": iso_now
            }
            response = requests.post(url, headers=headers, json=data, verify=False)
            return response.ok
        except Exception as e:
            print(f"创建黑名单失败: {e}")
            return False

    def create_blacklist_from_member(member_id, reason, created_at: str | None = None):
        """从现有成员创建黑名单记录（复制 name 和 group_id），允许指定created_at"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            # 先获取成员
            member_url = f"{SUPABASE_URL}/rest/v1/members?id=eq.{member_id}&select=id,name,group_id"
            m_resp = requests.get(member_url, headers=headers)
            if not m_resp.ok:
                print(f"查询成员失败: {m_resp.text}")
                return False
            members = m_resp.json()
            if not members:
                print("未找到成员")
                return False
            member = members[0]
            # 创建黑名单记录
            bl_url = f"{SUPABASE_URL}/rest/v1/blacklist"
            bl_headers = dict(headers)
            bl_headers['Prefer'] = 'return=representation'
            # 处理时间戳
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    iso_now = dt.isoformat().replace('+00:00', 'Z')
                except Exception:
                    iso_now = datetime.utcnow().isoformat() + 'Z'
            else:
                iso_now = datetime.utcnow().isoformat() + 'Z'

            bl_data = {
                "name": member.get('name'),
                "group_id": member.get('group_id'),
                "reason": reason,
                "created_at": iso_now,
                "updated_at": iso_now
            }
            bl_resp = requests.post(bl_url, headers=bl_headers, json=bl_data)
            return bl_resp.ok
        except Exception as e:
            print(f"从成员添加黑名单失败: {e}")
            return False

    def delete_blacklist_entry(entry_id):
        """删除黑名单成员"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return False
        try:
            url = f"{SUPABASE_URL}/rest/v1/blacklist?id=eq.{entry_id}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            resp = requests.delete(url, headers=headers)
            return resp.ok
        except Exception as e:
            print(f"删除黑名单失败: {e}")
            return False

    @app.route('/admin/blacklist', methods=['GET', 'POST'])
    @login_required
    def admin_blacklist():
        """黑名单管理页面 + 创建黑名单成员"""
        if request.method == 'POST':
            name = request.form.get('name')
            reason = request.form.get('reason')
            group_type = request.form.get('group_type')
            created_at = request.form.get('created_at')

            # 后台表单一般来自 datetime-local，形如 YYYY-MM-DDTHH:MM
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at)
                    created_at = dt.isoformat()
                except Exception:
                    created_at = None
            if not name:
                return "缺少姓名", 400
            
            success = create_blacklist_entry(name, reason, group_type, created_at)
            if not success:
                return "添加黑名单成员失败", 500
            
            # 记录添加黑名单日志
            log_operation(
                operation_type='add_blacklist',
                target_table='blacklist',
                target_name=name,
                action_details=f'添加黑名单成员：{name}，原因：{reason}',
                new_value={'name': name, 'reason': reason, 'group_id': resolve_group_id(group_type)}
            )
            
            return redirect(url_for('admin_blacklist'))

        # GET 渲染
        groups = load_groups_data()
        blacklisted_members = load_blacklist_data() or []
        return render_template('blacklist.html', groups=groups, blacklisted_members=blacklisted_members)

    @app.route('/admin/blacklist-from-members', methods=['POST'])
    @login_required
    def admin_blacklist_from_members():
        member_id = request.form.get('member_id')
        reason = request.form.get('reason')
        created_at = request.form.get('created_at')
        if created_at:
            try:
                dt = datetime.fromisoformat(created_at)
                created_at = dt.isoformat()
            except Exception:
                created_at = None
        if not member_id:
            return "缺少成员 ID", 400
            
        # 先获取成员信息用于日志
        member_data = load_member_data()
        member = None
        if member_data and 'members' in member_data:
            member = next((m for m in member_data['members'] if m['id'] == int(member_id)), None)
            
        success = create_blacklist_from_member(member_id, reason, created_at)
        if not success:
            return "添加黑名单成员失败", 500
            
        # 记录添加黑名单日志
        if member:
            log_operation(
                operation_type='add_blacklist',
                target_table='blacklist',
                target_name=member.get('name'),
                action_details=f'从成员添加黑名单：{member.get("name")}，原因：{reason}',
                new_value={'name': member.get('name'), 'group_id': member.get('group_id'), 'reason': reason}
            )
            
        return redirect(url_for('admin_blacklist'))

    @app.route('/admin/blacklist/<int:entry_id>', methods=['POST'])
    @login_required
    def admin_blacklist_delete(entry_id):
        """从表单提交中删除（method override 可选）"""
        # 兼容 _method=DELETE
        if request.form.get('_method', '').upper() in ('DELETE',):
            # 先获取旧数据用于日志
            old_data = load_blacklist_data()
            old_entry = None
            if old_data:
                old_entry = next((b for b in old_data if b['id'] == entry_id), None)
            
            success = delete_blacklist_entry(entry_id)
            if not success:
                return "删除失败", 500
            
            # 记录删除黑名单日志
            if old_entry:
                log_operation(
                    operation_type='delete_blacklist',
                    target_table='blacklist',
                    target_id=entry_id,
                    target_name=old_entry.get('name'),
                    action_details=f'从黑名单移除：{old_entry.get("name")}（原原因：{old_entry.get("reason")}）',
                    old_value={'name': old_entry.get('name'), 'reason': old_entry.get('reason'), 'group_id': old_entry.get('group_id')}
                )
            
            return redirect(url_for('admin_blacklist'))
        # 默认也执行删除
        # 先获取旧数据用于日志
        old_data = load_blacklist_data()
        old_entry = None
        if old_data:
            old_entry = next((b for b in old_data if b['id'] == entry_id), None)
        
        success = delete_blacklist_entry(entry_id)
        if not success:
            return "删除失败", 500
        
        # 记录删除黑名单日志
        if old_entry:
            log_operation(
                operation_type='delete_blacklist',
                target_table='blacklist',
                target_id=entry_id,
                target_name=old_entry.get('name'),
                action_details=f'从黑名单移除：{old_entry.get("name")}（原原因：{old_entry.get("reason")}）',
                old_value={'name': old_entry.get('name'), 'reason': old_entry.get('reason'), 'group_id': old_entry.get('group_id')}
            )
        
        return redirect(url_for('admin_blacklist'))
    
    @app.route('/admin/api/operation-logs')
    @login_required
    def api_operation_logs():
        """获取操作日志 API（支持筛选和导出）"""
        try:
            # 获取查询参数
            operator = request.args.get('operator', '')
            operation_type = request.args.get('operation_type', '')
            search = request.args.get('search', '')
            export_csv = request.args.get('export', '') == 'csv'
            
            if not SUPABASE_URL or not SUPABASE_KEY:
                return jsonify({'error': 'Supabase 配置缺失'}), 500
            
            # 构建查询 URL
            base_url = f"{SUPABASE_URL}/rest/v1/operation_logs"
            params = ["order=created_at.desc", "limit=100"]  # 限制 100 条
            
            if operator:
                params.append(f"operator_username=eq.{operator}")
            if operation_type:
                params.append(f"operation_type=eq.{operation_type}")
            
            url = f"{base_url}?{'&'.join(params)}"
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f"Bearer {SUPABASE_KEY}",
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if not response.ok:
                # 如果表不存在，返回空列表
                if response.status_code == 404:
                    logs = []
                else:
                    return jsonify({'error': f'获取日志失败：{response.text}'}), 500
            else:
                logs = response.json()
            
            # 前端搜索（target_name 和 action_details）
            if search:
                search_lower = search.lower()
                logs = [log for log in logs 
                       if (log.get('target_name', '') and search_lower in log.get('target_name', '').lower()) or
                          (log.get('action_details', '') and search_lower in log.get('action_details', '').lower())]
            
            # 导出 CSV
            if export_csv:
                from flask import make_response
                import csv
                import io
                
                # 添加 UTF-8 BOM 标记，让 Excel 能正确识别编码
                output = io.StringIO()
                output.write('\ufeff')  # UTF-8 BOM
                writer = csv.writer(output)
                writer.writerow(['时间', '操作人', '操作类型', '目标表', '目标名称', '操作描述', 'IP 地址'])
                
                for log in logs:
                    writer.writerow([
                        log.get('created_at', ''),
                        log.get('operator_username', ''),
                        log.get('operation_type', ''),
                        log.get('target_table', ''),
                        log.get('target_name', ''),
                        log.get('action_details', ''),
                        log.get('ip_address', '')
                    ])
                
                response = make_response(output.getvalue())
                response.headers['Content-Type'] = 'text/csv; charset=utf-8-sig'
                response.headers['Content-Disposition'] = 'attachment; filename=operation_logs.csv'
                return response
            
            # 格式化时间
            formatted_logs = []
            for log in logs:
                formatted_log = log.copy()
                if log.get('created_at'):
                    try:
                        dt = datetime.fromisoformat(log['created_at'].replace('Z', '+00:00'))
                        china_tz = pytz.timezone('Asia/Shanghai')
                        china_time = dt.astimezone(china_tz)
                        formatted_log['created_at'] = china_time.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                formatted_logs.append(formatted_log)
            
            return jsonify({'logs': formatted_logs})
            
        except Exception as e:
            print(f"获取操作日志时出错：{e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    return app