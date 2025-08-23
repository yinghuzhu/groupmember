from flask import Flask, render_template, jsonify, request, redirect, url_for
import os
import requests

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

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

    @app.route('/')
    def index():
        """渲染主页面"""
        data = load_member_data()
        if data is None:
            return "无法从Supabase加载数据", 500
        
        return render_template('index.html', members=data['members'], 
                              last_updated="未知")

    @app.route('/admin')
    def admin():
        """渲染后台管理页面"""
        data = load_member_data()
        if data is None:
            return "无法从Supabase加载数据", 500
        
        return render_template('admin.html', members=data['members'])

    @app.route('/admin/update', methods=['POST'])
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