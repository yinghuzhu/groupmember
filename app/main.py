from flask import Flask, render_template, jsonify
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
        """从Supabase加载成员数据"""
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("Supabase配置缺失")
            return None
            
        try:
            # 构建请求URL
            url = f"{SUPABASE_URL}/rest/v1/members"
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

    @app.route('/')
    def index():
        """渲染主页面"""
        data = load_member_data()
        if data is None:
            return "无法从Supabase加载数据", 500
        
        return render_template('index.html', members=data['members'], 
                              last_updated="未知")

    @app.route('/api/members')
    def api_members():
        """提供API接口获取成员数据"""
        data = load_member_data()
        if data is None:
            return jsonify({'error': '无法从Supabase加载数据'}), 500
        
        return jsonify(data)

    return app