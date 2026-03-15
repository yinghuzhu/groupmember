import os
import requests
from datetime import datetime
from flask import request, session

def get_client_ip():
    """获取客户端 IP 地址"""
    # 优先获取代理后的真实 IP
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_operation(operation_type, target_table=None, target_id=None, 
                  target_name=None, action_details=None, old_value=None, 
                  new_value=None):
    """
    同步记录操作日志
    注意：此函数会阻塞当前请求，直到 Supabase 返回结果
    
    :param operation_type: 操作类型（如 'add_member', 'update_score', 'login_failed'）
    :param target_table: 目标表名（如 'members', 'blacklist', 'admin_users'）
    :param target_id: 目标记录 ID
    :param target_name: 目标记录名称（如成员姓名、管理员用户名）
    :param action_details: 操作描述文本
    :param old_value: 修改前的值（dict）
    :param new_value: 修改后的值（dict）
    """
    try:
        # 1. 环境检查
        SUPABASE_URL = os.environ.get("SUPABASE_URL")
        SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
        
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("⚠️ 警告：缺少 Supabase 配置，审计日志未记录")
            return False

        # 2. 组装数据
        log_data = {
            "operator_username": session.get('admin_username', 'anonymous'),
            "operation_type": operation_type,
            "target_table": target_table,
            "target_id": str(target_id) if target_id else None,
            "target_name": target_name,
            "action_details": action_details,
            "old_value": old_value,
            "new_value": new_value,
            "ip_address": get_client_ip(),
            "created_at": datetime.utcnow().isoformat() + 'Z'
        }
        
        # 过滤掉 None 值，保持数据库整洁
        log_data = {k: v for k, v in log_data.items() if v is not None}

        # 3. 发送同步请求
        url = f"{SUPABASE_URL}/rest/v1/operation_logs"
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f"Bearer {SUPABASE_KEY}",
            'Content-Type': 'application/json'
        }
        
        # 设置合理的 timeout（3 秒），防止 Supabase 响应慢拖死主流程
        response = requests.post(url, headers=headers, json=log_data, timeout=3)
        
        if not response.ok:
            print(f"⚠️ 审计日志写入失败 [HTTP {response.status_code}]: {response.text}")
            return False
            
        return True

    except requests.exceptions.Timeout:
        print("⚠️ 审计日志写入超时：Supabase 响应过慢")
    except Exception as e:
        print(f"⚠️ 审计日志功能异常：{str(e)}")
    
    return False
