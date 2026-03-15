# 1. 创建日志记录辅助函数
def log_operation(operation_type, target_table, target_id=None, target_name=None, 
                  action_details=None, old_value=None, new_value=None):
    """记录操作日志到 operation_logs 表"""
    # 获取当前用户、IP 等信息
    # 写入数据库

# 2. 在关键操作处调用
@app.route('/admin/create', methods=['POST'])
@login_required
def admin_create():
    # ... 原有逻辑
    success = create_member(...)
    if success:
        log_operation(
            operation_type='add_member',
            target_table='members',
            target_id=new_member_id,
            target_name=name,
            action_details=f'添加新成员：{name}，积分：{score}',
            new_value={'name': name, 'score': score, 'group_id': group_id}
        )
    # ...
