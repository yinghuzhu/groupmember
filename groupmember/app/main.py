@app.route('/admin/delete/<int:member_id>', methods=['DELETE', 'POST'])  # 允许 DELETE 和 POST 方法
def delete_member(member_id):
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM members WHERE id = %s", (member_id,))
        db.commit()
        return jsonify({'success': True, 'message': '删除成功'})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)})