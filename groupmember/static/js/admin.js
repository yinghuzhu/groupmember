fetch(`/admin/delete/${id}`, {
    method: 'DELETE',  // 使用标准 DELETE 方法
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content  // 添加 CSRF 保护
    }
})