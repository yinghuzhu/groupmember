-- 为 admin_users 表添加超级管理员字段
-- is_super_admin: true-超级管理员，false-普通管理员

-- 添加 is_super_admin 字段，默认值为 false
ALTER TABLE admin_users 
ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT false;

-- 为现有管理员设置权限（如果需要，可以手动更新特定用户为超级管理员）
-- UPDATE admin_users SET is_super_admin = true WHERE username = '你的用户名';

-- 添加注释说明
COMMENT ON COLUMN admin_users.is_super_admin IS '是否为超级管理员（true=超级管理员，false=普通管理员）';
