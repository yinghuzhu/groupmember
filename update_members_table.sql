-- 重命名字段
ALTER TABLE members RENAME COLUMN group_type TO group_id;

-- 添加外键约束
ALTER TABLE members 
ADD CONSTRAINT fk_members_group 
FOREIGN KEY (group_id) REFERENCES groups(id);