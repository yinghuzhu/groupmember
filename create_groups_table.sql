CREATE TABLE public.groups (
  id SERIAL PRIMARY KEY,
  name CHARACTER VARYING(100) NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 插入初始数据
INSERT INTO public.groups (id, name, description) VALUES 
(1, '微信群', '微信群成员'),
(2, 'QQ群', 'QQ群成员'),
(3, 'QQ频道', 'QQ频道成员');

-- 重命名字段
ALTER TABLE members RENAME COLUMN group_type TO group_id;

-- 添加外键约束
ALTER TABLE members 
ADD CONSTRAINT fk_members_group 
FOREIGN KEY (group_id) REFERENCES groups(id);