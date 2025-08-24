-- 向members表添加group_type字段和updated_at字段
-- group_type: 1-微信群成员, 2-QQ群成员, 3-QQ频道成员
-- updated_at: 每次数据变更时自动更新的时间戳

-- 添加group_type字段
ALTER TABLE members 
ADD COLUMN IF NOT EXISTS group_type INTEGER;

-- 添加updated_at字段，带默认值为当前时间，并设置自动更新
ALTER TABLE members 
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- 创建自动更新updated_at字段的函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 创建触发器，在UPDATE操作时自动更新updated_at字段
DROP TRIGGER IF EXISTS update_members_updated_at ON members;
CREATE TRIGGER update_members_updated_at 
    BEFORE UPDATE ON members 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- 为现有数据设置默认group_type值（假设现有数据都是微信群成员）
UPDATE members 
SET group_type = 1 
WHERE group_type IS NULL;

-- 添加约束确保group_type值有效
ALTER TABLE members 
ADD CONSTRAINT valid_group_type 
CHECK (group_type IN (1, 2, 3));