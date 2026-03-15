-- 创建操作日志表
CREATE TABLE IF NOT EXISTS operation_logs (
    id BIGSERIAL PRIMARY KEY,
    operator_username VARCHAR(255) NOT NULL,
    operation_type VARCHAR(100) NOT NULL,
    target_table VARCHAR(100),
    target_id BIGINT,
    target_name VARCHAR(255),
    action_details TEXT,
    old_value JSONB,
    new_value JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 添加索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_operation_logs_operator ON operation_logs(operator_username);
CREATE INDEX IF NOT EXISTS idx_operation_logs_operation_type ON operation_logs(operation_type);
CREATE INDEX IF NOT EXISTS idx_operation_logs_target_table ON operation_logs(target_table);
CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at DESC);

-- 添加注释
COMMENT ON TABLE operation_logs IS '管理员操作日志表';
COMMENT ON COLUMN operation_logs.operator_username IS '操作员用户名';
COMMENT ON COLUMN operation_logs.operation_type IS '操作类型（如：add, update, delete, login, password_change等）';
COMMENT ON COLUMN operation_logs.target_table IS '操作的目标表（如：members, blacklist, admin_users, groups等）';
COMMENT ON COLUMN operation_logs.target_id IS '目标记录 ID';
COMMENT ON COLUMN operation_logs.target_name IS '目标记录名称';
COMMENT ON COLUMN operation_logs.action_details IS '操作详细信息描述';
COMMENT ON COLUMN operation_logs.old_value IS '修改前的值（JSON 格式）';
COMMENT ON COLUMN operation_logs.new_value IS '修改后的值（JSON 格式）';
COMMENT ON COLUMN operation_logs.ip_address IS '操作员 IP 地址';
COMMENT ON COLUMN operation_logs.created_at IS '操作时间';
