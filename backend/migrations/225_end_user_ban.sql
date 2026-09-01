-- 终端用户级封禁：把违规主体从"转售商账号"细化到"该账号下的某个终端客户"。
--
-- 背景：content_moderation_logs 此前只有 user_id（sub2api 账号，即转售商），
-- 自动封号只能 disable 整个账号，转售商名下所有 API Key 一起失效。
-- 一个终端客户违规就连坐其余全部客户。
--
-- end_user_identity 存 sha256 十六进制全量值（非展示用的短前缀）：它是计数与
-- 封禁的主键，截断会造成不同终端用户互相碰撞。原始 X-User-Id 永不落库。
ALTER TABLE content_moderation_logs
    ADD COLUMN IF NOT EXISTS end_user_identity VARCHAR(64) NOT NULL DEFAULT '';

-- 与 auto_banned 分开而不是复用：两层封禁阈值独立，各自的"计数重置锚点"
-- （统计只算最近一次封禁之后的违规）也必须独立，否则解封一层会影响另一层。
ALTER TABLE content_moderation_logs
    ADD COLUMN IF NOT EXISTS end_user_banned BOOLEAN NOT NULL DEFAULT FALSE;

-- 支撑 CountFlaggedByEndUserSince 的窗口计数（按标识过滤 + 按时间倒序取锚点）。
CREATE INDEX IF NOT EXISTS idx_content_moderation_logs_end_user_created_at
    ON content_moderation_logs(end_user_identity, created_at DESC);
