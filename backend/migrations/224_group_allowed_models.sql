-- 分组级模型准入白名单。
-- 与 models_list_config（仅影响 GET /v1/models 展示）不同：本列在调度前强制生效，
-- 命中不到即以 403 拒绝请求。
--
-- 空数组表示不限制。已存在的分组全部以空数组建列，因此升级不会改变任何现有行为；
-- 若把空解读为"不允许任何模型"，本次迁移会让所有部署立刻停摆。
ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS allowed_models JSONB NOT NULL DEFAULT '[]'::jsonb;
