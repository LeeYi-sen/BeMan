# VideoHub 2.0

独立运行的双语视频前台 + SQLite + 远程能力 API。不会下载、保存、代理或转码视频。仅管理有权展示/嵌入的外部内容；外部站点限制嵌入时可使用原站入口。

## 启动
```sh
cp .env.example .env
chmod 600 .env
# 编辑 .env：设置唯一 SITE_ID、API_KEY、32+ 字符 API_SECRET（openssl rand -hex 32）
bash start.sh
```
默认本机 `http://127.0.0.1:8080`。生产 HTTPS 反代到此地址，保持完整原始 URL path/query，不重写 `/api/v1/admin/`，不剥离签名请求头。外部访问无需登录，管理接口拒绝无签名请求。建议入口防火墙限制管理 API 仅中心服务器地址访问，配合 HTTPS。生产设 `VIDEOHUB_SECURE_COOKIE=1`。启用前先与管理中心同步时钟（NTP）。

数据保存在 `data/video.db`，备份在 `backups/`。`frontend/templates` 和 `frontend/static` 为公开 SSR 前端；后端 FastAPI，SQLite WAL/FTS5。没有 Nuxt 构建依赖，没有 `/admin` 页面或站点本地运营调度进程。`backend/worker.py` 是仅按远程命令运行的导入执行器，不是独立常驻任务。默认广告未配置、SEO 禁止索引、排名为空，待中心下发配置。普通搜索、分类和标签在本站查询，用户访问不跨地域依赖中心。

## 升级 v1
先停止原 v1 所有 API/worker、备份数据库及文件；将备份恢复或复制干净的数据库到本项目 `data/video.db`。新版本会初始化 v2 表，移除原本地管理员、session 和 scheduled_tasks。原有内容/播放源/统计/广告保留。旧管理 URL 不再兼容。新旧代码不要同时访问同一数据库。中心重新生成排行和 sitemap。使用 v1 回滚时恢复升级前数据库，不要让旧程序直接写入 v2 数据库。

## 运维
`bash backup.sh`、`bash stop.sh`、`bash restore.sh video-...db`、`docker compose exec backend python maintenance.py diagnose`、`docker compose logs -f`。恢复脚本要求停止本项目服务。API 备份只生成站点本机备份，不向中心自动传输 DB。备份文件包含内容与运营数据，应保密。远程认证为每站一个配置密钥对；可通过 `VIDEOHUB_API_READ_ONLY=1` 全局只读、通过修改密钥并重启撤销/轮换。尚未实现每密钥细粒度权限、自动密钥轮换和通用写入幂等。重复导入请求有专用 request_id；其它写入超时后应先查询状态，不盲目重试。

详细接口：`API.md`、`openapi.json`。本地测试 `python -m pytest -q tests/test_app.py`（安装 requirements-dev.txt）。实际 iframe/MP4/HLS 播放和广告计佣取决于来源、CORS、广告审核与格式。广告隔离不支持需要顶层跳转/弹窗的格式，未经验证不得宣称全部广告兼容。
