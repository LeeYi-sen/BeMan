# Management_Center 1.0

独立站点管理控制中心。可管理多个不同国家、云商、域名的 VideoHub 2.0 实例。中心保存站点配置、加密的 API Secret、任务、调度与审计；不复制站点视频库。中心通过 HTTPS 签名请求远程执行操作。

## 启动
```sh
cp .env.example .env
chmod 600 .env
# 编辑 MC_PASSWORD (12+ chars), MC_MASTER_KEY (32+ chars)
# 可用 openssl rand -hex 32 生成随机值；生产 MC_SECURE_COOKIE=1
bash start.sh
```
默认本机 8090。使用 HTTPS 反向代理，推荐仅允许管理员 VPN/IP。`MC_SECURE_COOKIE=1` 时必须通过 HTTPS 登录；仅本机开发可设 `0`。禁止生产环境关闭 HTTPS 或设置 `MC_ALLOW_HTTP_LOCAL=1`（仅供进程级回环测试，非 Docker 跨机用途）。

在网页添加站点：填写名称、地区、远程 HTTPS origin（不含路径）、站点 API Key 和 Secret。点击连接检测/检测全部站点；按站点切换视频、播放源、分类、标签、广告、SEO/搜索配置、导入、排行榜、统计、举报、日志和备份。常用视频操作和批量链接导入有快捷入口；其他管理命令使用 JSON 编辑器，暂非所有字段都有独立可视化表单。请求由中心服务器发起，密钥不回显给浏览器。

## 运营任务
- `health`: 读取能力及远程统计。
- `rankings`: 中心获取公开 ID/浏览统计，计算总榜与今日/周/月榜，再下发有版本的快照；默认每榜最多 1000，payload `{"limit":1000}`。
- `seo`: 中心生成 sitemap ID 列表；先在设置中配置 `site_url`、`seo_index="1"`。可选 `{"generate_metadata":true}` 生成基于内容的元数据（会覆盖手工元数据，默认关闭）。不是搜索排名保证。
- `check_sources`: 中心按时间和次数选择站点线路，调用单次检测，执行失效排除与恢复；payload `{"limit":30,"min_age":86400,"failure_threshold":3}`。仅对已配置批准来源域名的线路检测；HEAD 可达不代表实际能播放。
- `imports`: 创建导入记录后，中心驱动分批执行；可指定 `{"task_id":1}`。默认导入为未发布待授权记录。
- `backup`: 触发远程站点本机备份。

手工执行和每站计划任务独立；新增站点不会自动开始运营，需配置计划。任务在中心 DB 持久化，四个不同站点可同时运行任务（同站串行任务）；网络异常标记 `needs_review`，不盲目重试可能产生重复写入的请求。恢复后核实站点状态，手工重新提交。站点之间故障隔离，管理中心停机不会影响已下发的配置。快照版本防旧排行覆盖，不代表所有业务写入有版本 CAS。站点连接状态来自最近任务，刷新仅重新读取状态，连接检测会真正访问站点。

## 独立数据及运维
`data/management.db`（WAL）、`backups/`、`.env` 归属本目录。站点密钥 Fernet 加密；**MC_MASTER_KEY 必须单独安全备份**，丢失后无法解密既有站点密钥，数据库备份不含主密钥。不要更换主密钥而不重新录入站点密钥。`MC_PASSWORD` 更新并重启会使旧会话无效。独立服务只有一个管理员密码，尚未实现多用户 RBAC；建议限制管理网站访问。

`bash backup.sh` 创建中心本地备份；`bash restore.sh management-...db` 停止中心服务并恢复；`docker compose exec web python maintenance.py diagnose`；`docker compose logs -f`。解除绑定仅删除中心的站点注册、关联任务和调度，不删除远端数据库。远程备份不会自动复制到中心，需另行做主机级异地备份。API 限流、HTTPS/TLS、时间同步由部署环境保证。

## 测试
安装 Python 依赖及 pytest/httpx 后，在此目录执行 `python -m pytest -q tests/test_distributed.py`（相邻 VideoHub 源码需存在，仅测试时需要；正式运行不依赖）。真实本地 HTTP 进程联调通过；Docker 镜像、真实跨洲 TLS、浏览器和广告实机未验证。

## v2.0 白色数据中心

请以 [UPGRADE.md](UPGRADE.md) 为新版操作及升级说明。原 JSON 调试式管理界面已替换为全宽白色分模块 UI；新增中央资源库和跨站点分发 API（要求 VideoHub 2.1），旧站点凭据和任务记录保留。访问统计为远端快照，未接入广告收入 API。`/api/media`、`/api/media/{id}/distribute`、`/api/jobs/{id}/retry`、`/api/overview` 均要求管理会话，写操作要求 CSRF。中央数据库新增 media_library、media_source_keys、media_revisions、media_site_mappings。
