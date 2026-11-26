# VideoHub v1 remote API (application 2.0)

所有管理接口都以 `/api/v1/admin` 开头。无 Cookie 登录，不共享数据库。HTTPS，签名时间 ±300 秒；每次生成新 nonce（32 位小写十六进制），服务端持久化防重放。请求体按发送的原始字节计算 SHA256；URL 必须与实际发送的原始 path/query 完全一致。头：`X-API-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature`。签名为 HMAC-SHA256 hex，消息以 LF 连接：key_id, timestamp, nonce, 大写 method, path+query, sha256(body)。无请求体时散列空字节。不要把 secret 放进浏览器或 URL。JSON 编码 UTF-8。

```python
import time, secrets, hmac, hashlib, json, urllib.request, os
origin = 'https://video.example.com'
kid, secret = os.environ['VH_KEY'], os.environ['VH_SECRET']
method, target = 'GET', '/api/v1/admin/dashboard'
body = b''
ts, nonce = str(int(time.time())), secrets.token_hex(16)
msg = '\n'.join([kid, ts, nonce, method, target, hashlib.sha256(body).hexdigest()])
sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request(origin+target, method=method, headers={'X-API-Key':kid,'X-Timestamp':ts,'X-Nonce':nonce,'X-Signature':sig,'Content-Type':'application/json'})
print(json.load(urllib.request.urlopen(req, timeout=30)))
```

| Method | Suffix (after `/api/v1/admin`) | Purpose |
|---|---|---|
| GET | /capabilities, /dashboard | 站点标识、能力及统计 |
| GET | /videos?page=1&limit=30&q= | 视频列表 |
| GET/PUT/DELETE | /videos/{id} | 详情/局部更新/撤下并封禁（软删除） |
| POST | /videos | 新建；发布要求 status=1, rights_status=authorized, rights_reference, 启用源 |
| POST | /videos/{id}/sources | 新增线路 |
| PUT/DELETE | /sources/{id} | 编辑/删除线路 |
| POST | /sources/{id}/check | 单次 HEAD 检测（不下载视频） |
| PUT | /sources/{id}/policy | excluded: true/false，中心决定排除/恢复 |
| GET/POST | /categories, /tags, /providers, /ads | 列表/保存（含 id 为编辑） |
| DELETE | /categories/{id}, /tags/{id}, /providers/{id}, /ads/{id} | 删除 |
| GET | /sources, /reports, /imports, /logs | 分页列表，page/limit |
| POST | /reports/{id} | status: open/resolved/dismissed |
| GET/POST | /settings | site_name, site_url, site_description, seo_title, seo_description, seo_index, search_enabled, search_order |
| POST | /imports | request_id, items；1–5000 条（字符串或记录）；同 request_id 返回同任务 |
| GET | /imports/{id}/items | 导入进度及逐项结果 |
| POST | /imports/{id}/run | 处理最多 25 条待处理记录；事务内去重；可续跑 |
| GET | /published?after=0&limit=500 | 公开视频元数据，ID 游标 |
| GET | /stats?after=0&limit=500 | 最近 31 日每日统计，ID 游标（浏览非真实播放） |
| GET | /rankings | 当前排名记录 |
| PUT | /rankings/{popular,today,week,month} | ids + version（整数单调递增），整榜替换，旧版本拒绝 |
| PUT | /sitemap | ids + version，中心生成的发布 ID 列表；本站过滤已下架内容 |
| PUT | /videos/{id}/seo | title,title_en,description,description_en |
| GET | /backups | 站点本机备份列表 |
| POST | /backup | 站点本机一致性快照 |
| GET | /export | JSON 内容导出（最多 100000 条；大数据使用分页） |

示例视频：`{"title":"Demo","title_en":"Demo","rights_status":"pending","status":0,"sources":[{"source_url":"https://example.com/video.mp4","source_type":"mp4"}]}`。来源类型 iframe/mp4/hls/external；嵌入需要平台允许。广告参数见中心默认编辑模板，必须配置可信域名。`seo_index`/`search_enabled` 为 "0"/"1"，搜索排序 latest/popular/today/week/month/featured。版本用 UTC 毫秒时间戳。配置普通写入没有版本 CAS，避免多个管理客户端同时编辑；快照防旧版本覆盖，导入 request_id 专用幂等，签名 nonce 防重放但不等同于业务幂等。

`openapi.json` 是应用实际路由生成的 OpenAPI（字典参数字段约定见本文和源码），不会在公开站点提供交互式管理文档。公开 API 保留 `/api/public/config`, `/api/public/catalog`, `/api/public/video/{slug}`, `/view`, `/report`；健康检查 `/healthz`。

## v2.1 跨站点内容分发

签名和原有 API 保持一致。`PUT /api/v1/admin/distribution/{media_key}`：media_key 为 32 位十六进制中央资源标识，JSON 传 `revision`（正整数，每站独立递增）、`action`（publish/sync/unpublish/freeze/unfreeze/delete/restore）、`video`（中央资料及 sources、tags、category_name）。发布必须具备真实授权、启用的播放源；sync 保持已有发布状态；unfreeze/restore 恢复为未发布。delete 为可恢复的远端回收站状态，不物理删除。冻结/回收站记录不能用普通发布 API 绕过状态。相同版本重复提交返回已执行结果，旧版本不覆盖新版本。`GET /api/v1/admin/distribution/{media_key}` 查询实际远端映射及状态。每个站点自行保存数据。仪表板新增 today_views、daily、frozen，统计是视频页浏览而非广告曝光或经验证的播放次数。
