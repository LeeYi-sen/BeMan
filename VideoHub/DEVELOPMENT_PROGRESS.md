# 2.0 verification
- Removed admin UI/session routes/local scheduler; migrated schema and added HMAC authentication, nonce replay protection, external ranking/sitemap snapshots and source policy.
- 11 local pytest tests passed; distributed real HTTP integration test passed (two independent site services, a center and a center scheduler). See Management_Center/tests/test_distributed.py.
- Docker build, cross-region HTTPS deployment, full browser playback and real ad monetization not validated in the authoring environment.

## v2.1
- 增加分发原子接口、稳定远程映射、版本重放保护、冻结/恢复与回收站状态；保持原有公开前台与 HMAC 签名。
- SQLite 新表以 IF NOT EXISTS 迁移。VideoHub 前台原主题保留，不属于此次管理中心白色主题改版。
