# VideoHub distributed suite / 分布式视频站点套件

两个独立项目，分别部署，**不共享 SQLite、文件、环境变量或容器网络**。本目录只是交付容器，不是运行时依赖。每个子目录都能单独打包、复制、部署。VideoHub 不需要 Management_Center 在线才能服务用户。

- `VideoHub/`：公开前台、远程播放、内容/配置数据库、HMAC 管理 API、单次检测/导入/备份执行能力。没有管理页面、登录入口和自主运营定时器。
- `Management_Center/`：独立管理站点、站点注册与密钥存储、远程操作、调度、排行计算、SEO、广告、失效策略、进度、审计及中心自身备份。

## 部署
1. 分别复制两个文件夹到各自 Linux AMD64 主机。安装 Docker Engine 和 Compose 插件。无需共享任何目录。
2. 各自 `cp .env.example .env`，`chmod 600 .env`，修改密码和密钥（可用 `openssl rand -hex 32` 生成），再 `bash start.sh`。
3. 为各自绑定域名并配置 HTTPS 反代；默认 VideoHub 本机 8080，中心本机 8090。管理端建议 VPN/IP 白名单；VideoHub 管理路径 `/api/v1/admin/` 可在入口代理限制中心公网 IP（不要限制公开前台）。
4. 登录中心，新增每个 VideoHub 的 HTTPS origin、名称、地区和该站独立 API Key/Secret。检测连接，随后管理视频等数据。设置 SEO、广告、搜索策略及计划任务，按需开启各任务。
5. 同一服务器部署多个实例时使用不同端口、独立目录及 `COMPOSE_PROJECT_NAME`，确保不共享数据卷。跨服务器无需统一 Docker 网络。

具体见 `VideoHub/README.md`、`Management_Center/README.md`、`VideoHub/API.md`。首次使用先备份既有 v1 数据。旧 v1 管理账号和本地调度表会移除，视频、分类、来源、广告、统计保留；默认 SEO 索引关闭，须从中心重新配置和下发快照。

## 测试
本地实际 HTTP 联调启动两个站点、中心 Web、中心调度进程。测试使用临时独立 DB，未调用真实外部视频或广告账号。跨洲公网/TLS 实机、Docker 镜像构建和真实浏览器交互尚待部署环境验证。请勿将本地 HTTP 测试等同于跨洲生产验收。

## 2.1 / Management Center 2.0

新版采用白色全宽运营数据中心，双项目仍独立部署。已有系统请阅读 Management_Center/UPGRADE.md，先备份后分别升级；保留已有 `.env` 和数据库。两边都升级后才能使用新中央库分发功能。
