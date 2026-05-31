# EmbyProxy

EmbyProxy 是一个用于管理和转发 Emby 节点请求的代理程序，提供 Web 管理界面、节点配置、转发规则和运行状态管理。

![EmbyProxy 管理界面](https://img.072899.xyz/2026/05/29e593c5516b76d3e8532bb5c1da7bd0.png)

> **重要提醒**
>
> 首次运行前请务必配置 `ADMIN_TOKEN`。它用于登录管理界面和访问管理 API，请不要使用默认值或过短的字符串。

## 程序特点与优势

- **多服务器反代管理**：可以在一个管理界面中维护多个 Emby 服务器节点，为每个节点配置独立名称、上游地址、访问密钥、标签和备注。
- **统一代理入口**：客户端只需要连接当前程序提供的代理地址，即可按节点路径访问不同 Emby 服务器，减少多服务器切换和配置成本。
- **客户端身份伪装**：支持为节点指定客户端身份模板，以预设客户端形态访问上游服务器，适配对客户端类型有要求的播放场景。
- **按节点独立策略**：每个 Emby 节点都可以单独设置是否伪装客户端、是否启用直连访问、保号提醒周期等策略，便于针对不同服务器做差异化配置。
- **Telegram 保号通知**：可为节点配置保号周期、提前提醒时间和通知频率，通过 Telegram 推送保号提醒，减少忘记维护账号的风险。
- **Web 可视化运维**：节点维护、批量迁移、收藏排序、在线检测和播放统计都集中在管理面板中，多服务器维护更直观。
- **轻量本地部署**：Go 单程序运行，使用 SQLite 保存配置和统计数据，支持 Windows、Linux 和 Docker Compose 部署。
- **访问安全控制**：管理界面和管理 API 使用 `ADMIN_TOKEN` 保护，节点也可配置独立密钥，减少未授权访问风险。

## 程序下载和使用

打开 Release 页面下载对应系统的压缩包：

[https://github.com/hkfires/EmbyProxy/releases/latest](https://github.com/hkfires/EmbyProxy/releases/latest)

可用文件：

| 系统 | 架构 | 文件 |
| --- | --- | --- |
| Windows | x64 | `embyproxy-windows-x64.zip` |
| Windows | x86 | `embyproxy-windows-x86.zip` |
| Linux | x64 | `embyproxy-linux-x64.tar.gz` |
| Linux | x86 | `embyproxy-linux-x86.tar.gz` |

压缩包内包含程序文件和 `.env.example` 配置模板。解压后先复制一份配置文件：

```text
.env.example -> .env
```

然后打开 `.env`，把 `ADMIN_TOKEN` 改成自己的管理密钥：

```env
ADMIN_TOKEN=请改成足够长的随机字符串
```

`ADMIN_TOKEN` 用于登录管理界面和访问管理 API，请不要继续使用默认值。程序默认监听 `8787` 端口，只有需要改端口时才设置 `PORT`。

查看当前程序版本：

```text
embyproxy --version
```

## Docker Compose

Docker Compose 部署只需要下载 `compose.yml` 和 `.env.example`，并将两个文件放在同一个目录下：

- [`compose.yml`](https://raw.githubusercontent.com/hkfires/EmbyProxy/main/compose.yml)
- [`.env.example`](https://raw.githubusercontent.com/hkfires/EmbyProxy/main/.env.example)

`compose.yml` 默认使用远程镜像：

```yaml
image: ghcr.io/hkfires/embyproxy:latest
```

使用前先将 `.env.example` 复制为 `.env`，然后用文本编辑器打开 `.env`。

打开 `.env` 后，请先把 `ADMIN_TOKEN` 改成自己的管理密钥：

```env
ADMIN_TOKEN=请改成足够长的随机字符串
```

启动：

```bash
docker compose up -d
```

更新：

```bash
docker compose pull
docker compose up -d
```

## 配置

`.env` 至少需要设置：

```env
ADMIN_TOKEN=用于访问面板的管理密钥
```

常用配置：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_TOKEN` | 无 | 管理界面和管理 API Token，建议改为足够长的随机字符串 |
| `PORT` | `8787` | HTTP 服务监听端口，程序默认绑定 `0.0.0.0` |
| `DB_PATH` | `./data/proxy.db` | SQLite 数据库路径 |

Docker 运行时建议把 `/app/data` 挂载到宿主机目录，避免容器删除后丢失数据库。

## 访问

程序默认监听 `0.0.0.0:8787`。如果在本机访问，打开：

```text
http://127.0.0.1:8787/admin
```

如果部署在服务器上，将 `127.0.0.1` 替换为服务器 IP 或域名，并确认防火墙或反向代理已按预期放行。

代理路径由管理界面中的节点名称决定，通常形如：

```text
http://服务器地址:8787/节点名/
```

如果节点配置了密钥，路径中还需要包含密钥。

## 致谢

本项目根据 [chenhr454/emby---worker](https://github.com/chenhr454/emby---worker) 进行重构，感谢原项目作者的开源贡献与实现思路。

## 许可证

本项目采用 MIT License 开源。
