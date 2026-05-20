# fail2ban-ebpf

一个基于 eBPF 的轻量级入侵防护工具，支持 **SSH 暴力破解拦截** 和 **Nginx HTTP 状态码封控**，无需编写正则表达式、无需配置 sshd/nginx 日志格式，开箱即用。

项目通过 tracing 采集 SSH 认证失败事件和 Nginx HTTP 请求状态码，在用户态做滑动窗口计数；当某个源 IP 在指定时间窗口内达到失败阈值后，将该 IP 写入 XDP 黑名单并在网卡入口直接丢弃后续流量。

## 功能概览

### SSH 防护

- 通过 `inet_csk_accept` + `sched_process_fork` 追踪 SSH 连接和子进程继承关系
- 通过 `pam_authenticate` `uretprobe` 获取认证成功/失败结果
- 支持按 SSH 端口过滤
- 支持配置封禁阈值、统计窗口、封禁时长
- 达到阈值后自动写入 XDP 黑名单
- 支持 `normal` / `aggressive` 两种检测模式（aggressive 模式额外启用 preauth 短连接检测）

### Nginx HTTP 状态码封控

- 通过 `ngx_http_finalize_request` `uprobe` 追踪 Nginx HTTP 请求完成事件
- 自动发现 Nginx worker 进程路径并挂载探针
- 支持自定义监控的 HTTP 状态码列表（如 401、403、404）
- 从请求结构体中提取客户端真实 IP
- 独立的封禁策略（阈值、窗口、时长可与 SSH 分开配置）
- 达到阈值后同样写入 XDP 黑名单，在网卡入口丢弃流量

### 通用功能

- 日志落盘
- 以 `systemd` 或 Docker 方式部署
- 白名单支持（IP 和 CIDR）

## 工作流程

### SSH 防护流程

1. `ssh_monitor.bpf.c` 跟踪 SSH 连接，建立 `PID -> Remote IP` 映射。
2. `pam_authenticate` 返回时上报认证事件。
3. Go 用户态程序读取事件。
4. 如果某个 IP 在窗口内失败次数达到阈值，则加入 `xdp.bpf.c` 的 `blocked_ips` map。
5. XDP 程序在入口检查源 IP，命中黑名单则直接 `XDP_DROP`。

### Nginx 封控流程

1. `nginx_monitor.bpf.c` 通过 uprobe 挂载到 Nginx 的 `ngx_http_finalize_request` 函数。
2. 每个 HTTP 请求完成时，从 `ngx_http_request_t` / `ngx_connection_t` 结构体中提取客户端 IP 和 HTTP 状态码。
3. Go 用户态程序通过 ringbuf 读取事件，过滤不在监控列表中的状态码。
4. 如果某个 IP 在窗口内触发指定状态码的次数达到阈值，则加入 XDP 黑名单。
5. XDP 程序在入口检查源 IP，命中黑名单则直接 `XDP_DROP`。

## 运行要求

### 基础要求

- Linux
- 支持 eBPF / XDP 的内核（5.10以上）
- 宿主机存在 `/sys/kernel/btf/vmlinux`
- 需要 root 权限
- 需要宿主机存在 `libpam.so.0`（SSH 功能依赖）

说明：

- 本项目 SSH 功能依赖 `pam_authenticate` `uprobe`，因此必须能访问宿主机的 `libpam.so`。
- Docker 方式部署时，本质上仍然是在观测和操作宿主机资源，不属于强隔离场景。

### Nginx 功能额外要求

- 宿主机上正在运行的 **Nginx** 服务（需要能发现 worker 进程）
- 需要根据 Nginx 版本正确配置结构体偏移量（详见下方 `nginx.offset` 配置说明）

## Docker 部署

仓库内提供：

- [Dockerfile](./Dockerfile)
- [docker-compose.yml](./docker-compose.yml)

### 启动

如果你使用 compose 中指定的镜像，需要提前修改 `config.yaml` 中的网卡名称( `xdp.iface` )，详见注意事项：

```bash
docker compose up -d
```

查看日志：

```bash
tail -f ./logs/fail2ban-ebpf.log
```

## 日志格式

日志为单行文本，示例：

```text
time=2026-04-29T12:00:00+08:00 event=service_started config=config.yaml ssh_port=22 xdp_iface=ens33 xdp_mode=driver nginx_enabled=true
time=2026-04-29T12:01:02+08:00 event=auth_failed ip=192.168.1.10 pid=1234 ret=7
time=2026-04-29T12:03:15+08:00 event=ip_blocked ip=192.168.1.10 threshold=3 window_minutes=10 expires_at=2026-04-29T13:15+08:00 source=ssh
time=2026-04-29T12:05:00+08:00 event=http_status ip=192.168.1.20 status=404 pid=5678 fd=12 source=nginx
time=2026-04-29T12:06:30+08:00 event=ip_blocked ip=192.168.1.20 threshold=20 window_minutes=5 expires_at=2026-04-29T12:36:30+08:00 source=nginx reason=nginx_http_status
time=2026-04-29T12:13:20+08:00 event=ip_unblocked ip=192.168.1.10 source=ssh
time=2026-04-29T12:37:00+08:00 event=ip_unblocked ip=192.168.1.20 source=nginx
```

### 事件类型说明

| 事件 | 说明 |
|------|------|
| `auth_success` | SSH 认证成功 |
| `auth_failed` | SSH 认证失败 |
| `preauth_short_conn` | SSH preauth 短连接（aggressive 模式） |
| `http_status` | Nginx HTTP 状态码命中监控列表（source=nginx） |
| `ip_blocked` | IP 已被封禁并写入 XDP 黑名单（`source` 字段区分 ssh/nginx） |
| `ip_unblocked` | IP 封禁已过期，已从 XDP 移除（`source` 字段区分 ssh/nginx） |
| `nginx_module_loaded` | Nginx 监控模块加载成功 |

## 注意事项

### 通用

- `xdp.iface` 必须是实际承载入站流量的网卡。
- 某些虚拟网卡或驱动不支持 `offload`/`driver` 模式，程序会自动降级到 `generic`。
- 白名单命中或本机地址的 IP 不会下发到 XDP。
- 本项目当前主要支持 IPv4 黑名单拦截。

### SSH

- 如果 SSH 监听端口不是 `22`，需要同步修改 `ssh.port`。
- `mode=normal` 仅统计 PAM 认证失败；`mode=aggressive` 会额外启用 preauth 短连接检测。

### Nginx

- **默认关闭**，需要在 `config.yaml` 中设置 `nginx.enabled: true` 才会加载 Nginx 监控模块。
- `nginx.watch_status_codes` 配置需要监控的 HTTP 状态码列表，常见值：
  - `401`: 未认证
  - `403`: 禁止访问
  - `404`: 资源不存在（可用于防护扫描行为）
- **偏移量配置**：`nginx.offset` 中的三个字段与 Nginx 版本和编译选项相关，不同版本可能需要调整。默认值适用于常见的官方编译版本：
  - `req_conn`: `ngx_http_request_t` 结构体中 `connection` 字段的偏移量
  - `conn_fd`: `ngx_connection_t` 结构体中 `fd` 字段的偏移量
  - `conn_sockaddr`: `ngx_connection_t` 结构体中 `sockaddr` 字段的偏移量
- Nginx 和 SSH 使用**独立**的封禁策略（阈值、窗口、时长可分别配置），但共享同一个 XDP 黑名单和白名单过滤。

### Docker / 容器

- 如果容器内或宿主机上找不到正确的 `libpam.so.0`，SSH 的 `uprobe` 将无法挂载。
- 如果容器中找不到运行中的 Nginx worker 进程，Nginx 模块将无法启动。
- 容器方式无法生效时，检查是否启用了 `privileged: true`、`pid: host`、`network_mode: host`。

## 故障排查

### XDP 相关

- **XDP 挂载失败**
  检查网卡是否支持 XDP，检查是否以 root 运行。

### SSH 相关

- **`pam_authenticate` 挂载失败**
  检查宿主机 `libpam.so.0` 是否存在，检查容器是否挂载了宿主机库目录。

### Nginx 相关

- **Nginx 模块加载失败（`no nginx worker process found`）**
  - 确认宿主机上 Nginx 服务正在运行
  - 检查是否能从容器内看到宿主机的 `/proc`（需要 `pid: host`）
  - 确认 Nginx worker 进程的 cmdline 中包含 `"nginx: worker process"`

- **`ngx_http_finalize_request` uprobe 挂载失败**
  - 确认 Nginx 二进制文件未被 strip（uprobe 需要符号信息）
  - 检查是否有权限读取 Nginx 可执行文件
  - Docker 场景下确认容器能访问到 Nginx 进程的 `/proc/<pid>/exe`

- **Nginx 事件中 IP 为 0 或状态码异常**
  - 偏移量配置不匹配当前 Nginx 版本，需要重新调整 `nginx.offset`
  - 可通过 `dwarfdump` 或调试工具确认结构体布局

### 通用

- **没有日志输出**
  检查 `log.file` 路径是否可写，检查运行目录下是否创建了 `logs` 目录。

- **容器方式无法生效**
  检查是否启用了 `privileged: true`、`pid: host`、`network_mode: host`。

## 本地构建

### 依赖

至少需要：

- `go`
- `clang`
- `llvm`
- `bpftool`
