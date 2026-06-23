# fail2ban-ebpf

一个基于 eBPF 的轻量级 SSH 暴力破解拦截工具，无需编写正则表达式，无需配置sshd日志配置，开箱即用。

项目通过 tracing 采集 SSH 认证失败事件，在用户态做滑动窗口计数；当某个源 IP 在指定时间窗口内达到失败阈值后，将该 IP 写入 XDP 黑名单并在网卡入口直接丢弃后续流量。

## 功能概览

- 通过 `inet_csk_accept` + `sched_process_fork` 追踪 SSH 连接和子进程继承关系
- 通过 `pam_authenticate` `uretprobe` 获取认证成功/失败结果
- 支持按 SSH 端口过滤
- 支持配置封禁阈值、统计窗口、封禁时长
- 达到阈值后自动写入 XDP 黑名单
- 支持日志落盘
- 支持以 `systemd` 或 Docker 方式部署
- 支持白名单（IP和CIDR）

## 工作流程

1. `ssh_monitor.bpf.c` 跟踪 SSH 连接，建立 `PID -> Remote IP` 映射。
2. `pam_authenticate` 返回时上报认证事件。
3. Go 用户态程序读取事件。
4. 如果某个 IP 在窗口内失败次数达到阈值，则加入 `xdp.bpf.c` 的 `blocked_ips` map。
5. XDP 程序在入口检查源 IP，命中黑名单则直接 `XDP_DROP`。

## 运行要求

- Linux
- 支持 eBPF / XDP 的内核（5.10以上）
- 宿主机存在 `/sys/kernel/btf/vmlinux`
- 需要 root 权限
- 需要宿主机存在 `libpam.so.0`

说明：

- 本项目依赖 `pam_authenticate` `uprobe`，因此必须能访问宿主机的 `libpam.so`。
- Docker 方式部署时，本质上仍然是在观测和操作宿主机资源，不属于强隔离场景。

## Docker 部署

仓库内提供：

- [Dockerfile](./Dockerfile)
- [docker-compose.yml](./docker-compose.yml)

### 启动

如果你使用 compose 中指定的镜像，需要提前修改 `config.yaml` 中的网卡名称( `xdp.iface` )，详见注意事项：

```bash
./build.sh
docker compose up -d
```

查看日志：

```bash
tail -f ./logs/fail2ban-ebpf.log
```

## 日志格式

日志为单行文本，示例：

```text
time=2026-04-29T12:00:00+08:00 event=service_started config=config.yaml ssh_port=22 xdp_iface=ens33 xdp_mode=driver
time=2026-04-29T12:01:02+08:00 event=auth_failed ip=192.168.1.10 pid=1234 ret=7
time=2026-04-29T12:03:15+08:00 event=ip_blocked ip=192.168.1.10 threshold=3 window_minutes=10 expires_at=2026-04-29T12:13:15+08:00
time=2026-04-29T12:13:20+08:00 event=ip_unblocked ip=192.168.1.10
```

## 注意事项

- `xdp.iface` 必须是实际承载 SSH 入站流量的网卡。
- 如果 SSH 监听端口不是 `22`，需要同步修改 `ssh.port`。
- `mode=normal` 仅统计 PAM 认证失败；`mode=aggressive` 会额外启用 preauth 短连接检测。
- `whitelist.entries` 支持单个 IPv4 和 IPv4 CIDR；命中白名单或本机地址的 IP 不会下发到 XDP。
- 某些虚拟网卡或驱动不支持 `offload`/`driver` 模式，程序会自动降级到 `generic`。
- 如果容器内或宿主机上找不到正确的 `libpam.so.0`，`uprobe` 将无法挂载。
- 本项目当前主要支持 IPv4 黑名单拦截。

## 故障排查

- XDP 挂载失败
  检查网卡是否支持 XDP，检查是否以 root 运行。

- `pam_authenticate` 挂载失败
  检查宿主机 `libpam.so.0` 是否存在，检查容器是否挂载了宿主机库目录。

- 没有日志输出
  检查 `log.file` 路径是否可写，检查运行目录下是否创建了 `logs` 目录。

- 容器方式无法生效
  检查是否启用了 `privileged: true`、`pid: host`、`network_mode: host`。

## 本地构建

### 依赖

至少需要：

- `go`
- `clang`
- `llvm`
- `bpftool`
