//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

// --- 配置 Map 索引定义 ---
#define CONF_REQ_CONN_OFF_INDEX     1
#define CONF_CONN_FD_OFF_INDEX      2
#define CONF_CONN_SOCKADDR_OFF_INDEX 3

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} nginx_config_map SEC(".maps");

static __always_inline __u32 get_nginx_config(__u32 index) {
    __u32 *val = bpf_map_lookup_elem(&nginx_config_map, &index);
    return val ? *val : 0;
}

struct nginx_event {
    __u32 pid;
    __u32 status;
    __u32 addr;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} nginx_events SEC(".maps");

SEC("uprobe/ngx_http_finalize_request")
int handle_ngx_finalize(struct pt_regs *ctx) {
    void *r = (void *)PT_REGS_PARM1(ctx);
    long rc = PT_REGS_PARM2(ctx);
    
    // 只关注有效 HTTP 状态码
    if (rc < 100 || rc > 599) {
        return 0;
    }

    __u32 req_conn_off = get_nginx_config(CONF_REQ_CONN_OFF_INDEX);
    __u32 conn_fd_off = get_nginx_config(CONF_CONN_FD_OFF_INDEX);
    __u32 conn_sockaddr_off = get_nginx_config(CONF_CONN_SOCKADDR_OFF_INDEX);


    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 1. 读取 Connection 指针 (r + req_conn_off)
    void *conn = NULL;
    if (bpf_probe_read_user(&conn, sizeof(conn), r + req_conn_off) != 0 || !conn) {
        return 0;
    }

    // 2. 读取 FD (conn + conn_fd_off)
    __u32 fd = 0;
    bpf_probe_read_user(&fd, sizeof(fd), conn + conn_fd_off);

    // 3. 读取 sockaddr 指针 (conn + conn_sockaddr_off)
    void *sockaddr_ptr = NULL;
    if (bpf_probe_read_user(&sockaddr_ptr, sizeof(sockaddr_ptr), conn + conn_sockaddr_off) != 0 || !sockaddr_ptr) {
        return 0;
    }

    // 4. 从 sockaddr_in 提取 IP（sin_addr 偏移为 4）
    __u32 addr = 0;
    if (bpf_probe_read_user(&addr, sizeof(addr), sockaddr_ptr + 4) != 0) {
        return 0;
    }

    // 5. 上报事件
    struct nginx_event *ev = bpf_ringbuf_reserve(&nginx_events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    ev->pid = pid;
    ev->status = (__u32)rc;
    ev->addr = addr;
    ev->fd = fd;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
