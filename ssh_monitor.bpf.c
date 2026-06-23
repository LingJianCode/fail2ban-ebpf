//go:build ignore

#include "bpf_compat.h"

char __license[] SEC("license") = "GPL";

const volatile __u8 aggressive_mode = 0;
const volatile __u64 preauth_short_conn_ns = 2000000000ULL;

enum ssh_event_type {
    EVENT_AUTH_RESULT = 1,
    EVENT_PREAUTH_SHORT_CONN = 2,
};

struct ssh_event {
    __u32 type;
    __u32 pid;
    __u32 remote_ip;
    __u32 ret_code;
    __u64 duration_ns;
};

struct pid_ctx {
    __u32 remote_ip;
    __u64 start_ns;
    __u8 auth_attempted;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 128);
} monitored_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct pid_ctx);
    __uint(max_entries, 10240);
} pid_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// --- A. 记录新连接 (kretprobe) ---
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept_kretprobe, struct sock *newsk) {
    if (!newsk) {
        return 0;
    }

    // 获取本地端口 (skc_num 是主机字节序)
    __u16 lport = BPF_CORE_READ(newsk, __sk_common.skc_num);

    // 仅记录监控端口（如 22）
    if (!bpf_map_lookup_elem(&monitored_ports, &lport)) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    struct pid_ctx conn_ctx = {
        .remote_ip = daddr,
        .start_ns = bpf_ktime_get_ns(),
        .auth_attempted = 0,
    };

    // 记录映射：当前 sshd 主进程 PID -> 连接上下文
    bpf_map_update_elem(&pid_ctx_map, &pid, &conn_ctx, BPF_ANY);

    return 0;
}

// --- B. 子进程继承关系 (处理 sshd fork) ---
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    struct pid_ctx *parent_ctx = bpf_map_lookup_elem(&pid_ctx_map, &parent_pid);
    if (parent_ctx) {
        bpf_map_update_elem(&pid_ctx_map, &child_pid, parent_ctx, BPF_ANY);
    }
    return 0;
}

// --- C. PAM 认证判定 ---
SEC("uretprobe/pam_authenticate")
int handle_pam_auth(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pid_ctx *conn_ctx = bpf_map_lookup_elem(&pid_ctx_map, &pid);
    __u32 remote_ip = 0;
    if (conn_ctx) {
        conn_ctx->auth_attempted = 1;
        remote_ip = conn_ctx->remote_ip;
    }

    struct ssh_event e = {
        .type = EVENT_AUTH_RESULT,
        .pid = pid,
        .remote_ip = remote_ip,
        .ret_code = (__u32)ret,
        .duration_ns = 0,
    };
	void *ring = bpf_ringbuf_reserve(&events, sizeof(e), 0);
	if (!ring) {
		return 0;
	}
	__builtin_memcpy(ring, &e, sizeof(e));
	bpf_ringbuf_submit(ring, 0);
	return 0;
}

// --- D. 进程退出清理 ---
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct pid_ctx *conn_ctx = bpf_map_lookup_elem(&pid_ctx_map, &pid);
    if (!conn_ctx) {
        return 0;
    }

    // 1. 使用 CO-RE 方式读取，防御内核版本差异
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int raw_exit_code = BPF_CORE_READ(task, exit_code);

    // 2. 解析逻辑 (遵循内核实际位布局)
    __u32 exit_status = (raw_exit_code >> 8) & 0xFF; // 获取 exit(n) 的状态码
    __u32 exit_signal = raw_exit_code & 0x7F;       // 获取导致退出的信号量

    if (aggressive_mode) {
        // 如果没进过 PAM 流程
        if (conn_ctx->auth_attempted == 0) {
            __u64 duration_ns = bpf_ktime_get_ns() - conn_ctx->start_ns;
            
            // 判定异常：
            // a) 活得太短 (2秒内断开)
            // b) 或者是报错退出 (exit_status != 0)
            // c) 或者是被异常信号杀死的 (exit_signal != 0)
            if (duration_ns < preauth_short_conn_ns || exit_status != 0 || exit_signal != 0) {
                struct ssh_event e = {
                    .type = EVENT_PREAUTH_SHORT_CONN,
                    .pid = pid,
                    .remote_ip = conn_ctx->remote_ip,
                    .ret_code = exit_status | (exit_signal << 16), // 把两个信息都给 Go
                    .duration_ns = duration_ns,
                };
			void *ring = bpf_ringbuf_reserve(&events, sizeof(e), 0);
			if (!ring) {
				// ring buffer full, drop event
			} else {
				__builtin_memcpy(ring, &e, sizeof(e));
				bpf_ringbuf_submit(ring, 0);
			}
            }
        }
    }

    bpf_map_delete_elem(&pid_ctx_map, &pid);
    return 0;
}