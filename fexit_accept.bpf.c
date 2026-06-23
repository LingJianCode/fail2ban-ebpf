//go:build ignore

#include "bpf_compat.h"

char __license[] SEC("license") = "GPL";

// pid_ctx must match ssh_monitor.bpf.c exactly (maps share the same kernel object)
struct pid_ctx {
    __u32 remote_ip;
    __u64 start_ns;
    __u8 auth_attempted;
};

// Maps must match ssh_monitor.bpf.c in name, type, key/value layout and max_entries.
// At load time, these declarations are replaced with the actual map FDs from the main object.
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

// fexit/inet_csk_accept — kernel 7.x+ signature:
//   struct sock *inet_csk_accept(struct sock *sk, struct proto_accept_arg *arg);
// BPF_PROG last parameter is the return value.
//
// If this program loads and attaches successfully, main.go uses it in place of the
// kretprobe version (lower overhead per event). If it fails (old kernel or BTF mismatch),
// the kretprobe fallback in ssh_monitor.bpf.c is used instead.
SEC("fexit/inet_csk_accept")
int BPF_PROG(handle_accept_fexit, struct sock *sk, struct proto_accept_arg *arg, struct sock *ret) {
    if (!ret) {
        return 0;
    }

    __u16 lport = BPF_CORE_READ(ret, __sk_common.skc_num);
    if (!bpf_map_lookup_elem(&monitored_ports, &lport)) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 daddr = BPF_CORE_READ(ret, __sk_common.skc_daddr);

    struct pid_ctx conn_ctx = {
        .remote_ip = daddr,
        .start_ns = bpf_ktime_get_ns(),
        .auth_attempted = 0,
    };

    bpf_map_update_elem(&pid_ctx_map, &pid, &conn_ctx, BPF_ANY);
    return 0;
}
