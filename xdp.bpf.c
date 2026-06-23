//go:build ignore

#include "bpf_compat.h"

char __license[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// blocked_ips的长度会在启动时根据config.yaml配置文件进行修改，这里的长度起个语法填充作用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 65536);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->ihl < 5) {
        return XDP_PASS;
    }

    if ((void *)iph + iph->ihl * 4 > data_end) {
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&blocked_ips, &iph->saddr)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
