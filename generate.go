package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $BPF2GO_ARCH sshmon ssh_monitor.bpf.c --ccflags -g -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $BPF2GO_ARCH xdp xdp.bpf.c --ccflags -g -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $BPF2GO_ARCH fexitaccept fexit_accept.bpf.c --ccflags -g -O2 -Wall
