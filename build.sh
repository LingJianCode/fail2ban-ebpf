#!/bin/bash
# 删除repo中的vmlinux.h，并用你自己的替换
sudo rm ./vmlinux.h
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# build
docker build -t localhost/lingjiancode/fail2ban-ebpf .
# push
# docker push docker.cnb.cool/lingjiancode/fail2ban-ebpf 
