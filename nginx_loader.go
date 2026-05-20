package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// NginxModule 管理 Nginx eBPF 监控模块的生命周期
type NginxModule struct {
	Objects *nginxmonObjects
	Reader  *ringbuf.Reader
	Uprobe  link.Link
}

// NginxEvent 是从 ringbuf 读取的 Nginx HTTP 事件
type NginxEvent struct {
	Pid    uint32
	Status uint32
	Addr   uint32
	Fd     uint32
}

// LoadNginxModule 加载并初始化 Nginx eBPF 监控模块
func LoadNginxModule(cfg NginxConfig) (*NginxModule, error) {
	spec, err := loadNginxmon()
	if err != nil {
		return nil, fmt.Errorf("load nginxmon spec: %w", err)
	}

	var objs nginxmonObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load nginxmon objects: %w", err)
	}

	// 写入偏移量配置到 config_map
	configPairs := [][2]uint32{
		{0, 0},                               // debug = off
		{1, uint32(cfg.Offset.ReqConn)},      // req_conn offset
		{2, uint32(cfg.Offset.ConnFd)},       // conn_fd offset
		{3, uint32(cfg.Offset.ConnSockaddr)}, // conn_sockaddr offset
	}
	for _, pair := range configPairs {
		if err := objs.NginxConfigMap.Update(pair[0], pair[1], ebpf.UpdateAny); err != nil {
			objs.Close()
			return nil, fmt.Errorf("update nginx config [%d]=%d: %w", pair[0], pair[1], err)
		}
	}

	// 发现 Nginx 路径并 attach uprobe
	nginxPath, err := findNginxPath()
	if err != nil {
		objs.Close()
		return nil, err
	}
	eventLogger.Event("findNginxPath", map[string]interface{}{"path": nginxPath})
	ex, err := link.OpenExecutable(nginxPath)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("open nginx executable %s: %w", nginxPath, err)
	}

	up, err := ex.Uprobe("ngx_http_finalize_request", objs.HandleNgxFinalize, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach uprobe ngx_http_finalize_request: %w", err)
	}

	// 创建 ringbuf reader
	rd, err := ringbuf.NewReader(objs.NginxEvents)
	if err != nil {
		up.Close()
		objs.Close()
		return nil, fmt.Errorf("create nginx ringbuf reader: %w", err)
	}

	return &NginxModule{
		Objects: &objs,
		Reader:  rd,
		Uprobe:  up,
	}, nil
}

// ReadEvent 读取一个 Nginx 事件
func (m *NginxModule) ReadEvent() (NginxEvent, error) {
	record, err := m.Reader.Read()
	if err != nil {
		return NginxEvent{}, err
	}

	raw := record.RawSample
	if len(raw) < 16 {
		return NginxEvent{}, fmt.Errorf("nginx event too short: %d bytes", len(raw))
	}

	return NginxEvent{
		Pid:    le32(raw[0:4]),
		Status: le32(raw[4:8]),
		Addr:   le32(raw[8:12]),
		Fd:     le32(raw[12:16]),
	}, nil
}

// Close 释放所有资源
func (m *NginxModule) Close() error {
	var err error
	if m.Reader != nil {
		err = m.Reader.Close()
	}
	if m.Uprobe != nil {
		err = joinErrors(err, m.Uprobe.Close())
	}
	if m.Objects != nil {
		err = joinErrors(err, m.Objects.Close())
	}
	return err
}

// findNginxPath 从 /proc 中查找 Nginx worker 进程的可执行文件路径
// 逻辑复用自 ngx_ebpf 项目已验证的 findNginxPath
func findNginxPath() (string, error) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("read /proc: %w", err)
	}

	selfPid := os.Getpid()

	type inodeKey struct {
		dev uint64
		ino uint64
	}

	seen := make(map[inodeKey]struct{})

	for _, entry := range procEntries {
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}

		pid := 0
		if _, err := fmt.Sscanf(name, "%d", &pid); err != nil || pid == selfPid {
			continue
		}

		// 过滤 nginx worker process
		cmdlineBytes, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil || len(cmdlineBytes) == 0 {
			continue
		}

		cmdline := string(bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte{' '}))
		if !strings.Contains(cmdline, "nginx: worker process") {
			continue
		}

		// 获取 exe 真实路径
		exeTarget, err := os.Readlink("/proc/" + name + "/exe")
		if err != nil || !strings.Contains(exeTarget, "nginx") {
			continue
		}

		// 构造 mount namespace 内真实路径
		attachPath := "/proc/" + name + "/root" + exeTarget

		// inode 去重
		fi, err := os.Stat(attachPath)
		if err != nil {
			continue
		}

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		key := inodeKey{dev: uint64(st.Dev), ino: st.Ino}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		return attachPath, nil
	}

	return "", fmt.Errorf("no nginx worker process found")
}

// le32 从小端字节序读取 uint32
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func joinErrors(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	if err2 == nil {
		return err1
	}
	return fmt.Errorf("%v; %v", err1, err2)
}
