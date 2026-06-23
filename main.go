package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var eventLogger *EventLogger

const (
	eventAuthResult       = 1
	eventPreauthShortConn = 2
)

type SSHEvent struct {
	Type       uint32
	Pid        uint32
	RemoteIP   uint32
	RetCode    uint32
	DurationNS uint64
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fatalf("remove memlock: %v", err)
	}

	objs := sshmonObjects{}
	if err := loadConfiguredSshmonObjects(&objs, cfg); err != nil {
		fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	eventLogger, err = NewEventLogger(cfg.Log.File)
	if err != nil {
		fatalf("create logger: %v", err)
	}
	defer eventLogger.Close()

	rt, rd, libPath, banFilter, banManager, xdpBlocker, err := initResources(cfg, &objs)
	if err != nil {
		fatalf("init: %v", err)
	}
	defer rt.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventLogger.Event("service_started", map[string]interface{}{
		"config":             *configPath,
		"libpam":             libPath,
		"log_file":           cfg.Log.File,
		"mode":               cfg.Mode,
		"short_conn_seconds": cfg.Ban.ShortConnSeconds,
		"ssh_port":           cfg.SSH.Port,
		"threshold":          cfg.Ban.Threshold,
		"window_minutes":     cfg.Ban.WindowMinutes,
		"xdp_iface":          cfg.XDP.Iface,
		"xdp_mode":           xdpBlocker.Mode(),
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		runBanExpiryLoop(ctx, banManager, xdpBlocker)
	}()

	go func() {
		defer wg.Done()
		runEventProcessor(ctx, rd, banManager, banFilter, xdpBlocker, cfg)
	}()

	<-ctx.Done()
	eventLogger.Event("service_stopping", map[string]interface{}{
		"signal": ctx.Err().Error(),
	})

	wg.Wait()
	eventLogger.Event("service_stopped", map[string]interface{}{})

	if err := rt.Close(); err != nil && !isClosedPerfError(err) {
		fatalf("shutdown resources: %v", err)
	}
}

// initResources 初始化所有 BPF 探针、XDP 和 perf reader。
// 使用 closers + defer 统一清理，错误时自动按 LIFO 顺序释放已创建的资源。
func initResources(cfg Config, objs *sshmonObjects) (
	rt *Runtime,
	rd *ringbuf.Reader,
	libPath string,
	banFilter *BanFilter,
	banManager *BanManager,
	xdpBlocker *XDPBlocker,
	err error,
) {
	var closers []func()
	defer func() {
		if err != nil {
			for i := len(closers) - 1; i >= 0; i-- {
				closers[i]()
			}
		}
	}()

	banFilter, err = NewBanFilter(cfg)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("create ban filter: %w", err)
	}

	xdpBlocker, err = NewXDPBlocker(cfg)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("attach xdp: %w", err)
	}
	closers = append(closers, func() { _ = xdpBlocker.Close() })

	banManager = NewBanManager(cfg)

	port := cfg.SSH.Port
	var enabled uint8 = 1
	if err = objs.MonitoredPorts.Update(port, enabled, 0); err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("update port map: %w", err)
	}

	// Try fexit accelerator first (independent BPF object, shares maps via MapReplacements)
	var kpAccept link.Link
	var fexitLink link.Link
	var fexitObjs *fexitacceptObjects
	fexitLink, fexitObjs, err = tryAttachFexit(objs)
	if err == nil {
		eventLogger.Event("probe_attached", map[string]interface{}{
			"target": "fexit/inet_csk_accept (accelerator)",
		})
		closers = append(closers, func() { _ = fexitLink.Close() })
		closers = append(closers, func() { _ = fexitObjs.Close() })
	} else {
		eventLogger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("fexit accelerator not available: %v, using kretprobe", err),
		})

		kpAccept, err = attachKretprobe(objs)
		if err != nil {
			return nil, nil, "", nil, nil, nil, fmt.Errorf("attach kretprobe: %w", err)
		}
		closers = append(closers, func() { _ = kpAccept.Close() })
	}

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("attach sched_process_fork: %w", err)
	}
	closers = append(closers, func() { _ = tpFork.Close() })

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}
	closers = append(closers, func() { _ = tpExit.Close() })

	libPath = findLibPAM()
	if err := ensureExecutable(libPath); err != nil {
		eventLogger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("could not ensure executable bit on %s: %v", libPath, err),
		})
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("open libpam: %w", err)
	}

	up, err := ex.Uretprobe("pam_authenticate", objs.HandlePamAuth, nil)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("attach uretprobe: %w", err)
	}
	closers = append(closers, func() { _ = up.Close() })

	rd, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, nil, "", nil, nil, nil, fmt.Errorf("create perf reader: %w", err)
	}
	closers = append(closers, func() { _ = rd.Close() })

	rt = &Runtime{
		objs:       objs,
		reader:     rd,
		kpAccept:   kpAccept,
		fexitLink:  fexitLink,
		fexitObjs:  fexitObjs,
		tpFork:     tpFork,
		tpExit:     tpExit,
		pamProbe:   up,
		xdpBlocker: xdpBlocker,
	}
	return rt, rd, libPath, banFilter, banManager, xdpBlocker, nil
}

// findLibPAM 自动适配架构并动态查找 libpam 路径
func findLibPAM() string {
	var searchPaths []string

	arch := runtime.GOARCH
	is64bit := strings.Contains(arch, "64")

	if is64bit {
		searchPaths = append(searchPaths,
			"/usr/lib/x86_64-linux-gnu/libpam.so.0",
			"/usr/lib64/libpam.so.0",
			"/lib/x86_64-linux-gnu/libpam.so.0",
			"/lib64/libpam.so.0",
		)
	}

	if arch == "arm64" {
		searchPaths = append(searchPaths,
			"/usr/lib/aarch64-linux-gnu/libpam.so.0",
			"/lib/aarch64-linux-gnu/libpam.so.0",
		)
	}

	searchPaths = append(searchPaths,
		"/usr/lib/libpam.so.0",
		"/lib/libpam.so.0",
	)

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "libpam.so.0"
}

func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	mode := info.Mode()
	if mode&0111 == 0 {
		err := os.Chmod(path, mode|0111)
		if err != nil {
			return fmt.Errorf("failed to chmod +x %s: %w (try running as sudo)", path, err)
		}
	}
	return nil
}

func ipv4String(raw uint32) string {
	if raw == 0 {
		return "UNKNOWN"
	}

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, raw)
	return ip.String()
}

func runBanExpiryLoop(ctx context.Context, banManager *BanManager, blocker *XDPBlocker) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, ip := range banManager.Expired(time.Now()) {
				if err := blocker.Unban(ip); err != nil {
					eventLogger.Event("warning", map[string]interface{}{
						"message": fmt.Sprintf("failed to unban %s: %v", ipv4String(ip), err),
					})
					continue
				}
				eventLogger.Event("ip_unblocked", map[string]interface{}{
					"ip": ipv4String(ip),
				})
			}
		case <-ctx.Done():
			return
		}
	}
}

func runEventProcessor(
	ctx context.Context,
	reader *ringbuf.Reader,
	banManager *BanManager,
	banFilter *BanFilter,
	blocker *XDPBlocker,
	cfg Config,
) {
	type readResult struct {
		record ringbuf.Record
		err    error
	}

	for {
		readCh := make(chan readResult, 1)
		go func() {
			rec, err := reader.Read()
			readCh <- readResult{record: rec, err: err}
		}()

		select {
		case <-ctx.Done():
			_ = reader.Close()
			<-readCh // 等待 Read goroutine 退出，避免泄漏
			return
		case result := <-readCh:
			if result.err != nil {
				if isClosedPerfError(result.err) || ctx.Err() != nil {
					return
				}
				eventLogger.Event("warning", map[string]interface{}{
					"message": fmt.Sprintf("read ringbuf event: %v", result.err),
				})
				continue
			}

			var event SSHEvent
			if err := binary.Read(bytes.NewBuffer(result.record.RawSample), binary.LittleEndian, &event); err != nil {
				eventLogger.Event("warning", map[string]interface{}{
					"message": fmt.Sprintf("decode perf event: %v", err),
				})
				continue
			}

			fields := map[string]interface{}{
				"ip":  ipv4String(event.RemoteIP),
				"pid": event.Pid,
				"ret": event.RetCode,
			}

			switch event.Type {
			case eventAuthResult:
				if event.RetCode == 0 {
					eventLogger.Event("auth_success", fields)
					continue
				}

				eventLogger.Event("auth_failed", fields)

				if event.RemoteIP == 0 {
					continue
				}

				if banned, expiresAt := banManager.RegisterFailure(event.RemoteIP, time.Now()); banned {
					logBanResult(banFilter, blocker, fields["ip"], event.RemoteIP, expiresAt, map[string]interface{}{
						"reason":         "auth_failed",
						"threshold":      cfg.Ban.Threshold,
						"window_minutes": cfg.Ban.WindowMinutes,
					})
				}
			case eventPreauthShortConn:
				fields["duration_ms"] = event.DurationNS / uint64(time.Millisecond)
				eventLogger.Event("preauth_short_conn", fields)

				if event.RemoteIP == 0 {
					continue
				}

				exitStatus := event.RetCode & 0xFFFF
				exitSignal := (event.RetCode >> 16) & 0xFFFF
				isCritical := exitSignal == 11 || exitSignal == 4 || exitSignal == 7
				if !isCritical && exitStatus == 255 && event.DurationNS < uint64(100*time.Millisecond) {
					isCritical = true
				}

				if isCritical {
					expiresAt := banManager.ForceBan(event.RemoteIP, time.Now())
					reason := "critical_protocol_error"
					if exitSignal == 11 || exitSignal == 4 || exitSignal == 7 {
						reason = fmt.Sprintf("critical_signal_%d", exitSignal)
					}
					logBanResult(banFilter, blocker, fields["ip"], event.RemoteIP, expiresAt, map[string]interface{}{
						"reason":         reason,
						"exit_status":    exitStatus,
						"exit_signal":    exitSignal,
						"threshold":      cfg.Ban.Threshold,
						"window_minutes": cfg.Ban.WindowMinutes,
					})
					continue
				}

				if banned, expiresAt := banManager.RegisterFailure(event.RemoteIP, time.Now()); banned {
					logBanResult(banFilter, blocker, fields["ip"], event.RemoteIP, expiresAt, map[string]interface{}{
						"reason":             "preauth_short_conn",
						"short_conn_seconds": cfg.Ban.ShortConnSeconds,
						"threshold":          cfg.Ban.Threshold,
						"window_minutes":     cfg.Ban.WindowMinutes,
					})
				}
			default:
				eventLogger.Event("warning", map[string]interface{}{
					"message": fmt.Sprintf("unknown event type %d", event.Type),
				})
			}
		}
	}
}

func attachKretprobe(objs *sshmonObjects) (link.Link, error) {
	l, err := link.Kretprobe("inet_csk_accept", objs.HandleAcceptKretprobe, nil)
	if err == nil {
		eventLogger.Event("probe_attached", map[string]interface{}{
			"target": "kretprobe/inet_csk_accept",
		})
		return l, nil
	}

	return nil, fmt.Errorf("kretprobe attach failed: %w", err)
}

// tryAttachFexit attempts to load and attach the fexit accelerator BPF object.
// It shares the same maps (monitored_ports, pid_ctx_map, events) with the main
// sshmon object via MapReplacements — no duplicate map allocation.
// Returns (link, objects, nil) on success, or (nil, nil, error) if unavailable
// (caller falls back to kretprobe).
func tryAttachFexit(sshmon *sshmonObjects) (link.Link, *fexitacceptObjects, error) {
	spec, err := loadFexitaccept()
	if err != nil {
		return nil, nil, fmt.Errorf("load fexit spec: %w", err)
	}

	// Share maps with the main sshmon object so fexit writes into the same maps
	var objs fexitacceptObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"monitored_ports": sshmon.MonitoredPorts,
			"pid_ctx_map":     sshmon.PidCtxMap,
			"events":          sshmon.Events,
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("load fexit objects: %w", err)
	}

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.HandleAcceptFexit,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach fexit: %w", err)
	}

	return l, &objs, nil
}

func loadConfiguredSshmonObjects(objs *sshmonObjects, cfg Config) error {
	spec, err := loadSshmon()
	if err != nil {
		return err
	}

	if preauthVar := spec.Variables["preauth_short_conn_ns"]; preauthVar != nil {
		if err := preauthVar.Set(uint64(cfg.Ban.ShortConnSeconds) * uint64(time.Second)); err != nil {
			return fmt.Errorf("set preauth_short_conn_ns: %w", err)
		}
	}
	if modeVar := spec.Variables["aggressive_mode"]; modeVar != nil {
		var enabled uint8
		if cfg.Mode == "aggressive" {
			enabled = 1
		}
		if err := modeVar.Set(enabled); err != nil {
			return fmt.Errorf("set aggressive_mode: %w", err)
		}
	}

	return spec.LoadAndAssign(objs, nil)
}

func logBanResult(
	banFilter *BanFilter,
	blocker *XDPBlocker,
	ipValue interface{},
	rawIP uint32,
	expiresAt time.Time,
	fields map[string]interface{},
) {
	if allowed, reason := banFilter.Check(rawIP); !allowed {
		fields["ip"] = ipValue
		if eventReason, exists := fields["reason"]; exists {
			fields["event_reason"] = eventReason
		}
		fields["skip_reason"] = reason
		delete(fields, "reason")
		eventLogger.Event("ban_skipped", fields)
		return
	}

	if err := blocker.Ban(rawIP); err != nil {
		eventLogger.Event("warning", map[string]interface{}{
			"message": fmt.Sprintf("failed to ban %v: %v", ipValue, err),
		})
		return
	}

	fields["ip"] = ipValue
	if !expiresAt.IsZero() {
		fields["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	eventLogger.Event("ip_blocked", fields)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
