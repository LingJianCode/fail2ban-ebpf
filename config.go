package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode string `yaml:"mode"`
	SSH  struct {
		Port uint16 `yaml:"port"`
	} `yaml:"ssh"`
	Nginx NginxConfig `yaml:"nginx"`
	XDP struct {
		Iface string `yaml:"iface"`
	} `yaml:"xdp"`
	Ban struct {
		Threshold        int    `yaml:"threshold"`
		WindowMinutes    int    `yaml:"window_minutes"`
		DurationMinutes  int    `yaml:"duration_minutes"` // 0 表示永久封禁
		MaxBlockedIPs    uint32 `yaml:"max_blocked_ips"`
		ShortConnSeconds int    `yaml:"short_conn_seconds"`
	} `yaml:"ban"`
	Log struct {
		File string `yaml:"file"`
	} `yaml:"log"`
	Whitelist struct {
		Entries []string `yaml:"entries"`
	} `yaml:"whitelist"`
}

// NginxConfig Nginx HTTP 状态码监控配置
type NginxConfig struct {
	Enabled          bool            `yaml:"enabled"`
	WatchStatusCodes []int           `yaml:"watch_status_codes"`
	Offset           NginxOffset     `yaml:"offset"`
	Ban              NginxBanConfig  `yaml:"ban"`
}

// NginxOffset ngx_http_request_t / ngx_connection_t 结构体字段偏移量
type NginxOffset struct {
	ReqConn      uint32 `yaml:"req_conn"`       // r->connection 的偏移量
	ConnFd       uint32 `yaml:"conn_fd"`         // conn->fd 的偏移量
	ConnSockaddr uint32 `yaml:"conn_sockaddr"`   // conn->sockaddr 的偏移量
}

// NginxBanConfig Nginx 独立封禁策略配置
type NginxBanConfig struct {
	Threshold       int `yaml:"threshold"`        // 窗口内触发封禁的次数
	WindowMinutes   int `yaml:"window_minutes"`    // 统计窗口
	DurationMinutes int `yaml:"duration_minutes"`  // 封禁时长
}

func defaultConfig() Config {
	cfg := Config{}
	cfg.Mode = "normal"
	cfg.SSH.Port = 22
	cfg.Nginx = NginxConfig{
		Enabled:          false,
		WatchStatusCodes: []int{401, 403, 404},
		Offset: NginxOffset{
			ReqConn:      8,
			ConnFd:       24,
			ConnSockaddr: 104,
		},
		Ban: NginxBanConfig{
			Threshold:       20,
			WindowMinutes:   5,
			DurationMinutes: 30,
		},
	}
	cfg.XDP.Iface = "eth0"
	cfg.Ban.Threshold = 3
	cfg.Ban.WindowMinutes = 10
	cfg.Ban.DurationMinutes = 1440
	cfg.Ban.MaxBlockedIPs = 262144
	cfg.Ban.ShortConnSeconds = 2
	cfg.Log.File = "./fail2ban-ebpf.log"
	return cfg
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshal yaml: %w", err)
	}

	return cfg, cfg.validate()
}

func (c Config) validate() error {
	switch {
	case c.Mode != "normal" && c.Mode != "aggressive":
		return fmt.Errorf("mode must be one of: normal, aggressive")
	case c.SSH.Port == 0:
		return fmt.Errorf("ssh.port must be greater than 0")
	case c.XDP.Iface == "":
		return fmt.Errorf("xdp.iface must not be empty")
	case c.Ban.Threshold <= 0:
		return fmt.Errorf("ban.threshold must be greater than 0")
	case c.Ban.WindowMinutes <= 0:
		return fmt.Errorf("ban.window_minutes must be greater than 0")
	case c.Ban.MaxBlockedIPs == 0:
		return fmt.Errorf("ban.max_blocked_ips must be greater than 0")
	case c.Ban.ShortConnSeconds <= 0:
		return fmt.Errorf("ban.short_conn_seconds must be greater than 0")
	case c.Log.File == "":
		return fmt.Errorf("log.file must not be empty")
	}

	// Nginx 配置校验（仅在启用时）
	if c.Nginx.Enabled {
		if c.Nginx.Ban.Threshold <= 0 {
			return fmt.Errorf("nginx.ban.threshold must be greater than 0")
		}
		if c.Nginx.Ban.WindowMinutes <= 0 {
			return fmt.Errorf("nginx.ban.window_minutes must be greater than 0")
		}
		if len(c.Nginx.WatchStatusCodes) == 0 {
			return fmt.Errorf("nginx.watch_status_codes must not be empty")
		}
	}

	return nil
}
