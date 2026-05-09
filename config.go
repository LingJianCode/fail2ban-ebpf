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

func defaultConfig() Config {
	cfg := Config{}
	cfg.Mode = "normal"
	cfg.SSH.Port = 22
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

	return nil
}
