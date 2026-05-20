package main

import (
	"sync"
	"time"
)

type BanManager struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	duration  time.Duration
	attempts  map[uint32][]time.Time
	banned    map[uint32]time.Time
}

func NewBanManager(cfg Config) *BanManager {
	return &BanManager{
		window:    time.Duration(cfg.SSH.Ban.WindowMinutes) * time.Minute,
		threshold: cfg.SSH.Ban.Threshold,
		duration:  time.Duration(cfg.SSH.Ban.DurationMinutes) * time.Minute,
		attempts:  make(map[uint32][]time.Time),
		banned:    make(map[uint32]time.Time),
	}
}

// NewBanManagerFromConfig 使用独立的阈值/窗口/时长创建 BanManager（供 Nginx 等非 SSH 模块使用）
func NewBanManagerFromConfig(threshold, windowMinutes, durationMinutes int) *BanManager {
	return &BanManager{
		window:    time.Duration(windowMinutes) * time.Minute,
		threshold: threshold,
		duration:  time.Duration(durationMinutes) * time.Minute,
		attempts:  make(map[uint32][]time.Time),
		banned:    make(map[uint32]time.Time),
	}
}

func (m *BanManager) RegisterFailure(ip uint32, now time.Time) (bool, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if banned, expiresAt := m.isAlreadyBanned(ip, now); banned {
		return false, expiresAt
	}

	return m.registerAttempt(ip, now, m.attempts, m.window, m.threshold)
}

func (m *BanManager) ForceBan(ip uint32, now time.Time) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt time.Time
	if m.duration > 0 {
		expiresAt = now.Add(m.duration)
	}
	m.banned[ip] = expiresAt
	delete(m.attempts, ip)
	return expiresAt
}

func (m *BanManager) Expired(now time.Time) []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.duration <= 0 {
		return nil
	}

	var expired []uint32
	for ip, expiresAt := range m.banned {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			expired = append(expired, ip)
			delete(m.banned, ip)
		}
	}
	return expired
}

func (m *BanManager) isAlreadyBanned(ip uint32, now time.Time) (bool, time.Time) {
	if expiresAt, exists := m.banned[ip]; exists && !expiresAt.IsZero() && now.Before(expiresAt) {
		return true, expiresAt
	}
	if expiresAt, exists := m.banned[ip]; exists && expiresAt.IsZero() {
		return true, expiresAt
	}
	return false, time.Time{}
}

func (m *BanManager) registerAttempt(ip uint32, now time.Time, attemptsMap map[uint32][]time.Time, window time.Duration, threshold int) (bool, time.Time) {
	cutoff := now.Add(-window)
	attempts := attemptsMap[ip][:0]
	for _, ts := range attemptsMap[ip] {
		if !ts.Before(cutoff) {
			attempts = append(attempts, ts)
		}
	}
	attempts = append(attempts, now)
	attemptsMap[ip] = attempts

	if len(attempts) < threshold {
		return false, time.Time{}
	}

	var expiresAt time.Time
	if m.duration > 0 {
		expiresAt = now.Add(m.duration)
	}
	m.banned[ip] = expiresAt
	delete(m.attempts, ip)
	return true, expiresAt
}
