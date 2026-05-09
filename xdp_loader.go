package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type XDPBlocker struct {
	objects  xdpObjects
	link     link.Link
	linkType string
}

func NewXDPBlocker(cfg Config) (*XDPBlocker, error) {
	iface, err := net.InterfaceByName(cfg.XDP.Iface)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", cfg.XDP.Iface, err)
	}

	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("load xdp spec: %w", err)
	}

	if mapSpec := spec.Maps["blocked_ips"]; mapSpec != nil {
		mapSpec.MaxEntries = cfg.Ban.MaxBlockedIPs
	}

	var objects xdpObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load xdp objects: %w", err)
	}

	blocker := &XDPBlocker{objects: objects}
	if err := blocker.attach(iface.Index); err != nil {
		blocker.Close()
		return nil, err
	}

	return blocker, nil
}

func (x *XDPBlocker) attach(ifaceIndex int) error {
	flagNames := []string{"offload", "driver", "generic"}
	modes := []link.XDPAttachFlags{
		link.XDPOffloadMode,
		link.XDPDriverMode,
		link.XDPGenericMode,
	}

	var count int
	for i, mode := range modes {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   x.objects.XdpProg,
			Interface: ifaceIndex,
			Flags:     mode,
		})
		if err == nil {
			x.linkType = flagNames[i]
			x.link = l
			return nil
		}
		count++
	}

	if count == len(modes) {
		return errors.New("failed to attach XDP program")
	}

	return nil
}

func (x *XDPBlocker) Ban(ip uint32) error {
	var blocked uint8 = 1
	return x.objects.BlockedIps.Update(ip, blocked, ebpf.UpdateAny)
}

func (x *XDPBlocker) Unban(ip uint32) error {
	err := x.objects.BlockedIps.Delete(ip)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (x *XDPBlocker) Close() error {
	var closeErr error
	if x.link != nil {
		closeErr = errors.Join(closeErr, x.link.Close())
	}
	closeErr = errors.Join(closeErr, x.objects.Close())
	return closeErr
}

func (x *XDPBlocker) Mode() string {
	return x.linkType
}
