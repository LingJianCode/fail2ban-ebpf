package main

import (
	"errors"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Runtime struct {
	objs       *sshmonObjects
	reader     *ringbuf.Reader
	kpAccept   link.Link   // kretprobe (fexit fallback)
	fexitLink  link.Link   // fexit accelerator (nil if unavailable)
	fexitObjs  *fexitacceptObjects // fexit BPF objects (nil if unavailable)
	tpFork     link.Link
	tpExit     link.Link
	pamProbe   link.Link
	xdpBlocker *XDPBlocker
}

func (r *Runtime) Close() error {
	var closeErr error

	if r.objs != nil {
		closeErr = errors.Join(closeErr, r.objs.Close())
	}
	if r.fexitObjs != nil {
		closeErr = errors.Join(closeErr, r.fexitObjs.Close())
	}
	if r.reader != nil {
		closeErr = errors.Join(closeErr, r.reader.Close())
	}
	closeErr = errors.Join(
		closeErr,
		closeLink(r.fexitLink),
		closeLink(r.pamProbe),
		closeLink(r.tpExit),
		closeLink(r.tpFork),
		closeLink(r.kpAccept),
	)
	if r.xdpBlocker != nil {
		closeErr = errors.Join(closeErr, r.xdpBlocker.Close())
	}

	return closeErr
}

func closeLink(l link.Link) error {
	if l == nil {
		return nil
	}
	return l.Close()
}

func isClosedPerfError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed)
}
