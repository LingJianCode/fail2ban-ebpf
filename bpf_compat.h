//go:build ignore

// bpf_compat.h — compatibility wrapper for kernel 7.x BTF + older libbpf headers
//
// Kernel 7.x BTF exports BPF helper kfuncs (like bpf_stream_vprintk) into vmlinux.h.
// Older libbpf's bpf_helpers.h also declares them (with a different signature),
// causing "conflicting types" at compile time.
//
// We never call bpf_stream_vprintk in our programs, so we rename the declaration
// in bpf_helpers.h to a dummy name to avoid the conflict, then restore it.
// bpf_core_read.h and bpf_tracing.h both include bpf_helpers.h transitively.

#ifndef __BPF_COMPAT_H
#define __BPF_COMPAT_H

// vmlinux.h from kernel 7.x may contain orphan struct forward declarations
// (e.g. "struct aes_enckey;") that trigger -Wmissing-declarations — harmless.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

// Suppress bpf_stream_vprintk from bpf_helpers.h — vmlinux.h already has it
// with a different signature (u32 len__sz vs variadic).
#define bpf_stream_vprintk __bpfc_bpf_stream_vprintk_dummy

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#undef bpf_stream_vprintk

#endif // __BPF_COMPAT_H
