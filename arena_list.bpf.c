#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
} arena SEC(".maps");

#include "bpf_arena_alloc.h"