#include<linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 10);
    __ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
} arena SEC(".maps");