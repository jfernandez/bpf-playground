
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

u64 count = 0;

__noinline int increment_count()
{
	__sync_fetch_and_add(&count, 1);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int test_enable_stats(void *ctx)
{
	return increment_count();
}