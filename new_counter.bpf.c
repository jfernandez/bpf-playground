
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

__u64 count = 0;

SEC("freplace/increment_count")
int new_increment_count()
{
	__sync_fetch_and_add(&count, 2);
	return 0;
}