#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int simple(void *ctx)
{
    u128 foo = 10;
    return foo;
}