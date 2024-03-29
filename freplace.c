#include <unistd.h>
#include "freplace_skel.h"
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct freplace *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = freplace__open();
    if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    err = freplace__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
	err = freplace__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
    freplace__destroy(skel);
    return -err;
}