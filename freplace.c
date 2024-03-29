#include <unistd.h>
#include "counter_skel.h"
#include "new_counter_skel.h"
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct counter *skel;
	struct new_counter *ext_skel;
	int err, prog_fd;

	libbpf_set_print(libbpf_print_fn);

	skel = counter__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = counter__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	ext_skel = new_counter__open();
	if (!ext_skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.counter);
	if (prog_fd < 0) {
		fprintf(stderr,
			"Failed to get file descriptor for BPF program\n");
		err = prog_fd;
		goto cleanup;
	}

	err = bpf_program__set_attach_target(
		ext_skel->progs.new_increment_count, prog_fd, NULL);
	if (err) {
		fprintf(stderr,
			"Failed to set attach target for BPF program\n");
		goto cleanup;
	}

	err = new_counter__load(ext_skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	bpf_program__attach_freplace(ext_skel->progs.new_increment_count,
				     prog_fd, "increment_count");

	err = counter__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	counter__destroy(skel);
	return -err;
}