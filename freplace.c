#include <unistd.h>
#include "counter_skel.h"
#include "new_counter_skel.h"
#include <bpf/bpf.h>
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
	struct bpf_prog_info prog_info, ext_prog_info;
	int err, prog_fd, ext_prog_fd;
	__u32 prog_info_len, ext_prog_info_len;

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

	ext_prog_fd = bpf_program__fd(ext_skel->progs.new_increment_count);

	printf("Successfully started!\n");

	for (;;) {
		prog_info_len = sizeof(prog_info);
		ext_prog_info_len = sizeof(ext_prog_info);
		ext_prog_fd = bpf_program__fd(ext_skel->progs.new_increment_count);
		err = bpf_obj_get_info_by_fd(ext_prog_fd, &ext_prog_info, &ext_prog_info_len);
		prog_fd = bpf_program__fd(skel->progs.counter);
		err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_info_len);

		fprintf(stderr, ".");
		fprintf(stderr, "count: %llu\n", prog_info.run_cnt);
		sleep(1);
	}

cleanup:
	counter__destroy(skel);
	return -err;
}