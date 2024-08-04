/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __NEW_COUNTER_SKEL_H__
#define __NEW_COUNTER_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct new_counter {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *new_increment_count;
	} progs;
	struct {
		struct bpf_link *new_increment_count;
	} links;
	struct new_counter__bss {
		__u64 count;
	} *bss;

#ifdef __cplusplus
	static inline struct new_counter *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct new_counter *open_and_load();
	static inline int load(struct new_counter *skel);
	static inline int attach(struct new_counter *skel);
	static inline void detach(struct new_counter *skel);
	static inline void destroy(struct new_counter *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
new_counter__destroy(struct new_counter *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
new_counter__create_skeleton(struct new_counter *obj);

static inline struct new_counter *
new_counter__open_opts(const struct bpf_object_open_opts *opts)
{
	struct new_counter *obj;
	int err;

	obj = (struct new_counter *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = new_counter__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	new_counter__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct new_counter *
new_counter__open(void)
{
	return new_counter__open_opts(NULL);
}

static inline int
new_counter__load(struct new_counter *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct new_counter *
new_counter__open_and_load(void)
{
	struct new_counter *obj;
	int err;

	obj = new_counter__open();
	if (!obj)
		return NULL;
	err = new_counter__load(obj);
	if (err) {
		new_counter__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
new_counter__attach(struct new_counter *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
new_counter__detach(struct new_counter *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *new_counter__elf_bytes(size_t *sz);

static inline int
new_counter__create_skeleton(struct new_counter *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "new_counter";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "new_coun.bss";
	s->maps[0].map = &obj->maps.bss;
	s->maps[0].mmaped = (void **)&obj->bss;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "new_increment_count";
	s->progs[0].prog = &obj->progs.new_increment_count;
	s->progs[0].link = &obj->links.new_increment_count;

	s->data = new_counter__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *new_counter__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xa0\x09\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1a\0\
\x01\0\xb7\x01\0\0\x02\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdb\x12\0\0\0\
\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\x01\x11\x01\
\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\0\0\
\x02\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x01\x01\x49\
\x13\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\
\x06\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\
\x0b\0\0\x08\x2e\0\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x49\
\x13\x3f\x19\0\0\0\x69\0\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\0\0\
\0\0\0\x02\x02\x30\0\0\0\x08\0\0\0\x02\x03\x2e\0\0\0\0\x05\x02\xa1\0\x03\x3a\0\
\0\0\x04\x3e\0\0\0\x04\0\x05\x04\x06\x01\x06\x05\x08\x07\x02\x06\x4d\0\0\0\0\
\x07\x02\xa1\x01\x07\x55\0\0\0\x08\x01\x08\x05\x07\x07\x08\x08\x02\x30\0\0\0\
\x01\x5a\x09\0\x0a\x68\0\0\0\x05\x0a\x05\x04\0\x30\0\0\0\x05\0\0\0\0\0\0\0\x15\
\0\0\0\x27\0\0\0\x3b\0\0\0\x44\0\0\0\x49\0\0\0\x5d\0\0\0\x63\0\0\0\x76\0\0\0\
\x7c\0\0\0\x90\0\0\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\
\x31\x38\x2e\x31\x2e\x38\0\x6e\x65\x77\x5f\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\
\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\x65\
\x2f\x62\x70\x66\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x63\x68\x61\x72\0\x5f\x5f\
\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x63\x6f\
\x75\x6e\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\
\x6e\x67\0\x5f\x5f\x75\x36\x34\0\x6e\x65\x77\x5f\x69\x6e\x63\x72\x65\x6d\x65\
\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x69\x6e\x74\0\x1c\0\0\0\x05\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xcc\0\
\0\0\xcc\0\0\0\xed\0\0\0\0\0\0\0\0\0\0\x0d\x02\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\
\0\0\x20\0\0\x01\x05\0\0\0\x01\0\0\x0c\x01\0\0\0\x9f\0\0\0\0\0\0\x01\x01\0\0\0\
\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x04\0\0\0\x06\0\0\0\x04\0\0\0\xa4\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\xb8\0\0\0\0\0\0\x0e\x05\0\0\0\x01\0\0\0\xc1\0\0\
\0\0\0\0\x08\x09\0\0\0\xc7\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\xda\0\0\0\0\0\0\
\x0e\x08\0\0\0\x01\0\0\0\xe0\0\0\0\x01\0\0\x0f\0\0\0\0\x0a\0\0\0\0\0\0\0\x08\0\
\0\0\xe5\0\0\0\x01\0\0\x0f\0\0\0\0\x07\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\
\x6e\x65\x77\x5f\x69\x6e\x63\x72\x65\x6d\x65\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\
\x66\x72\x65\x70\x6c\x61\x63\x65\x2f\x69\x6e\x63\x72\x65\x6d\x65\x6e\x74\x5f\
\x63\x6f\x75\x6e\x74\0\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\
\x65\x2f\x62\x70\x66\x2f\x6e\x65\x77\x5f\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\
\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x6e\x65\x77\x5f\x69\x6e\x63\x72\x65\x6d\x65\
\x6e\x74\x5f\x63\x6f\x75\x6e\x74\x28\x29\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\
\x65\x74\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x26\x63\x6f\x75\x6e\x74\
\x2c\x20\x32\x29\x3b\0\x09\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x63\x68\x61\
\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\
\x5f\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x6f\x75\x6e\x74\
\0\x2e\x62\x73\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\0\x9f\xeb\x01\0\x20\0\0\
\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x3c\0\0\0\x50\0\0\0\0\0\0\0\x08\0\0\0\x19\0\0\0\
\x01\0\0\0\0\0\0\0\x03\0\0\0\x10\0\0\0\x19\0\0\0\x03\0\0\0\0\0\0\0\x32\0\0\0\
\x58\0\0\0\0\x28\0\0\x08\0\0\0\x32\0\0\0\x72\0\0\0\x02\x30\0\0\x20\0\0\0\x32\0\
\0\0\x94\0\0\0\x02\x34\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\
\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x72\0\0\0\x05\0\
\x08\0\x50\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\
\x01\x01\x1f\x02\0\0\0\0\x14\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x02\x16\0\0\0\0\
\x0f\x45\xb6\xfc\x53\x23\x72\x67\xb9\x70\x6f\xd4\xc3\x4f\xbe\x11\x28\0\0\0\x01\
\xf5\x5b\x61\xf1\xeb\x40\xeb\xc4\x05\x3f\x6e\xb2\xe1\xa2\x30\x0d\x04\0\0\x09\
\x02\0\0\0\0\0\0\0\0\x03\x0a\x01\x05\x02\x0a\x21\x3d\x02\x02\0\x01\x01\x2f\x68\
\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\x65\x2f\x62\x70\x66\0\x2e\0\
\x6e\x65\x77\x5f\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\
\x6c\x69\x6e\x75\x78\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe2\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0c\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x15\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x22\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x4d\0\0\0\x11\0\
\x06\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\xb8\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x01\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\x03\
\0\0\0\x03\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x15\0\0\0\0\0\0\0\x03\0\
\0\0\x08\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\
\0\x05\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x0c\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\
\x0b\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\xc4\0\0\0\0\0\0\0\x04\0\0\0\
\x0b\0\0\0\xdc\0\0\0\0\0\0\0\x04\0\0\0\x0c\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x32\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x47\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x61\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x0a\x0c\x0b\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\
\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x6e\
\x65\x77\x5f\x69\x6e\x63\x72\x65\x6d\x65\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x2e\
\x72\x65\x6c\x66\x72\x65\x70\x6c\x61\x63\x65\x2f\x69\x6e\x63\x72\x65\x6d\x65\
\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\
\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x62\x73\x73\0\x2e\x64\x65\
\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\
\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\
\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\
\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x6e\x65\x77\x5f\x63\x6f\x75\x6e\
\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\
\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf4\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x93\x08\0\0\0\0\0\0\x0d\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3a\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x30\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x36\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x06\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xb9\0\0\0\x01\0\0\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6a\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x78\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\0\0\
\0\0\0\0\0\x73\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x9e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xeb\0\0\0\0\0\0\0\x6d\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9a\0\0\0\x09\0\0\
\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x06\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x19\
\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x57\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x01\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x53\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xe0\x06\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\x19\0\0\0\x0a\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\x6f\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x8c\x01\0\0\0\0\0\0\x94\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\x8e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x02\
\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x8a\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x07\0\0\0\0\0\0\
\x30\0\0\0\0\0\0\0\x19\0\0\0\x0d\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x08\
\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x02\0\0\0\0\0\0\xd1\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\x01\0\0\x09\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x07\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\x19\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\x04\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xe0\x07\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x19\0\0\0\x11\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xd5\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x88\x04\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xd1\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x08\
\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\
\0\0\0\0\xc5\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x04\0\0\0\0\0\
\0\x76\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc1\0\0\
\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x08\0\0\0\0\0\0\x50\0\0\0\0\
\0\0\0\x19\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7a\0\0\0\x01\0\
\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x26\x05\0\0\0\0\0\0\x32\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xaa\0\0\0\x03\x4c\xff\x6f\0\
\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x90\x08\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x19\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfc\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x58\x05\0\0\0\0\0\0\x38\x01\0\0\0\0\0\0\x01\0\0\0\x0a\0\0\0\
\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct new_counter *new_counter::open(const struct bpf_object_open_opts *opts) { return new_counter__open_opts(opts); }
struct new_counter *new_counter::open_and_load() { return new_counter__open_and_load(); }
int new_counter::load(struct new_counter *skel) { return new_counter__load(skel); }
int new_counter::attach(struct new_counter *skel) { return new_counter__attach(skel); }
void new_counter::detach(struct new_counter *skel) { new_counter__detach(skel); }
void new_counter::destroy(struct new_counter *skel) { new_counter__destroy(skel); }
const void *new_counter::elf_bytes(size_t *sz) { return new_counter__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
new_counter__assert(struct new_counter *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->count) == 8, "unexpected size of 'count'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __NEW_COUNTER_SKEL_H__ */
