/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __COUNTER_SKEL_H__
#define __COUNTER_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct counter {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *counter;
	} progs;
	struct {
		struct bpf_link *counter;
	} links;
	struct counter__bss {
		__u64 count;
	} *bss;

#ifdef __cplusplus
	static inline struct counter *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct counter *open_and_load();
	static inline int load(struct counter *skel);
	static inline int attach(struct counter *skel);
	static inline void detach(struct counter *skel);
	static inline void destroy(struct counter *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
counter__destroy(struct counter *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
counter__create_skeleton(struct counter *obj);

static inline struct counter *
counter__open_opts(const struct bpf_object_open_opts *opts)
{
	struct counter *obj;
	int err;

	obj = (struct counter *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = counter__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	counter__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct counter *
counter__open(void)
{
	return counter__open_opts(NULL);
}

static inline int
counter__load(struct counter *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct counter *
counter__open_and_load(void)
{
	struct counter *obj;
	int err;

	obj = counter__open();
	if (!obj)
		return NULL;
	err = counter__load(obj);
	if (err) {
		counter__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
counter__attach(struct counter *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
counter__detach(struct counter *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *counter__elf_bytes(size_t *sz);

static inline int
counter__create_skeleton(struct counter *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "counter";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "counter.bss";
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

	s->progs[0].name = "counter";
	s->progs[0].prog = &obj->progs.counter;
	s->progs[0].link = &obj->links.counter;

	s->data = counter__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *counter__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x28\x0c\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1c\0\
\x01\0\xb7\x01\0\0\x01\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdb\x12\0\0\0\
\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x85\x10\0\0\xff\xff\xff\xff\xb7\0\0\
\0\0\0\0\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\x01\x11\x01\x25\x25\x13\x05\
\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x01\x55\x23\x73\x17\x74\x17\0\0\x02\x34\0\
\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x01\x01\x49\x13\0\0\
\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x06\x24\0\
\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\x08\
\x2e\0\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x49\x13\x3f\x19\
\0\0\x09\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\
\x19\x49\x13\x3f\x19\0\0\x0a\x05\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0b\x48\
\0\x7f\x13\x7d\x1b\0\0\x0c\x0f\0\0\0\0\x90\0\0\0\x05\0\x01\x08\0\0\0\0\x01\0\
\x1d\0\x01\x08\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\
\x36\0\0\0\0\x05\x02\xa1\0\x03\x42\0\0\0\x04\x46\0\0\0\x04\0\x05\x04\x06\x01\
\x06\x05\x08\x07\x02\x06\x55\0\0\0\0\x07\x02\xa1\x01\x07\x5d\0\0\0\x08\x01\x08\
\x05\x07\x07\x08\x08\x02\x30\0\0\0\x01\x5a\x09\0\x09\x8e\0\0\0\x09\x03\x18\0\0\
\0\x01\x5a\x0b\0\x10\x8e\0\0\0\x0a\x0c\0\x10\x92\0\0\0\x0b\x61\0\0\0\x04\0\x05\
\x0a\x05\x04\x0c\0\x13\0\0\0\x05\0\x08\0\x01\0\0\0\x04\0\0\0\x03\x02\x30\x03\
\x03\x18\0\x38\0\0\0\x05\0\0\0\0\0\0\0\x15\0\0\0\x23\0\0\0\x37\0\0\0\x40\0\0\0\
\x45\0\0\0\x59\0\0\0\x5f\0\0\0\x72\0\0\0\x78\0\0\0\x88\0\0\0\x8c\0\0\0\x94\0\0\
\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x38\x2e\x31\x2e\
\x38\0\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\
\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\x65\x2f\x62\x70\x66\0\x5f\x6c\x69\x63\
\x65\x6e\x73\x65\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\
\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x63\x6f\x75\x6e\x74\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\x34\
\0\x69\x6e\x63\x72\x65\x6d\x65\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x69\x6e\x74\0\
\x63\x6f\x75\x6e\x74\x65\x72\0\x63\x74\x78\0\x2c\0\0\0\x05\0\x08\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x9f\xeb\
\x01\0\x18\0\0\0\0\0\0\0\xf8\0\0\0\xf8\0\0\0\x19\x01\0\0\0\0\0\0\0\0\0\x0d\x02\
\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x05\0\0\0\x01\0\0\x0c\x01\0\0\
\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x8b\0\0\0\x04\0\0\0\
\x8f\0\0\0\x01\0\0\x0c\x05\0\0\0\xcb\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\
\0\0\0\0\0\x03\0\0\0\0\x07\0\0\0\x09\0\0\0\x04\0\0\0\xd0\0\0\0\0\0\0\x01\x04\0\
\0\0\x20\0\0\0\xe4\0\0\0\0\0\0\x0e\x08\0\0\0\x01\0\0\0\xed\0\0\0\0\0\0\x08\x0c\
\0\0\0\xf3\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\x06\x01\0\0\0\0\0\x0e\x0b\0\0\0\
\x01\0\0\0\x0c\x01\0\0\x01\0\0\x0f\0\0\0\0\x0d\0\0\0\0\0\0\0\x08\0\0\0\x11\x01\
\0\0\x01\0\0\x0f\0\0\0\0\x0a\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\x69\x6e\
\x63\x72\x65\x6d\x65\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x2e\x74\x65\x78\x74\0\
\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\x65\x2f\x62\x70\x66\
\x2f\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x5f\x5f\x6e\x6f\x69\
\x6e\x6c\x69\x6e\x65\x20\x69\x6e\x74\x20\x69\x6e\x63\x72\x65\x6d\x65\x6e\x74\
\x5f\x63\x6f\x75\x6e\x74\x28\x29\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\
\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x26\x63\x6f\x75\x6e\x74\x2c\x20\
\x31\x29\x3b\0\x09\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x63\x74\x78\0\x63\x6f\
\x75\x6e\x74\x65\x72\0\x72\x61\x77\x5f\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\
\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x09\x72\x65\x74\x75\x72\x6e\x20\x69\
\x6e\x63\x72\x65\x6d\x65\x6e\x74\x5f\x63\x6f\x75\x6e\x74\x28\x29\x3b\0\x63\x68\
\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x6f\x75\x6e\
\x74\0\x2e\x62\x73\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\0\x9f\xeb\x01\0\x20\
\0\0\0\0\0\0\0\x24\0\0\0\x24\0\0\0\x64\0\0\0\x88\0\0\0\0\0\0\0\x08\0\0\0\x15\0\
\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\x97\0\0\0\x01\0\0\0\0\0\0\0\x06\0\0\0\x10\0\0\
\0\x15\0\0\0\x03\0\0\0\0\0\0\0\x1b\0\0\0\x3d\0\0\0\0\x24\0\0\x08\0\0\0\x1b\0\0\
\0\x5e\0\0\0\x02\x2c\0\0\x20\0\0\0\x1b\0\0\0\x80\0\0\0\x02\x30\0\0\x97\0\0\0\
\x02\0\0\0\0\0\0\0\x1b\0\0\0\xb0\0\0\0\x09\x48\0\0\x08\0\0\0\x1b\0\0\0\xb0\0\0\
\0\x02\x48\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x18\0\0\0\0\0\0\0\x8e\0\0\0\x05\0\x08\0\x50\0\0\0\x08\x01\x01\xfb\x0e\x0d\
\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x02\0\0\0\0\x14\0\0\0\x03\x01\
\x1f\x02\x0f\x05\x1e\x02\x16\0\0\0\0\x3c\x83\x36\x37\x4d\x82\x14\x55\x39\x13\
\x61\xc6\xa8\xc7\x78\xb2\x24\0\0\0\x01\xf5\x5b\x61\xf1\xeb\x40\xeb\xc4\x05\x3f\
\x6e\xb2\xe1\xa2\x30\x0d\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x09\x01\x05\x02\
\x0a\x21\x3d\x02\x02\0\x01\x01\x04\0\x05\x09\x0a\0\x09\x02\0\0\0\0\0\0\0\0\x03\
\x11\x01\x05\x02\x06\x20\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\
\x65\x2f\x43\x6f\x64\x65\x2f\x62\x70\x66\0\x2e\0\x63\x6f\x75\x6e\x74\x65\x72\
\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfa\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x15\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x26\0\0\0\x12\
\0\x02\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x30\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\x7d\0\0\0\x12\0\x04\0\0\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\
\xd0\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x01\
\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\x0a\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\
\0\x04\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\
\x0a\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x27\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\
\x0f\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x0d\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x28\0\0\0\0\0\0\0\x02\0\0\0\
\x03\0\0\0\xf0\0\0\0\0\0\0\0\x04\0\0\0\x0d\0\0\0\x08\x01\0\0\0\0\0\0\x04\0\0\0\
\x0f\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x3c\0\0\0\0\0\0\0\x04\0\0\0\
\x03\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x88\0\0\0\0\0\0\0\x04\0\0\0\
\x03\0\0\0\x98\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x30\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\
\x0b\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x32\0\0\0\0\0\0\0\x03\0\0\0\
\x0b\0\0\0\x47\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x61\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x7e\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x0e\x0f\x0d\0\x2e\x64\x65\x62\
\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x72\x65\x6c\x2e\x74\x65\x78\x74\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x69\x6e\x63\x72\x65\x6d\x65\
\x6e\x74\x5f\x63\x6f\x75\x6e\x74\0\x2e\x64\x65\x62\x75\x67\x5f\x72\x6e\x67\x6c\
\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\
\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x62\x73\x73\0\x2e\x64\x65\x62\x75\x67\x5f\
\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\
\x63\x6f\x75\x6e\x74\x65\x72\0\x2e\x72\x65\x6c\x72\x61\x77\x5f\x74\x72\x61\x63\
\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x2e\x72\x65\
\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\
\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\
\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\
\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\
\x72\x61\x6d\x65\0\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x2e\
\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\
\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\x0b\0\0\0\0\0\0\x21\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x13\0\0\0\x01\0\
\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\x08\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1b\0\0\0\x02\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x89\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x50\x08\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1b\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\xd1\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\0\
\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x5d\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x08\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\xa9\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb6\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x39\x01\0\0\0\0\0\0\x94\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb2\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x60\x08\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x09\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x36\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcd\
\x01\0\0\0\0\0\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x4a\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x01\0\0\0\0\0\0\
\x3c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x46\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x08\0\0\0\0\0\0\xd0\0\0\0\0\0\
\0\0\x1b\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x62\0\0\0\x01\0\0\
\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x02\0\0\0\0\0\0\x98\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xa6\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xb8\x02\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa2\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x80\x09\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x0f\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x1c\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xe8\x02\0\0\0\0\0\0\x29\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x18\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\x09\
\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1b\0\0\0\x11\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\
\0\0\0\0\x1d\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\x05\0\0\0\0\0\
\0\xa8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x19\0\0\
\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x09\0\0\0\0\0\0\x70\0\0\0\0\
\0\0\0\x1b\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xed\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x05\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe9\0\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x60\x0a\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1b\0\0\0\x15\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xdd\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x06\0\0\0\0\0\0\x92\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xd9\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\
\x0a\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x1b\0\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x6d\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x92\x06\0\0\
\0\0\0\0\x2e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\xc2\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\
\x03\0\0\0\0\0\0\0\x1b\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x01\
\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x06\0\0\0\0\0\0\x80\x01\0\0\
\0\0\0\0\x01\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct counter *counter::open(const struct bpf_object_open_opts *opts) { return counter__open_opts(opts); }
struct counter *counter::open_and_load() { return counter__open_and_load(); }
int counter::load(struct counter *skel) { return counter__load(skel); }
int counter::attach(struct counter *skel) { return counter__attach(skel); }
void counter::detach(struct counter *skel) { counter__detach(skel); }
void counter::destroy(struct counter *skel) { counter__destroy(skel); }
const void *counter::elf_bytes(size_t *sz) { return counter__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
counter__assert(struct counter *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->count) == 8, "unexpected size of 'count'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __COUNTER_SKEL_H__ */
