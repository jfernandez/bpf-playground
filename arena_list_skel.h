/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __ARENA_LIST_SKEL_H__
#define __ARENA_LIST_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct arena_list {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *arena;
	} maps;

#ifdef __cplusplus
	static inline struct arena_list *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct arena_list *open_and_load();
	static inline int load(struct arena_list *skel);
	static inline int attach(struct arena_list *skel);
	static inline void detach(struct arena_list *skel);
	static inline void destroy(struct arena_list *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
arena_list__destroy(struct arena_list *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
arena_list__create_skeleton(struct arena_list *obj);

static inline struct arena_list *
arena_list__open_opts(const struct bpf_object_open_opts *opts)
{
	struct arena_list *obj;
	int err;

	obj = (struct arena_list *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = arena_list__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	arena_list__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct arena_list *
arena_list__open(void)
{
	return arena_list__open_opts(NULL);
}

static inline int
arena_list__load(struct arena_list *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct arena_list *
arena_list__open_and_load(void)
{
	struct arena_list *obj;
	int err;

	obj = arena_list__open();
	if (!obj)
		return NULL;
	err = arena_list__load(obj);
	if (err) {
		arena_list__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
arena_list__attach(struct arena_list *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
arena_list__detach(struct arena_list *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *arena_list__elf_bytes(size_t *sz);

static inline int
arena_list__create_skeleton(struct arena_list *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "arena_list";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "arena";
	s->maps[0].map = &obj->maps.arena;

	s->data = arena_list__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *arena_list__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x48\x07\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x13\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x11\
\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x73\x17\0\0\x02\x34\0\x03\
\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x13\x01\x0b\x0b\x3a\x0b\
\x3b\x0b\0\0\x04\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x05\x04\x01\
\x49\x13\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x06\x28\0\x03\x25\x1c\x0f\0\0\x07\x0f\0\
\x49\x13\0\0\x08\x01\x01\x49\x13\0\0\x09\x21\0\x49\x13\x37\x0b\0\0\x0a\x24\0\
\x03\x25\x3e\x0b\x0b\x0b\0\0\x0b\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x0c\x21\0\
\x49\x13\x37\x05\0\0\0\xa1\0\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\
\0\0\0\0\0\x02\x08\0\0\0\x02\x03\x29\0\0\0\0\x0b\x02\xa1\0\x03\x20\0\x06\x04\
\x04\x64\0\0\0\0\x07\0\x04\x07\x7d\0\0\0\0\x08\x08\x04\x08\x8f\0\0\0\0\x09\x10\
\x04\x09\x51\0\0\0\0\x0a\x18\x05\xa0\0\0\0\x08\0\x0a\x06\x0b\x80\x80\x80\x80\
\x80\x80\x04\0\0\x07\x69\0\0\0\x08\x75\0\0\0\x09\x79\0\0\0\x21\0\x0a\x05\x05\
\x04\x0b\x06\x08\x07\x07\x82\0\0\0\x08\x75\0\0\0\x0c\x79\0\0\0\0\x04\0\x07\x94\
\0\0\0\x08\x75\0\0\0\x09\x79\0\0\0\x64\0\x0a\x0a\x07\x08\0\x34\0\0\0\x05\0\0\0\
\0\0\0\0\x15\0\0\0\x26\0\0\0\x3a\0\0\0\x40\0\0\0\x45\0\0\0\x49\0\0\0\x5d\0\0\0\
\x67\0\0\0\x73\0\0\0\x7d\0\0\0\x8b\0\0\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\
\x73\x69\x6f\x6e\x20\x31\x38\x2e\x31\x2e\x38\0\x61\x72\x65\x6e\x61\x5f\x6c\x69\
\x73\x74\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\
\x43\x6f\x64\x65\x2f\x62\x70\x66\0\x61\x72\x65\x6e\x61\0\x74\x79\x70\x65\0\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x6d\x61\x70\x5f\x66\x6c\x61\x67\x73\0\x6d\x61\x78\x5f\x65\x6e\x74\
\x72\x69\x65\x73\0\x6d\x61\x70\x5f\x65\x78\x74\x72\x61\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x6e\x69\x71\x75\x65\x5f\x76\x61\
\x6c\x75\x65\x5f\x5f\x43\x4f\x55\x4e\x54\x45\x52\x5f\x5f\0\x0c\0\0\0\x05\0\x08\
\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x08\x01\0\0\x08\x01\0\
\0\x64\0\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\
\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x21\0\0\0\x05\0\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x02\0\0\0\x04\0\0\0\x64\0\0\0\0\0\0\0\x01\0\0\x13\x08\0\0\0\x19\0\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x33\0\0\0\x01\0\0\0\0\0\0\0\x38\
\0\0\0\x05\0\0\0\x40\0\0\0\x42\0\0\0\x07\0\0\0\x80\0\0\0\x4e\0\0\0\x09\0\0\0\
\xc0\0\0\0\x58\0\0\0\0\0\0\x0e\x0a\0\0\0\x01\0\0\0\x5e\0\0\0\x01\0\0\x0f\0\0\0\
\0\x0b\0\0\0\0\0\0\0\x20\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\
\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x5f\x5f\x75\x6e\x69\x71\x75\x65\
\x5f\x76\x61\x6c\x75\x65\x5f\x5f\x43\x4f\x55\x4e\x54\x45\x52\x5f\x5f\0\x74\x79\
\x70\x65\0\x6d\x61\x70\x5f\x66\x6c\x61\x67\x73\0\x6d\x61\x78\x5f\x65\x6e\x74\
\x72\x69\x65\x73\0\x6d\x61\x70\x5f\x65\x78\x74\x72\x61\0\x61\x72\x65\x6e\x61\0\
\x2e\x6d\x61\x70\x73\0\x3f\0\0\0\x05\0\x08\0\x37\0\0\0\x08\x01\x01\xfb\x0e\x0d\
\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x01\0\0\0\0\x03\x01\x1f\x02\
\x0f\x05\x1e\x01\x14\0\0\0\0\x47\x85\x1c\x1e\xb1\x47\x78\x85\x97\xb1\x2c\xdc\
\x55\x60\xcb\xe0\x2f\x68\x6f\x6d\x65\x2f\x6a\x6f\x73\x65\x2f\x43\x6f\x64\x65\
\x2f\x62\x70\x66\0\x61\x72\x65\x6e\x61\x5f\x6c\x69\x73\x74\x2e\x62\x70\x66\x2e\
\x63\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8b\0\0\0\x04\0\
\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xac\0\0\0\x11\0\x03\0\0\0\0\0\0\0\0\0\
\x20\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x02\0\0\0\x11\0\0\0\0\0\0\0\x03\
\0\0\0\x03\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x1a\0\0\0\0\0\0\0\x03\0\
\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\
\0\x04\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\
\x04\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\
\x04\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\
\x04\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\
\x04\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\
\x04\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x08\0\0\0\x18\x01\0\0\0\0\0\0\x04\0\0\0\
\x08\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x2e\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x08\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\
\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\
\x66\x66\x73\x65\x74\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x64\x65\x62\x75\x67\x5f\
\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\
\x64\x72\x73\x69\x67\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\
\x65\0\x61\x72\x65\x6e\x61\x5f\x6c\x69\x73\x74\x2e\x62\x70\x66\x2e\x63\0\x2e\
\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x61\x72\x65\x6e\x61\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x9c\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x89\x06\0\0\
\0\0\0\0\xbb\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2c\0\0\0\x01\0\0\
\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x8b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xeb\0\0\0\0\0\0\0\xa5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x5d\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x05\0\0\0\0\
\0\0\x40\0\0\0\0\0\0\0\x12\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\x38\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x05\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\
\x12\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x32\0\0\0\x01\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x01\0\0\0\0\0\0\xa5\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x51\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x6d\x02\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4d\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x48\x06\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x12\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\xb6\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\
\x02\0\0\0\0\0\0\x84\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xb2\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x06\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x12\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x7f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\x04\0\0\0\0\0\0\x43\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7b\0\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x06\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\x12\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x3d\0\0\0\x01\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\x04\0\0\0\0\0\0\x25\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x6d\0\0\0\x03\x4c\xff\x6f\0\0\0\
\x80\0\0\0\0\0\0\0\0\0\0\0\0\x88\x06\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x12\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa4\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x70\x04\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\x01\0\0\0\x08\0\0\0\x08\0\
\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct arena_list *arena_list::open(const struct bpf_object_open_opts *opts) { return arena_list__open_opts(opts); }
struct arena_list *arena_list::open_and_load() { return arena_list__open_and_load(); }
int arena_list::load(struct arena_list *skel) { return arena_list__load(skel); }
int arena_list::attach(struct arena_list *skel) { return arena_list__attach(skel); }
void arena_list::detach(struct arena_list *skel) { arena_list__detach(skel); }
void arena_list::destroy(struct arena_list *skel) { arena_list__destroy(skel); }
const void *arena_list::elf_bytes(size_t *sz) { return arena_list__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
arena_list__assert(struct arena_list *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __ARENA_LIST_SKEL_H__ */
