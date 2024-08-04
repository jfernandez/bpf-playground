#pragma once

#ifndef arena_container_of
#define arena_container_of(ptr, type, member)			\
	({							\
		void __arena *__mptr = (void __arena *)(ptr);	\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

#ifdef __BPF__ /* when compiled as bpf program */

#ifndef PAGE_SIZE
#define PAGE_SIZE __PAGE_SIZE
/*
 * for older kernels try sizeof(struct genradix_node)
 * or flexible:
 * static inline long __bpf_page_size(void) {
 *   return bpf_core_enum_value(enum page_size_enum___l, __PAGE_SIZE___l) ?: sizeof(struct genradix_node);
 * }
 * but generated code is not great.
 */
#endif

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && !defined(BPF_ARENA_FORCE_ASM)
#define __arena __attribute__((address_space(1)))
#define __arena_global __attribute__((address_space(1)))
#define cast_kern(ptr) /* nop for bpf prog. emitted by LLVM */
#define cast_user(ptr) /* nop for bpf prog. emitted by LLVM */
#else
#define __arena
#define __arena_global SEC(".addr_space.1")
#define cast_kern(ptr) bpf_addr_space_cast(ptr, 0, 1)
#define cast_user(ptr) bpf_addr_space_cast(ptr, 1, 0)
#endif

void __arena* bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
				    int node_id, __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym __weak;
#endif