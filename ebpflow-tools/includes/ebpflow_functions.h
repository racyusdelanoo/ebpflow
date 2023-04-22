#ifndef __EBPFLOW_SWITCH_FUNCTIONS_H
#define __EBPFLOW_SWITCH_FUNCTIONS_H


// static int (*__map_insert)(void *map, uint64_t key, uint64_t value) = (void *) 0;

static uint64_t (*__map_lookup)(void *map, uint64_t key) = (void *) 1;

static int (*__map_update)(void *map, uint64_t key, uint64_t value, unsigned long long flags) = (void *) 2;

static int (*__map_delete)(void *map, uint64_t key) = (void *) 3;

static inline uint64_t bpf_map_lookup_elem(void *map, void *keyptr){
	uint64_t key = *((uint64_t*) keyptr);
	return __map_lookup(map,key);
}

static inline int bpf_map_update_elem(void *map, void *keyptr, void *valueptr, unsigned long long flags){
	uint64_t key = *((uint64_t*) keyptr);
	uint64_t val = *((uint64_t*) valueptr);
	return __map_update(map,key,val,flags);
}

static inline int bpf_map_delete_elem(void *map, void *keyptr){
	uint64_t key = *((uint64_t*) keyptr);
	return __map_delete(map,key);
}

#endif