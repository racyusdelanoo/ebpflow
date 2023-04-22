#include <sys/queue.h>
#include <string.h>
#include <stdio.h>

#include "bpfmap.h"
#include "hashtab.h"
#include "ebpflow_consts.h"

#define MAX_MAPS 64
#define MAX_KEY_SZ 8
#define MAX_VAL_SZ 8

struct bpf_map *bpf_maps[MAX_MAPS] = {0};

const struct bpf_map_ops bpf_map_types[] = {
    [BPF_MAP_TYPE_HASH] = {
        .map_alloc = htab_map_alloc,
        .map_free = htab_map_free,
        .map_get_next_key = htab_map_get_next_key,
        .map_lookup_elem = htab_map_lookup_elem,
        .map_update_elem = htab_map_update_elem,
        .map_delete_elem = htab_map_delete_elem,
        .map_print = htab_map_print,
    }
};

int bpf_create_map(enum bpf_map_type map_type, uint64_t key_size, uint64_t value_size, int max_entries, int map_idx) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    // Sanity checks. These are necessary to correctly
    // simulate the switch's behavior
    switch(map_type){
        case BPF_MAP_TYPE_HASH: 
            if(key_size > 8 || value_size > 8)
                return -1;
            break;
        case BPF_MAP_TYPE_LPM_TRIE:
            if(key_size > 8 || value_size > 8)
                return -1;
            break;
        default:
            return -1;
    }

    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;

    const struct bpf_map_ops *map_type_ops = &bpf_map_types[map_type];
    struct bpf_map *map;

    map = map_type_ops->map_alloc(&attr);
    if (map == NULL) {
        return -1;
    }

    map->ops = map_type_ops;

    // Check if index is free
    if (bpf_maps[map_idx] == NULL) {
        bpf_maps[map_idx] = map;
    }else{
        return -1;
    }

    return 0;
}

int bpf_update_elem(int map, uint64_t key, uint64_t value, unsigned long long flags) {
    struct bpf_map *m = bpf_maps[map];

    // Mask key and val according to their sizes
    key = key & (0xFFFFFFFFFFFFFFFFULL >> ((MAX_KEY_SZ-m->key_size)*8));
    value = value & (0xFFFFFFFFFFFFFFFFULL >> ((MAX_VAL_SZ-m->value_size)*8));

    return m->ops->map_update_elem(m, &key, &value, flags);
}

uint64_t bpf_lookup_elem(int map, uint64_t key) {
    void *v = NULL;
    struct bpf_map *m = bpf_maps[map];
    uint64_t val;

    // Mask key according to its size
    key = key & (0xFFFFFFFFFFFFFFFFULL >> ((MAX_KEY_SZ-m->key_size)*8));

    v = m->ops->map_lookup_elem(m, &key);
    if (v == NULL) {
        return LOOKUP_FAIL;
    }

    // Mask val to remove garbage
    val = *((uint64_t*)v) & (0xFFFFFFFFFFFFFFFFULL >> ((MAX_VAL_SZ-m->value_size)*8));

    return val;
}

int bpf_delete_elem(int map, uint64_t key) {
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_delete_elem(m, &key);
}

int bpf_get_next_key(int map, void *key, void *next_key) {
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_get_next_key(m, key, next_key);
}

void bpf_print_map(int map){
    struct bpf_map *m = NULL;

    if(map < MAX_MAPS && bpf_maps[map] != NULL)
        m = bpf_maps[map];

    if(m != NULL)
        m->ops->map_print(m);
}
