#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "../libghthash/ght_hash_table.h"
#include "bpfmap.h"

/* each htab element is struct htab_elem + key + value */
struct htab_elem {
    char key[0] __attribute__((aligned(8)));
};

struct bpf_htab {
    struct bpf_map map;
    // struct bucket *buckets;
    void *elems;

    ght_hash_table_t* htab;

    ght_iterator_t iterator;
    struct htab_elem *current;

    // atomic_t count;    /* number of elements in this hashtable */
    uint32_t n_buckets;    /* number of hash buckets */
    uint32_t elem_size;    /* size of each element in bytes */
};

struct bpf_map *htab_map_alloc(union bpf_attr *attr)
{
    struct bpf_htab *htab;
    int err, i;
    uint64_t cost;

    // if (attr->map_flags & ~BPF_F_NO_PREALLOC) {
    //     /* reserved bits should not be used */
    //     errno = EINVAL;
    //     return NULL;
    // }

    htab = calloc(1, sizeof(*htab));
    if (!htab) {
        errno = ENOMEM;
        return NULL;
    }

    /* mandatory map attributes */
    htab->map.map_type = attr->map_type;
    htab->map.key_size = attr->key_size;
    htab->map.value_size = attr->value_size;
    htab->map.max_entries = attr->max_entries;
    // htab->map.map_flags = attr->map_flags;

    /* check sanity of attributes.
     * value_size == 0 may be allowed in the future to use map as a set
     * max key size is 8 Bytes, which is what the CAM can hold
     * the same for max value size of 8 Bytes
     */
    if (htab->map.max_entries == 0 || htab->map.key_size == 0 ||
        htab->map.key_size > 8 || htab->map.value_size == 0 || htab->map.value_size > 8)
        goto free_htab;

    htab->htab = ght_create(htab->map.max_entries);
    if (htab->htab == NULL)
        goto free_htab;

    htab->elem_size = sizeof(struct htab_elem) +
              round_up(htab->map.key_size, 8) +
              round_up(htab->map.value_size, 8);

    return &htab->map;

free_htab:
    free(htab);
    errno = EINVAL;
    return NULL;
}

void *htab_map_lookup_elem(struct bpf_map *map, void *key)
{
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
    struct htab_elem *l = ght_get(htab->htab, map->key_size, key);

    if (l == NULL) {
        errno = ENOENT;
        return NULL;
    }

    return l->key + round_up(map->key_size, 8);
}

int htab_map_update_elem(struct bpf_map *map, void *key, void *value,
                uint64_t map_flags)
{
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
    struct htab_elem *l_old;
    struct htab_elem *l_new;

    // ght_replace doesn't work
    l_old = ght_get(htab->htab, map->key_size, key);
    if (l_old != NULL) {
        ght_remove(htab->htab, map->key_size, key);
        free(l_old);
    }

    // Allocate the new element
    l_new = calloc(1, htab->elem_size);
    if (l_new == NULL) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(l_new->key, key, map->key_size);
    memcpy(l_new->key + round_up(map->key_size, 8), value, map->value_size);

    return ght_insert(htab->htab, l_new->key, map->key_size, l_new);
}

int htab_map_delete_elem(struct bpf_map *map, void *key)
{
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
    struct htab_elem *l;

    l = ght_remove(htab->htab, map->key_size, key);
    if (l) {
        free(l);
        return 0;
    }

    errno = ENOENT;
    return -1;
}

void htab_map_free(struct bpf_map *map)
{
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);

    ght_iterator_t iterator;
    const void *p_key;
    void *p_e;
    for (p_e = ght_first(htab->htab, &iterator, &p_key); p_e; p_e = ght_next(htab->htab, &iterator, &p_key)) {
        free(p_e);
    }

    ght_finalize(htab->htab);

    free(htab);
}

int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
    struct htab_elem *l;
    const void *p_key;

    // If current is equal to key then continue iterating
    // Otherwise,  initialize iterator,  get(key), if exist, iterate iterator until key

    if (htab->current != NULL && memcmp(htab->current->key, key, map->key_size) == 0) {
        htab->current = ght_next(htab->htab, &htab->iterator, &p_key);
    } else {
        htab->current = ght_first(htab->htab, &htab->iterator, &p_key);

        void *l = ght_get(htab->htab, map->key_size, key);
        if (l != NULL) {
            while (memcmp(p_key, key, map->key_size) != 0) {
                // found the item we were looking for
                htab->current = ght_next(htab->htab, &htab->iterator, &p_key);
            }

            // get the next item
            htab->current = ght_next(htab->htab, &htab->iterator, &p_key);
        }
    }

    if (htab->current == NULL) {
        errno = ENOENT;
        return -1;
    }

    memcpy(next_key, p_key, map->key_size);
    return 0;
}

void htab_map_print(struct bpf_map *map){
    unsigned int n_items;
    ght_iterator_t iterator;
    void *key;
    void *val;
    struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
    char fmt[64];
    unsigned char *keybuf;
    unsigned char *valbuf;
    struct htab_elem *elem;

    // keybuf = (char*) malloc(map->key_size);
    // memset(keybuf,0xa,sizeof(keybuf));
    // keybuf[map->key_size] = '\0';
    // valbuf = (char*) malloc(map->value_size);
    // memset(valbuf,0xb,sizeof(valbuf));
    // valbuf[map->value_size] = '\0';
    // if(keybuf == NULL || valbuf == NULL){
    //     printf("Unable to allocate buffers to print map\n");
    //     return;
    // }

    n_items = ght_size(htab->htab);
    if(n_items == 0){
        printf(" Empty\n");
        return;
    }

    printf(" Key\t\tValue\n ");
    sprintf(fmt," 0x%%0%dx\t0x%%0%dx\n",2*map->key_size,2*map->value_size);
    // printf("%s",fmt);
    for(val = ght_first(htab->htab, &iterator, &key); val; val = ght_next(htab->htab, &iterator, &key)){
        elem = (struct htab_elem*) val;
        keybuf = (unsigned char*) elem->key;
        valbuf = (unsigned char*) elem->key + round_up(map->key_size, 8);

        printf("0x");
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        for(int i = map->key_size-1 ; i >= 0; i--)
            printf("%02x",keybuf[i]);
        #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        for(int i = 0 ; i < map->key_size; i++)
            printf("%02x",keybuf[i]);
        #endif
        printf("\t");

        printf("0x");
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        for(int i = map->value_size-1 ; i >= 0 ; i--)
            printf("%02x",valbuf[i]);
        #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        for(int i = 0 ; i < map->value_size ; i++)
            printf("%02x",valbuf[i]);
        #endif


        printf("\n ");

        // printf(fmt,*keybuf,*valbuf);
    }

}
