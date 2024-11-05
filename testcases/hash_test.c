#define REFTRACK_DEBUG
#define REFTRACK_TRACE

#include "hrcmm.h"
#include "uthash.h"
#include <assert.h>

typedef int key_t;

REFTRACK_STRUCT(my_struct){
    key_t key;
    float value;
    UT_hash_handle hh;
};
REFTRACK_EPILOG(my_struct);

typedef struct my_struct my_struct;

int main(int argc, char *argv[]){
    my_struct *ht = NULL;

    int entries = 30;
    
    if (argc == 2){
        entries=atoi(argv[1]);
    }
    
    atexit(print_mem_stats);
    
    for(int i = 0; i < entries; i++){
        my_struct *vo = my_struct_create();
        vo->key = i+1;
        vo->value = vo->key*0.5;
        // need to add reference manually as uthash doesn't preserve the type of my_struct internally.
        my_struct_addref(vo); 
        HASH_ADD_INT(ht, key, vo);
    }

    assert(HASH_COUNT(ht) == entries);
    
    my_struct *tmp = NULL;
    key_t search_key = entries;
    
    printf("Before HASH_FIND_INT\n");
    HASH_FIND_INT(ht, &search_key, tmp);
    printf("After HASH_FIND_INT\n");
    
    if (tmp){
        assert(tmp->value == (entries)*0.5);
    }
    else{
        printf("Entry not found:%d\n", search_key);
    }
      
    // delete all entries

    my_struct *cur_elem = NULL, *it_tmp = NULL;
    
    HASH_ITER(hh, ht, cur_elem, it_tmp){
        printf("---BEGIN LOOP BODY---\n");
        printf("Deleting entry:|%p|:key:%d, RC:%d\n", cur_elem, cur_elem->key, REFTRACK_COUNT(cur_elem));
        HASH_DEL(ht, cur_elem);
        my_struct_removeref(cur_elem);
        printf("---END LOOP BODY---\n");
    }
   

    
}

