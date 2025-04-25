#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_STRUCT(S) { int im; };

REFTRACK_EPILOG(S);

REFTRACK_DEF_CTOR(S);

typedef struct S S;

void set_S(S *p){
    p->im=0x1234;
}


int main(int argc, char *argv[]){

    S *array[] = {S_create(), S_create(), S_create()};

    for(int i = 0; i < sizeof(array)/sizeof(array[0]); i++){
        S_addref(array[i]);
        set_S(array[i]);
        printf("Object initialized\n");
    }

    atexit(print_mem_stats);

    for(int i = 0; i < sizeof(array)/sizeof(array[0]); i++){
        S_removeref(array[i]);
    }
}
