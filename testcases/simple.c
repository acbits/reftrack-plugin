#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define REFTRACK_DEBUG
#define REFTRACK_TRACE
#define REFTRACK_DEBUG
#include "hrcmm.h"

typedef struct REFTRACK  {
    int im;
} R;


R *srp;

REFTRACK_DESTRUCTOR_FN void R_destroy(R *rp){
    printf("Deleting R:%d\n", rp->im);
}

int main(int argc, char *argv[]) {
    atexit(print_mem_stats);
    R *rp = rc_malloc(sizeof(R));
    REFTRACK_DTOR(rp) = &R_destroy;
    rp->im = 0xab;
    R  *dummy = rc_malloc(sizeof(R));
    R  *ptr_unused = NULL, **pp = NULL;
    ptr_unused = rp;
    pp = &rp;
    *pp = dummy;
    rp->im = 0xab;
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
    //rc_free(rp);
}
