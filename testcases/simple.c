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


int main(int argc, char *argv[]) {
    atexit(print_mem_stats);
    R *rp = rc_malloc(sizeof(R));
    rp->im = 0xab;
    R  *dummy = rc_malloc(sizeof(R));
    R  *ptr_unused = NULL, **pp = NULL;
    ptr_unused = rp;
    pp = &rp;
    *pp = dummy;
    rp->im = 0xab;
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
}
