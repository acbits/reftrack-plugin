#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"

REFTRACK_STRUCT(R){
    int im;
};

REFTRACK_EPILOG(R);
typedef struct R R;

R *add(R *p, R *q){
    p->im += q->im;
    return q;
}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    R *rp = (R*)rc_malloc(sizeof(R));
    memset(rp, 0,sizeof(R));
    rp->im = 2;
    R *tmp = add(rp, rp);

    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);

}
