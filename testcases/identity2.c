#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(R);

struct REFTRACK_CUSTOM(R) R {
    int im;
};

REFTRACK_EPILOG(R);
REFTRACK_DEF_CTOR(R);

typedef struct R R;


R *id(R* p){
    return p;
}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    R *p = R_create();
    R *rp  = id(id(p));
    rp->im++;

    printf("After id(id(x))\n");
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);

}
