#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(R_)

struct REFTRACK_CUSTOM(R_) R_ {
    int im;
};

REFTRACK_EPILOG(R_)


typedef struct R_ R;


R *id(R* p){
    return p;
}



int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    R *p = R__create();
    R *rp  = id(id(p));
    rp->im++;

    printf("After id(id(x))\n");
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
    
}
