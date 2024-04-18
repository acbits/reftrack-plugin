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
    R *rp = R__create();
    rp = R__create();
    rp->im = 0xab;
    R *rp2 = id(id(rp));
    printf("After id(id(x))\n");
    (void)id(id(rp));
    printf("After discarded id(id(x))\n");
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
    
}
