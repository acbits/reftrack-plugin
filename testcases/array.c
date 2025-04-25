#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(R)

struct REFTRACK_CUSTOM(R) R {
    int im;
};

REFTRACK_EPILOG(R);
REFTRACK_DEF_CTOR(R);

typedef struct R R;


int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    R *rp = R_create(), *rp2 = R_create(); 
    rp->im = 0xab;

    R *ap[2][2];

    for(int r = 0; r < 2; r++)
       for(int c = 0; c < 2; c++){
	       ap[r][c] = rp;
       }

    R *rp3 = rp2;
    printf("After rp2 = rp\n");
    
    if (rp->im >= 0xab)
        rp3 = ap[0][1];
    else
        rp3 = rp;

    printf("main:RC:%d %d %x\n", REFTRACK_COUNT(rp), REFTRACK_COUNT(rp3), rp->im);
    
}
