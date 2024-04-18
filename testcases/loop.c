#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(R)

struct REFTRACK_CUSTOM(R) R {
    int im;
};

REFTRACK_EPILOG(R)


typedef struct R R;

typedef R R2;

struct C {
    struct R_ *rp;
};

R *srp;



int main(int argc, char *argv[]) {
    atexit(print_mem_stats);
    for(int i = 0; i < 2; i++){
        R *rp = (R*)rc_malloc(sizeof(R)), *dummy = (R*)rc_malloc(sizeof(R)); //, *dummy2;
        memset(rp, 0,sizeof(R));
        rp->im = 0xab;
        printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
        
    }
    
}
