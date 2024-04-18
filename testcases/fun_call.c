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

typedef R R2;

struct C {
    struct R_ *rp;
};


R *odd(R *p, int i){
    
	if (i & 1){
        printf("odd:RC:%d\n", REFTRACK_COUNT(p));
		return p;
    }
	else
		return NULL;
    
}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    R *rp = (R*)rc_malloc(sizeof(R));
    memset(rp, 0,sizeof(R));
    rp->im = 0xab;
    R *tmp = odd(rp, 1);
    odd(rp, 2);
    
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);
    
}
