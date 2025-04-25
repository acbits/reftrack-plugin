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
    struct R *rp;
};


R *foo(R2 *p, int k){
    p->im++;
    
    
    R *obp;
    {
        R *p1, *p2 = NULL, *pa[8];
        p1=p;
        obp = p;
        p1->im=0xab;
        p1 = p1;

    }
    printf("foo:RC:%d\n", REFTRACK_COUNT(p));
    return p;
}

int even(R *p, int i){
    R *rp = NULL;
    
	if (i & 1){
        rp = p;

		return 0;
    }
	else{
		return 1;
    }
}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    
    R *rp = (R*)malloc(sizeof(R)), *dummy = (R*)malloc(sizeof(R)), *unused = NULL;
    memset(rp, 0,sizeof(R));
    rp->im = 0xab;
    even(rp, 1);
    R *rv = foo(rp, 10);
    int offset = 1, offset2 = -1;
    R *rv2 = offset+rp+offset2;
    printf("main:RC:%d %x %x\n", REFTRACK_COUNT(rv), rv->im, rv2->im);
}
