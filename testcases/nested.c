#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(A);

struct REFTRACK_CUSTOM(A) A {
    int ia;
};

REFTRACK_EPILOG_WITH_DTOR(A);

typedef struct A A;

REFTRACK_PROLOG(B);

struct REFTRACK_CUSTOM(B) B{
    A *ap;
    int ib;
};

REFTRACK_EPILOG_WITH_DTOR(B);

typedef struct B B;

void A_destroy(A *const p){
    printf("A_destroy(A *const)\n");
    fflush(stdout);
}

void B_destroy(B *const p){
    printf("B_destroy(B *const)\n");
    fflush(stdout);
    A_removeref(p->ap);
}

B *fill(B *p, int i){
    
	if (i & 1){
        p->ap = A_create();
        p->ap->ia = 0xff;
        printf("fill:RC:%d\n", REFTRACK_COUNT(p));
		return p;
    }
	else{
		return NULL;
    }
}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    B *rp = B_create();
    memset(rp, 0,sizeof(B));
    rp->ib = 0xab;
    B *fp = fill(rp, 1);
    fill(rp, 2);
    
    printf("main:RC:B:%d,A:%d %x\n", REFTRACK_COUNT(fp), REFTRACK_COUNT(fp->ap), fp->ap->ia);
    
}
