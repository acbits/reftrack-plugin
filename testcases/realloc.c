#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define REFTRACK_DEBUG
#include "hrcmm.h"


REFTRACK_PROLOG(R_)

struct REFTRACK_CUSTOM(R_) R_ {
    int im;
};

REFTRACK_EPILOG(R_);


typedef struct R_ R;

R *srp;

void test_realloc(){
	R *p = rc_malloc(sizeof(R));
	R *q = rc_realloc(p, sizeof(R)*2);
	if (q){
		p = q;
		q->im = 0xac;
		printf("%d\n", q->im);
	}
}

int main(int argc, char *argv[]) {
    atexit(print_mem_stats);
    test_realloc();

    R *rp = rc_malloc(sizeof(R));
    printf("Resizing object:%p\n", rp);
    rp = rc_realloc(rp, sizeof(R)*1000);

    memset(rp, 0,sizeof(R));
    rp->im = 0xab;
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), rp->im);

}
