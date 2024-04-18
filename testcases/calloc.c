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


int main(int argc, char *argv[]) {
    atexit(print_mem_stats);
    const int N = 10;
    R *rp = rc_calloc(N, sizeof(R));

    memset(rp, 0, sizeof(R)*N);
    rp[N-1].im = 0xab;
    printf("main:RC:%d %x\n", REFTRACK_COUNT(rp), (rp[N-1]).im);

}
