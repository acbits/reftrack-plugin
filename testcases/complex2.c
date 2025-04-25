#define REFTRACK_TRACE
#define REFTRACK_DEBUG
#include "hrcmm.h"
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>

#define CLEAR(x) memset(&(x), 0, sizeof(x))

REFTRACK_STRUCT(R){
    int im;
};

REFTRACK_EPILOG_WITH_DTOR(R);
REFTRACK_DEF_CTOR(R);

typedef struct R R;

void R_destroy(struct R *p){
    if (p)
        printf("R_destroy():%p\n", p);
}

REFTRACK_STRUCT(P){
    struct R *pr;
};

REFTRACK_EPILOG_WITH_DTOR(P);
REFTRACK_DEF_CTOR(P);


typedef struct P P;

REFTRACK_DESTRUCTOR_FN void P_destroy(P *p){
    if (p){
        p->pr = NULL;
        printf("P_destroy():%p\n", p);
    }
}

typedef struct {
    R *br;
    P *bp;
} B;

typedef struct {
    B *abv[2];
    B ab;
} A;


R *gpr;

void foo(int flag){
    static B sb;
    static R *spr;

    B b;
    R *arp[10];
    R ar[20];
    R *rau[0];
    R **rap;

    int ia[10];

    CLEAR(sb);
    CLEAR(b);

    if (!flag){
        printf("Clear statics\n");
        spr = NULL;
        return;
    }

    {
        A a;
        memset(&a, 0, sizeof(A));

        a.abv[0] = &b;
        a.abv[1] = &sb;
        spr = R_create();
        gpr = spr;
        a.abv[0]->br = NULL;

        a.abv[1]->br = a.abv[0]->br;
        a.ab.bp = P_create();
        a.ab.bp->pr = spr;
        a.ab.bp->pr->im++;
        printf("BLOCK END\n");
    }

}

__attribute__((destructor)) static void cleanup(){

    printf("cleanup\n");
    foo(0);
    gpr = NULL;
    print_mem_stats();
}

int main(int argc, char *argv[]){
    foo(1);

}
