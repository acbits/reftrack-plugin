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
typedef struct R R;

void R_destroy(struct R *p){
    if (p)
        printf("R_destroy():%p\n", p);
}

REFTRACK_STRUCT(P){
    struct R *pr;
};

REFTRACK_EPILOG_WITH_DTOR(P);

typedef struct P P;

typedef struct {
    P *pp;
} S;

REFTRACK_DESTRUCTOR_FN void P_destroy(P *p){
    if (p){
        p->pr = NULL;
        printf("P_destroy():%p\n", p);
    }
}


static inline void foo(P *p){
    printf("foo() ENTER\n");
    P *a = p;
    {
        printf("{A} ENTER\n");
        S s;
        CLEAR(s);
        s.pp = a;
        {
            printf("{B} ENTER\n");
            
            P *c = s.pp;
            c->pr = R_create();
            c->pr->im = 0xbeef;
            
            printf("{B} EXIT\n");
        }
        printf("{A} EXIT\n");
    }
    printf("foo() EXIT\n");
}


int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    P *p = P_create();
    
    foo(p);
    
    printf("%x\n", p->pr->im);
}
