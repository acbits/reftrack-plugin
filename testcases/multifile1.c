#define REFTRACK_TRACE
#define REFTRACK_DEBUG

#include "multifile.h"

REFTRACK_DEF_CTOR(R);

void R_destroy(R *p){
    if (p){
        p->sp = NULL;
        printf("R destroyed:%p\n", p);
    }

}

R *build_R(S *p){
    printf("build_R called\n");
    p->i++;
    R *rp = R_create();
    
    /*
     * When rp goes out of scope, object would be deleted as
     * no one else is holding a reference, so a manual addref()
     * is required.
     */
    R_addref(rp);
    rp->sp = p;
    return rp;
}
