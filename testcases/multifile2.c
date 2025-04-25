#define REFTRACK_TRACE
#define REFTRACK_DEBUG

#include "multifile.h"

REFTRACK_DEF_CTOR(S);

R *bar(S *p){
    printf("Calling foo\n");
    R *rv = build_R(p);
    return rv;
}

int main(int argc, char *argv[]){
    S *p = S_create();
    R *tmp = bar(p);
}
