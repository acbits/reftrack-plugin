#define REFTRACK_TRACE
#include <stdio.h>
#include "hrcmm.h"

struct REFTRACK S { int i; };
typedef struct S S;


REFTRACK_STRUCT(R) { S *sp; };
REFTRACK_EPILOG_WITH_DTOR(R);

typedef struct R R;

NOINLINE R *build_R(S *p);
NOINLINE R *bar(S *p);

