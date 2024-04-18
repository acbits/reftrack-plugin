#define REFTRACK_DEBUG
#include <string.h>
#include "hrcmm.h"
/*
  REFTRACK_STRUCT macro defines the following declarations

  struct foo;
  void foo_addref(const struct foo *const);
  void foo_removeref(const struct foo *const);
*/

REFTRACK_STRUCT(foo){
    int bar;
};

/*
  REFTRACK_EPILOG_WITH_DTOR macro calls foo_destroy when reference count is zero.
  This is optional, if there is no special cleanup to be done, use REFTRACK_EPILOG. 
*/
REFTRACK_EPILOG_WITH_DTOR(foo);

// This function is called when the reference count for object pointed to by p is zero
void foo_destroy(struct foo *p){
    if (p)
        printf("foo destroyed:%p\n", p);
}

typedef struct foo foo;

// statements commented out are injected by the plugin
     
void baz(foo *p){
    printf("%d\n", p->bar);
    // foo_removeref(p);
}

int main(int argc, char *argv[]){
    foo *p = rc_malloc(sizeof(foo)); // rc_malloc is a default wrapper provided
    // foo_addref(p); 
    p->bar = 123;
    
    // foo_addref(p); 
    foo *q = p;

    // foo_addref(q); 
    baz(q);

    // foo_removeref(p); 
    // foo_removeref(q); 
}
