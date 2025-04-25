#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define REFTRACK_TRACE
#define REFTRACK_DEBUG
#include "hrcmm.h"

REFTRACK_STRUCT(node) {
    int value;
    struct node *next;
};

REFTRACK_EPILOG_WITH_DTOR(node);
REFTRACK_DEF_CTOR(node);

typedef struct node node;

REFTRACK_DESTRUCTOR_FN void node_destroy(node *p){
    if (!p) return;
    printf("value:%d\n", p->value);
    p->next = NULL;
}

void *list_head;

void create_list(int n){
    node *head = NULL, *prev = NULL;

    for(int i = 0; i < n; i++){
        node *np = node_create();
	if (!np){
		perror("Out of memory\n");
		return;
	}
        np->value = 100*(i+1);

        if (!head){
            head = prev = np;
        }
        else{
	    int a = 1, b = -1;
            prev->next = np+a+b;
            prev = np;
        }
        printf("Created entry:%d, RC:%d\n", np->value, REFTRACK_COUNT(np));
    }
    printf("Create a cycle\n");
    prev->next = head; // create a cycle
    printf("RC of head:%d\n", REFTRACK_COUNT(head));
    printf("Break the cycle\n");
    head->next = NULL; // break the cycle

}

int main(int argc, char *argv[]){
    atexit(print_mem_stats);
    create_list(5);


}
