// SPDX-License-Identifier: Apache-2.0
// GCC reftrack plugin based heap management
/************************************************************
Copyright (C) 2023 Aravind Ceyardass (dev@aravind.cc)
************************************************************/


#ifndef RCMM__
#define RCMM__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdatomic.h>
#include "reftrack.h"

#define REFTRACK_MARKER 0xfacebeef
#define UNUSED __attribute__((unused))

typedef atomic_int refcount_t;

#define REFCOUNT_SET(v, x) atomic_init(&(v), x)
#define REFCOUNT_INC(v) atomic_fetch_add(&(v), 1)
#define REFCOUNT_DEC(v) atomic_fetch_sub(&(v), 1)
#define REFCOUNT_READ(v) atomic_load(&(v))

#define check_add_overflow(...) false


// define this to enable every change in the number of references. Generates extremely verbose output.
#ifdef REFTRACK_TRACE
#define REFTRACK_TRACE_LOG(...) do{__VA_ARGS__;}while(0)
#else
#define REFTRACK_TRACE_LOG(...)
#endif


//
// structure that is prefixed to allocated memory

struct reftrack_ {
#ifdef REFTRACK_DEBUG
	const char *filename;	// base filename of file where allocation happened
	unsigned lineno;	// line number in the corresponding file
    int mark;
#endif

	refcount_t rc;		// reference count
    void (*dtor)(void*); // destructor
};

typedef struct reftrack_ reftrack_t;
typedef void *(*allocator_t)(size_t);


#define REFTRACK_HDR(bodyp) ((reftrack_t *)((void *)(bodyp) - sizeof(reftrack_t)))
#define REFTRACK_BODY(hdrp) ((void *)hdrp + sizeof(reftrack_t))
#define REFTRACK_COUNTER(bodyp) (REFTRACK_HDR(bodyp)->rc)
#define REFTRACK_COUNT(bodyp) REFCOUNT_READ(REFTRACK_COUNTER(bodyp))
#define REFTRACK_DTOR(bodyp) (REFTRACK_HDR(bodyp)->dtor)

#ifdef REFTRACK_DEBUG

#define REFTRACK_DEBUG_LOG(...)                                                \
  do {                                                                         \
    __VA_ARGS__;                                                               \
  } while (0)

static refcount_t reftrack_alloc_count, reftrack_free_count;
UNUSED static void inc_alloc_count() { REFCOUNT_INC(reftrack_alloc_count); }
UNUSED static void inc_free_count() { REFCOUNT_INC(reftrack_free_count); }

static bool mark_found(const void *p, const char *const fname){
    if (!p)
        return false;

    reftrack_t *rtp = REFTRACK_HDR(p);
    if (rtp->mark != REFTRACK_MARKER){
        printf("reftrack: Invalid pointer/use-after-free |0x%p| to |%s|\n", p, fname);
        return false;
    }
    return true;
}

#define debug_info_init(x) do{                   \
        reftrack_t *const p = x;                 \
        p->filename = filename;                  \
        p->lineno = lineno;                      \
        p->mark = REFTRACK_MARKER;               \
    }while(0)

#define REFTRACK_DEBUG_ARGS    , __BASE_FILE__, __LINE__
#define REFTRACK_DEBUG_PARAMS_DECL  ,const char *const filename,const unsigned lineno
#define REFTRACK_DEBUG_PARAMS , filename, lineno

#else

#define REFTRACK_DEBUG_LOG(...)
#define inc_alloc_count()
#define inc_free_count()
#define mark_found(p, fn) true
#define debug_info_init(x)
#define REFTRACK_DEBUG_ARGS
#define REFTRACK_DEBUG_PARAMS_DECL
#define REFTRACK_DEBUG_PARAMS

#endif

REFTRACK_IGNORE MALLOC_LIKE static void *
rc_alloc_helper_(size_t n, allocator_t alloc_fn
                 REFTRACK_DEBUG_PARAMS_DECL)
{

	void *p;

	p = alloc_fn(n+sizeof(reftrack_t));

	if (p) {
        inc_alloc_count();

		reftrack_t *const rtp = (reftrack_t *)p;
		REFCOUNT_SET(rtp->rc, 0);
        p = REFTRACK_BODY(p);
        debug_info_init(rtp);
        rtp->dtor = NULL;
#ifdef REFTRACK_DEBUG
        printf("reftrack: Allocated |0x%p| of size |%lu| bytes at |%s:%u|\n",
                p , n, filename, lineno);
#endif

	}
	return p;
}

UNUSED REFTRACK_IGNORE MALLOC_LIKE static void *
rc_calloc_helper_(size_t n,
                  size_t size,
                  allocator_t alloc_fn
                  REFTRACK_DEBUG_PARAMS_DECL)
{

    size_t total_size = n*size;
    // TODO check for overflow of total_size

    return rc_alloc_helper_(total_size, alloc_fn REFTRACK_DEBUG_PARAMS);
}


UNUSED REFTRACK_HEAP_FN static void *
rc_realloc_helper_(const void *p,
                   size_t new_size
                   REFTRACK_DEBUG_PARAMS_DECL)
{
	void *rv = NULL;

	if (!p) {
		rv = rc_alloc_helper_(new_size, malloc REFTRACK_DEBUG_PARAMS);
		/* we have to increment reference count here due to realloc
		 * behaving like malloc and we are forced to declare realloc as a heap function.
		 */
		if (rv) {
			REFCOUNT_INC(REFTRACK_COUNTER(rv));
		}
	} else if (new_size) {
		void *orig_p = REFTRACK_HDR(p);
        // TODO check for overflow
		size_t total_size=new_size+sizeof(reftrack_t);

        rv = realloc(orig_p, total_size);
        if (rv != orig_p) {
            int count = REFTRACK_COUNT(REFTRACK_BODY(rv));
            if (count > 1)
                printf("reftrack:object |0x%p| moved while |%d| active references exist\n",
                       p, count);
        }

	} else {
/*
 * case: new_size is zero
 * We don't free the object as in original implementation because the object is
 * freed when reference count goes to zero.
 * NO ACTION NEEDED
 */

	}

	return rv ? REFTRACK_BODY(rv) : rv;

}

REFTRACK_IGNORE static void
rc_free_helper_(const void *p, void (*const free_fn)(void *)
                REFTRACK_DEBUG_PARAMS_DECL){

	if(p) {
        if (!mark_found(p, __func__))
            return;

		reftrack_t *rtp = REFTRACK_HDR(p);
        inc_free_count();
		if (REFCOUNT_READ(rtp->rc)) {
			printf(
#ifdef REFTRACK_DEBUG
                       "reftrack: WARNING object |0x%p| allocated at |%s:%u|, freed at |%s:%u| has |%d| reference(s)\n",
                       p, rtp->filename, rtp->lineno,
                       filename, lineno, REFCOUNT_READ(rtp->rc)
#else
                       "reftrack: WARNING object |0x%p| freed has |%u| reference(s)\n",
                       rtp, REFCOUNT_READ(rtp->rc)
#endif
                );
		}

		if (free_fn) {
            rtp->mark = 0; // clear mark
            free_fn(rtp);
        }

	}
}

#define rc_malloc(n)     rc_alloc_helper_(n, malloc REFTRACK_DEBUG_ARGS)
#define rc_calloc(c, n)  rc_calloc_helper_(c, n, malloc REFTRACK_DEBUG_ARGS)
#define rc_realloc(p, n) rc_realloc_helper_(p, n REFTRACK_DEBUG_ARGS)
#define rc_free(p)       rc_free_helper_(p, free REFTRACK_DEBUG_ARGS)


void reftrack_addref_(const void *const p, const char *type_name) {
    if (p){
        if (!mark_found(p, __func__))
            return;
        REFCOUNT_INC(REFTRACK_COUNTER(p));
        REFTRACK_TRACE_LOG(printf("reftrack:%s:|0x%p|:+1\n", type_name, p));
    }

}

#line 1
UNUSED static void *reftrack_alloc(size_t n) { return rc_malloc(n); }
#line 1
UNUSED static void reftrack_free(void *p){ rc_free(p); }
#line 238

UNUSED void reftrack_addref(const void *const p) {
    reftrack_addref_(p, "");
}

UNUSED void reftrack_removeref(const void *const p) {

    const char *const ctx = __func__;

    if (p) {
        if (!mark_found(p, ctx))
            return;

        REFTRACK_TRACE_LOG(printf("reftrack:|0x%p|:-1\n", p));
        reftrack_t *const rtp = REFTRACK_HDR(p);
        /* checking for one as the value before decrement to zero is one */
        if (REFCOUNT_DEC(rtp->rc) == 1){
            REFTRACK_DEBUG_LOG(printf("reftrack: releasing object |0x%p|\n", p));
            void (*dtor)(void *) = REFTRACK_DTOR(p);
            if (dtor) dtor((void*)p);
            rc_free((void*)p);
        }
    }
}

#define REFTRACK_PROLOG(S)                                            \
    struct S;                                                         \
    static void S##_addref(const struct S *const);                    \
    static void S##_removeref(const struct S *const);


#define DECL_ADDREF(S) void S##_addref(const struct S *const p) { reftrack_addref_(p, #S); }

#define DECL_REMOVEREF(S,DTOR)                                          \
    void S##_removeref(const struct S *const p) { \
        if (p) {                                                        \
            if (!mark_found(p, __func__))                               \
                return;                                                 \
            REFTRACK_TRACE_LOG(printf("reftrack:%s:|0x%p|:-1\n", #S, p)); \
            reftrack_t *const rtp = REFTRACK_HDR(p);                    \
            /* checking for one as the value before decrement to zero is one */ \
            if (REFCOUNT_DEC(rtp->rc) == 1){                         \
                REFTRACK_DEBUG_LOG(printf("reftrack: releasing object |0x%p| type |%s|\n", p, #S)); \
                do{ DTOR((struct S*)p); }while(0);                      \
                rc_free((void*)p);                                      \
            }                                                           \
        }                                                               \
    }


/*
 * sample implementation of a constructor for struct with NO flexible arrays.
 */
#define REFTRACK_DECL_CTOR(S)                                           \
    struct S *S##_create() {                                            \
        void *const p = rc_malloc(sizeof(struct S));                    \
        memset(p, 0, sizeof(struct S));                                 \
        return p;                                                       \
    }

#define REFTRACK_STRUCT(S)                      \
    REFTRACK_PROLOG(S);                         \
    struct REFTRACK_CUSTOM(S) S

#define REFTRACK_EPILOG(S)                      \
    REFTRACK_DECL_CTOR(S)                       \
    DECL_ADDREF(S)                              \
    DECL_REMOVEREF(S, REFTRACK_NOP)

#define REFTRACK_EPILOG_WITH_DTOR(S)      \
    REFTRACK_DECL_CTOR(S)                 \
    DECL_ADDREF(S)                        \
    REFTRACK_DESTRUCTOR_FN static void S##_destroy(struct S *const); \
    DECL_REMOVEREF(S, S##_destroy)

UNUSED static void print_mem_stats(){

#ifdef REFTRACK_DEBUG

    printf("#alloc=%u, #free=%u\n", REFCOUNT_READ(reftrack_alloc_count), REFCOUNT_READ(reftrack_free_count));
    fflush(stderr);
    fflush(stdout);
    assert(REFCOUNT_READ(reftrack_alloc_count) == REFCOUNT_READ(reftrack_free_count));
#endif

}

#endif // RCMM__
