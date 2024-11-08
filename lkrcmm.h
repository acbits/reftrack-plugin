// GCC reftrack plugin based heap management for the Linux kernel
// SPDX-License-Identifier: GPL-2.0-only
/************************************************************
Copyright (C) 2022-2023 Aravind Ceyardass (dev@aravind.cc)
************************************************************/


#ifndef LKRCMM__
#define LKRCMM__

#include <linux/compiler.h>
#include <linux/compiler_attributes.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/syslog.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/reftrack.h>

#ifdef REFTRACK_DEBUG
#define REFTRACK_USE_MARK
#endif


#ifdef REFTRACK_TRACE
#define REFTRACK_TRACE_LOG(...) do{__VA_ARGS__}while(0)
#else
#define REFTRACK_TRACE_LOG(...)
#endif

typedef atomic_t reftrack_count_t;

#define REFCOUNT_SET(v, x)     atomic_set(&(v), x)
#define REFCOUNT_INC(v)        atomic_inc(&(v))
#define REFCOUNT_DEC(v)        atomic_dec(&(v))
#define REFCOUNT_DEC_READ(v)   atomic_dec_and_test(&(v))
#define REFCOUNT_READ(v)       atomic_read(&(v))

#define REFTRACK_MARKER 0xfacebeef

// structure that is prefixed to allocated memory

struct reftrack_ {
    reftrack_count_t rc;       // reference count
#ifdef REFTRACK_DEBUG
    const char *filename;      // filename of file where allocation happened
    unsigned lineno;           // line number in the corresponding file
#endif
#ifdef REFTRACK_USE_MARK
    int mark;
#endif
    void (*dtor)(void*);       // destructor
};

typedef struct reftrack_ reftrack_t;

#define REFTRACK_HDR(bodyp) ((reftrack_t *)((void *)(bodyp) - sizeof(reftrack_t)))
#define REFTRACK_BODY(hdrp) ((void*)hdrp + sizeof(reftrack_t))
#define REFTRACK_COUNTER(bodyp) (REFTRACK_HDR(bodyp)->rc)
#define REFTRACK_COUNT(bodyp) REFCOUNT_READ(REFTRACK_COUNTER(bodyp))
#define REFTRACK_DTOR(hdrp) (hdrp->dtor)

#ifdef REFTRACK_USE_MARK

#define REFTRACK_SET_MARK(p, v) do{ (p)->mark = v; } while(0)
#define mark_found(bodyp) (REFTRACK_HDR(bodyp)->mark == REFTRACK_MARKER)

#else

#define REFTRACK_SET_MARK(p, v) /* discard */
#define mark_found(p) true

#endif

#ifdef REFTRACK_DEBUG

#define reftrack_debug_init(x) do{              \
        reftrack_t *const p = x;                \
        p->filename = filename;                 \
        p->lineno = lineno;                     \
    }while(0)


#define REFTRACK_DEBUG_ARGS    ,__BASE_FILE__,__LINE__
#define REFTRACK_DEBUG_PARAMS_DECL  ,const char *const filename,const unsigned lineno
#define REFTRACK_DEBUG_PARAMS ,filename,lineno

#else

#define reftrack_debug_init(x) /* discard */
#define REFTRACK_DEBUG_ARGS
#define REFTRACK_DEBUG_PARAMS_DECL
#define REFTRACK_DEBUG_PARAMS

#endif

static void reftrack_hdr_init(reftrack_t *const rtp){
        REFCOUNT_SET(rtp->rc, 0);
        REFTRACK_SET_MARK(rtp, REFTRACK_MARKER);
        reftrack_debug_init(rtp);
        rtp->dtor = NULL;
}

REFTRACK_IGNORE MALLOC_LIKE static void *
rc_alloc_helper_(size_t n, gfp_t flags, void *(*alloc_fn)(size_t, gfp_t) REFTRACK_DEBUG_PARAMS_DECL)
{

	size_t total_size;
	void *p;

	if (unlikely(check_add_overflow(n, sizeof(reftrack_t), &total_size)))
		return NULL;

	p = alloc_fn(total_size, flags);

	if (p) {
        reftrack_hdr_init(p);
        p = REFTRACK_BODY(p);
	}
	return p;
}

REFTRACK_IGNORE MALLOC_LIKE static void *
rc_kcalloc_(size_t n, size_t size, gfp_t flags REFTRACK_DEBUG_PARAMS_DECL)
{

	size_t total_size;

	if (unlikely(check_mul_overflow(n, size, &total_size)))
		return NULL;
	else
		return rc_alloc_helper_(total_size, flags REFTRACK_DEBUG_PARAMS);
}


REFTRACK_IGNORE MALLOC_LIKE static void *
rc_vmalloc_helper_(unsigned long n, void *(*const alloc_fn)(unsigned long)
                   REFTRACK_DEBUG_PARAMS_DECL)
{

	size_t total_size;
	void *p;

	if (unlikely(check_add_overflow(n, sizeof(reftrack_t), &total_size)))
		return NULL;

	p = alloc_fn(total_size);

	if (p) {
		reftrack_hdr_init(p);
        p = REFTRACK_BODY(p);
	}
	return p;
}

REFTRACK_HEAP_FN static void *
rc_krealloc_(const void *p, size_t new_size, gfp_t flags
             REFTRACK_DEBUG_PARAMS_DECL)
{
	void *rv = NULL;

	if (!p) {
		rv = rc_alloc_helper_(new_size, flags REFTRACK_DEBUG_PARAMS);
		/* we have to increment reference count here due to realloc
		 * behaving like malloc and we are forced to declare krealloc as a heap function.
		 */
		if (rv) {
			REFCOUNT_INC(REFTRACK_COUNTER(rv));

		}
	} else if (new_size) {
		void *orig_p = REFTRACK_HDR(p);
		size_t total_size;

		if (unlikely(check_add_overflow(new_size, sizeof(reftrack_t), &total_size))) {
			pr_err("reftrack:realloc for |0x%p| has incorrect size:|%lu|\n",
                 p, new_size);
		} else {
			rv = krealloc(orig_p, total_size, flags);
			if (rv != orig_p) {
				int count = REFTRACK_COUNT(REFTRACK_BODY(rv));
				if (count > 1)
					pr_warn("reftrack:object |0x%p| moved while |%d| active references exist\n",
                         p, count);
			}
		}
	} else {
/*
 * case: new_size is zero
 * We don't free the object as in original implementation because the object is
 * freed when reference count goes to zero.
 */
        int count = REFTRACK_COUNT(p);
        if (count > 1)
            pr_warn("reftrack:attempt to free object |0x%p| with |%d| active references\n",
                    count-1);
	}

	return rv ? REFTRACK_BODY(rv) : rv;

}

REFTRACK_IGNORE static void
rc_free_helper_(void *p, void (*const free_fn)(const void *)
                REFTRACK_DEBUG_PARAMS_DECL){

	if(p) {
		reftrack_t *rtp = REFTRACK_HDR(p);

		if (REFCOUNT_READ(rtp->rc) != 0) {
			pr_warn(
#ifdef REFTRACK_DEBUG
                       "reftrack: WARNING object |0x%p| allocated at |%s:%u|, freed at |%s:%u| has |%d| reference(s)\n",
                       rtp, rtp->filename, rtp->lineno,
                       filename, lineno, REFCOUNT_READ(rtp->rc)
#else
                       "reftrack: WARNING object |0x%p| has |%u| reference(s)\n",
                       rtp, REFCOUNT_READ(rtp->rc)
#endif
                );
		}

		if (free_fn) {
            REFTRACK_SET_MARK(rtp, 0);
            free_fn(rtp);

        }

	}
}


#define rc_kmalloc(n, f)     rc_alloc_helper_(n, f, kmalloc REFTRACK_DEBUG_ARGS)
#define rc_kcalloc(c, n, f)  rc_kcalloc_(c, n, f REFTRACK_DEBUG_ARGS)
#define rc_kzalloc(n, f)     rc_alloc_helper_(n, (f|__GFP_ZERO), kmalloc REFTRACK_DEBUG_ARGS)
#define rc_vmalloc(n)        rc_vmalloc_helper_(n, vmalloc REFTRACK_DEBUG_ARGS)
#define rc_vzalloc(n)        rc_vmalloc_helper_(n, vzalloc REFTRACK_DEBUG_ARGS)
#define rc_kvmalloc(n, f)    rc_alloc_helper_(n, f, kvmalloc REFTRACK_DEBUG_ARGS)
#define rc_krealloc(p, n, f) rc_krealloc_(p, n, f REFTRACK_DEBUG_ARGS)
#define rc_kfree(x)          rc_free_helper_(x, kfree REFTRACK_DEBUG_ARGS)
#define rc_vfree(x)          rc_free_helper_(x, vfree REFTRACK_DEBUG_ARGS)
#define rc_kvfree(x)         rc_free_helper_(x, kvfree REFTRACK_DEBUG_ARGS)


#define REFTRACK_PROLOG(S)                                            \
    struct S;                                                         \
    static void S##_addref(const struct S *const);                    \
    static void S##_removeref(const struct S *const);                 \
    REFTRACK_IGNORE static void S##_destroy(struct S *const);

#define DECL_ADDREF(S)                                              \
    void S##_addref(const struct S *const p) {                      \
        if (p){                                                     \
            if (!mark_found(p)){                                     \
                pr_warn("reftrack: Invalid pointer/use-after-free |0x%p| to |%s|\n", p, #S); \
                return;                                              \
            }                                                        \
            REFCOUNT_INC(REFTRACK_COUNTER(p));                       \
            REFTRACK_TRACE_LOG(pr_info("%s:|0x%p|:+1\n", #S, p));    \
        }                                                            \
    }

#define DECL_REMOVEREF(S, DTOR)                                        \
    void S##_removeref(const struct S *const p) {                       \
        if (p) {                                                        \
            if (!mark_found(p)) {                                       \
                pr_warn("reftrack: Invalid pointer/use-after-free |0x%p| to |%s|\n", p, #S); \
                return;                                                 \
            }                                                           \
            REFTRACK_TRACE_LOG(pr_info("%s:|0x%p|:-1n", #S, p));        \
            reftrack_t *const rtp = REFTRACK_HDR(p);                    \
                                                                        \
            if (REFCOUNT_DEC_READ(rtp->rc)){                            \
                REFTRACK_TRACE_LOG(pr_info("reftrack:free object:%p: type:%s:\n",p,#S)); \
                do{ DTOR((struct S*)p); }while(0);                      \
                rc_kvfree((void*)p);                                    \
            }                                                           \
        }                                                               \
    }

#define REFTRACK_STRUCT(S)                      \
    REFTRACK_PROLOG(S);                         \
    struct REFTRACK(S) S

#define REFTRACK_EPILOG(S)                      \
    DECL_ADDREF(S)                              \
    DECL_REMOVEREF(S, REFTRACK_NOP)

#define REFTRACK_EPILOG_WITH_DTOR(S)      \
    DECL_ADDREF(S)                        \
    DECL_REMOVEREF(S, S##_destroy)

/*
 * Default implementation of addref & removeref functions.
 */

noinline void reftrack_addref(const void *const p) {
    if (p){
        if (!mark_found(p)){
            pr_warn("reftrack: Invalid pointer/use-after-free |0x%p|\n", p);
            return;
        }

        REFCOUNT_INC(REFTRACK_COUNTER(p));
        REFTRACK_TRACE_LOG(pr_info("reftrack:|0x%p|:+1\n", p));
    }

}

noinline void reftrack_removeref(const void *const p) {

    if (p) {
        if (!mark_found(p)){
            pr_warn("reftrack: Invalid pointer/use-after-free |0x%p|\n", p);
            return;
        }

        REFTRACK_TRACE_LOG(pr_info("reftrack:|0x%p|:-1\n", p));
        reftrack_t *const rtp = REFTRACK_HDR(p);

        /* checking for one as the value before decrement to zero is one */
        if (REFCOUNT_DEC_READ(rtp->rc)){
            REFTRACK_DEBUG_LOG(pr_info("reftrack: releasing object |0x%p|\n", p));
            void (*dtor)(void *) = REFTRACK_DTOR(rtp);
            if (dtor) dtor((void*)p);
            rc_kvfree((void*)p);
        }
    }
}

#ifdef REFTRACK_REPLACE_ALL
#define kmalloc(n, f)  rc_kmalloc(n, f)
#define kcalloc(c, n, f)  rc_kcalloc(c, n, f)
#define kzalloc(n, f)  rc_kzalloc(n, f)
#define vmalloc(n)  rc_vmalloc(n)
#define vzalloc(n)  rc_vzalloc(n)
#define kvmalloc(n, f) rc_kvmalloc(n, f)
#define krealloc(p, n, f) rc_krealloc(p, n, f)
#define kfree(x)    rc_kfree(x)
#define vfree(x)    rc_vfree(x)
#define kvfree(x)   rc_kvfree(x)
#endif

#endif // LKRCMM__
