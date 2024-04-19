# Introduction

*reftrack* is a GCC plugin for C language that tracks references to
allocated objects though it could be used for other purposes by writing
custom functions.

## Minimum Requirements

- GCC: \>= 12.3 Other GCC versions might work, but testing on 9.3 showed
  that GCC encounters an internal compiler error at -O2 or -O3 on some
  test cases.
- make: \>= 4.2.1

## Installation

Unpack the source package and run `make install` to install the gcc
plugin. You could pass a value for DESTDIR if you need to package it.

## Sanity test

``` bash
$ cd testcases
$ make run
```

All test cases should pass.

## Integration

Add
`-fplugin=/usr/lib64/reftrack.so -I/usr/include/reftrack -fplugin-arg-reftrack-addref=reftrack_addref
    -fplugin-arg-reftrack-removeref=reftrack_removeref` to `CFLAGS`.
These are the minimum arguments required.

## Plugin arguments

TODO

## Usage

First step is to tag the structure that needs to be tracked.

``` c
struct S;
static void S_addref(const struct S *const);
static void S_removeref(const struct S *const);
struct __attribute__((__reftrack__(S_addref, S_removeref))) S {
    int foo;
    char bar;
};
```

The functions `S_addref`, `S_removeref` could be called anything as long
as their signatures are exactly same as in the example above.

It becomes tedious to write these declarations for every structure that
needs to be tracked, hence the macro `REFTRACK_STRUCT` has been provided
which simplifies the declarations to a form as given below.

``` c
REFTRACK_STRUCT(S) {
    int foo;
    char bar;
};
REFTRACK_EPILOG(S)
```

`REFTRACK_EPILOG(S)` is a macro that provides default definitions for
`S_addref()` and `S_removeref()`. If you want call a destructor before
the object is released, use `REFTRACK_EPILOG_WITH_DTOR(S)` macro.

## Transformations

The plugin transforms the original C code wherever it encounters
statements involving pointers to structures that have the *reftrack*
attribute applied to them.

### Assignments

``` c
typedef struct S S;
S *p = ... , *q = ...;
p = q;
```

is transformed into

``` c
typedef struct S S;
S *p = ... , *q = ...;
S_addref(q); 
S_removeref(p); 
p = q;
```

### Function calls

``` c
S *p = ...;

void print_S(S *sp){
    stat1;
    stat2;
}
print_S(p);

```

is transformed into

``` c
S *p = ...;

void print_S(S *sp){
   stat1;
   stat2;
   S_removeref(sp);
}
S_addref(p);
print_S(p);
```

### Return values

``` c
S *p = ...;
S *get_obj(int);

p = get_obj(123);
```

is transformed into

``` c
S *p = ...;
S *get_obj(int);

S_removeref(p);
p = get_obj(123);
S_addref(p);

```

## Garbage Collection

One of the motivation behind the development of this plugin is to
implement garbage collection for the C programming language that is
natively supported by the compiler. The *addref*, *removeref*
instrumentation makes it easier to implement reference counted GC rather
than mark and sweep GC and a sample implementation is provided in
*hrcmm.h*.

The *`rc_malloc()`*, *`rc_calloc()`* are wrappers for the standard
*`malloc()`*, *`calloc()`* functions that prefix a small header to the
object allocation by requesting extra memory for the header. The header
contains the reference count and optionally the filename and line number
where allocation took place. Similarly, *`rc_realloc()`*, *`rc_free()`*
are wrappers for *`realloc()`* and *`free()`*.

Note: There is no need to call *`rc_free()`* directly in almost all
cases.

## Macros

- `REFTRACK_STRUCT(X)` Declares functions `X_addref()`, `X_removeref()`
- `REFTRACK_EPILOG(X)` Defines functions `X_create()`, `X_addref()`, and
  `X_removeref()`
- `REFTRACK_EPILOG_WITH_DTOR(X)` Same as `REFTRACK_EPILOG(X)`, but calls
  `X_destroy()` before calling `free()`. The programmer has to provide a
  definition for `X_destroy()`.
- `REFTRACK_DEBUG` Prints the location of allocation and release of
  memory objects. Uses extra space in the allocated object.
- `REFTRACK_COUNT(p)` Returns the reference count of the given pointer.

## Destructors

Destructors are special functions that get called on an object when
their reference count is zero and is about to be freed. They must have
the signature `REFTRACK_DESTRUCTOR_FN void X_destroy(struct X *const)`

## Heap functions

TODO

## Usage within Linux kernel

TODO The header file requires more testing.

## Limitations

- Array of tracked pointers is currently unsupported. Look at *array2.c*
  example in the `testcases` directory for a way to handle them.
- The plugin is unable to distinguish pointers holding an address to
  object on the stack vs heap. Use of a mark in the header attached to
  the allocated object mitigates it in most cases at the cost of extra
  storage.
