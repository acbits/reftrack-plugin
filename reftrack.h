// SPDX-License-Identifier: Apache-2.0
/************************************************************
Copyright (C) 2023-2025 Aravind Ceyardass (dev@aravind.cc)
************************************************************/

#ifndef REFTRACK__
#define REFTRACK__

#define REFTRACK_IGNORE_FLAG 0x1
#define REFTRACK_HEAP_FN_FLAG 0x2
#define REFTRACK_DESTRUCTOR_FN_FLAG 0x4

#define REFTRACK            __attribute__((__reftrack__()))
#define REFTRACK_CUSTOM(S)  __attribute__((__reftrack__(S##_addref, S##_removeref)))
#define REFTRACK_IGNORE     __attribute__((__reftrack__(REFTRACK_IGNORE_FLAG)))
#define REFTRACK_HEAP_FN    __attribute__((__reftrack__(REFTRACK_HEAP_FN_FLAG | REFTRACK_IGNORE_FLAG)))
#define REFTRACK_DESTRUCTOR_FN __attribute__((__reftrack__(REFTRACK_DESTRUCTOR_FN_FLAG)))
#define REFTRACK_NOP(x)

#define MALLOC_LIKE __attribute__((__malloc__))

#endif // REF TRACK__
