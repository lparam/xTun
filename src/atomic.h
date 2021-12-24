#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <stdatomic.h>

#define ATOM_INT atomic_int
#define ATOM_INIT(ref, v) atomic_init(ref, v)
#define ATOM_LOAD(ptr) atomic_load(ptr)
#define ATOM_STORE(ptr, v) atomic_store(ptr, v)
#define ATOM_CAS(ptr, oval, nval) atomic_compare_exchange_weak(ptr, &(oval), nval)
#define ATOM_FINC(ptr) atomic_fetch_add(ptr, 1)
#define ATOM_FDEC(ptr) atomic_fetch_sub(ptr, 1)

#endif // for #ifndef _ATOMIC_H
