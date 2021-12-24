#ifndef _RWLOCK_H
#define _RWLOCK_H

#include "atomic.h"

typedef struct rwlock {
	ATOM_INT write;
	ATOM_INT read;
} rwlock_t;

static inline void
rwlock_init(struct rwlock *lock) {
	ATOM_INIT(&lock->write, 0);
	ATOM_INIT(&lock->read, 0);
}

static inline void
rwlock_rlock(struct rwlock *lock) {
	for (;;) {
		while(ATOM_LOAD(&lock->write)) {}
		ATOM_FINC(&lock->read);
		if (ATOM_LOAD(&lock->write)) {
			ATOM_FDEC(&lock->read);
		} else {
			break;
		}
	}
}

static inline void
rwlock_wlock(struct rwlock *lock) {
	int clear = 0;
	while (!ATOM_CAS(&lock->write,clear,1)) {}
	while(ATOM_LOAD(&lock->read)) {}
}

static inline void
rwlock_wunlock(struct rwlock *lock) {
	ATOM_STORE(&lock->write, 0);
}

static inline void
rwlock_runlock(struct rwlock *lock) {
	ATOM_FDEC(&lock->read);
}

#endif // for #ifndef _RWLOCK_H
