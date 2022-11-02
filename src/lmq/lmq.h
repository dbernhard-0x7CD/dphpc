
#ifndef LMQ_H
#define LMQ_H

#include <snrt.h>

/*
 * Defined to satisfy the compiler.
 */
extern int mcycle;

/*
 * Pointer to the next free memory.
 */
extern void* cur_memory;

/*
 * Allocates n * element_size bytes of memory.
 */
void* allocate(const size_t n, const size_t element_size);


#endif
