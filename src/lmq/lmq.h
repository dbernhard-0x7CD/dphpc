
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

/*
 * Prints a matrix which is in the form [rows x columns] and row major inside arr.
 */
void print_matrix(const float* arr, const size_t rows, const size_t cols);

/*
 * Calculates an approximation of the square root of a.
 * Needed as the fsqrt instruction is not implemented on the snitch. 
 */
float sqrt_approx(float a);

#endif
