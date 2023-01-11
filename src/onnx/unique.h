#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>


/*
 * Find the unique elements of the input 'arr'.
 * The output 'result' is an array of the same size, where
 * result[i] may contain the following:
 * - arr[i] if it is unique
 * - -1 if arr[i] is not unique
 * (Note that this specification is slightly modified but does 
 * not change the work while directly allowing parallelization).
 * The other (optional) outputs are omitted.
 */
int unique_baseline(double* arr, const size_t n, double* result);
int unique_ssr(double* arr, const size_t n, double* result);
int unique_frep(double* arr, const size_t n, double* result);
int unique_parallel(double* arr, const size_t n, double* result);

#endif