#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>


/*
 * Find the unique elements of the input array.
 * The output 'result' contains all unique values of the 'arr'.
 * The other (otpional) outputs are ommitted.
 */
int unique_baseline(float* arr, const size_t n, float* result);
int unique_ssr(float* arr, const size_t n, float* result);

#endif