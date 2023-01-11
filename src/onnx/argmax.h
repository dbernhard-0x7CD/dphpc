
#ifndef LMQ_ARGMAX_H
#define LMQ_ARGMAX_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of argmax. Calculates the argmax of n elements starting at arr.
 */
int argmax_baseline(const double* arr, const size_t n, int* result);
int argmax_ssr(const double* arr, const size_t n, int* result);
int argmax_ssr_frep(const double* arr, const size_t n, int* result);

int argmax_parallel(double* arr, const size_t n, int* result);
int argmax_ssr_parallel(double* arr, const size_t n, int* result);

#endif
