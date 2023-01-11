
#ifndef LMQ_CUMSUM_H
#define LMQ_CUMSUM_H

#include <snrt.h>

/*
 * Naive implementation of cumulative sum. Calculates the cumulative sum of n elements starting at arr.
 */
int cumsum_baseline(const double* arr, const size_t n, double* result);
int cumsum_ssr(const double* arr, const size_t n, volatile double* result);
int cumsum_ssr_frep(const double* arr, const size_t n, volatile double* result);

int cumsum_parallel(const double* arr, const size_t n, double* result);
int cumsum_ssr_parallel(const double* arr, const size_t n, volatile double* result);
int cumsum_ssr_frep_parallel(const double* arr, const size_t n, volatile double* result);

#endif
