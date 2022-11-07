
#ifndef LMQ_CUMSUM_H
#define LMQ_CUMSUM_H

#include <snrt.h>

/*
 * Naive implementation of cumulative sum. Calculates the cumulative sum of n elements starting at arr.
 */
int cumsum_baseline(const float* arr, const size_t n, float* result);

int cumsum_ssr(const float* arr, const size_t n, volatile float* result);

int cumsum_ssr_frep(const float* arr, const size_t n, volatile float* result);

#endif
