
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acosh. Calculates the acosh of n elements starting at arr.
 */
int ainh_baseline(const float* arr, const size_t n, float* result);

int asinh_ssr(const float* arr, const size_t n, float* result);

int asinh_ssr_frep(const float* arr, const size_t n, float* result);

#endif
