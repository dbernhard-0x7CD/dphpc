
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acosh. Calculates the acosh of n elements starting at arr.
 */
int ainh_baseline(const double* arr, const size_t n, double* result);

int asinh_ssr(const double* arr, const size_t n, double* result);

int asinh_ssr_frep(const double* arr, const size_t n, double* result);

#endif
