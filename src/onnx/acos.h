
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acos. Calculates the acos of n elements starting at arr.
 */
int acos_baseline(float* arr, const size_t n, float* result);
int acos_ssr(float* arr, const size_t n, float* result);
int acos_ssr_frep(float* arr, const size_t n, float* result);

#endif
