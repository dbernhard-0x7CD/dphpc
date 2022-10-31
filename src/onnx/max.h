
#ifndef LMQ_MAX_H
#define LMQ_MAX_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of max. Calculates the argmax of n elements starting at arr.
 */
int argmax_baseline(const float* arr, const size_t n, float* result);

int argmax_ssr(const float* arr, const size_t n, float* result);

int argmax_ssr_frep(const float* arr, const size_t n, float* result);

#endif
