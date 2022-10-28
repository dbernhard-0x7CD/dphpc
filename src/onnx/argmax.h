
#ifndef LMQ_ARGMAX_H
#define LMQ_ARGMAX_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of argmax. Calculates the argmax of n elements starting at arr.
 */
int argmax_baseline(const float* arr, const size_t n, int* result);

int argmax_ssr(const float* arr, const size_t n, int* result);

int argmax_ssr_frep(const float* arr, const size_t n, int* result);

#endif
