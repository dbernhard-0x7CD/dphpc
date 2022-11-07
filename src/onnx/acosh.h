
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acosh. Calculates the acosh of n elements starting at arr.
 */
int acosh_baseline(const float* arr, const size_t n, float* result);

int acosh_ssr(const float* arr, const size_t n, float* result);

int acosh_ssr_frep(const float* arr, const size_t n, float* result);

#endif
