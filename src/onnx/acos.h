
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acos. Calculates the acos of n elements starting at arr.
 */
int acos_baseline(double* arr, const size_t n, double* result);
int acos_ssr(double* arr, const size_t n, double* result);
int acos_ssr_frep(double* arr, const size_t n, double* result);

#endif
