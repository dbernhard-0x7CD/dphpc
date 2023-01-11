
#ifndef LMQ_ACOS_H
#define LMQ_ACOS_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of acosh. Calculates the acosh of n elements starting at arr.
 */
int acosh_baseline(double* arr, const size_t n, double* result);
int acosh_ssr(double* arr, const size_t n, double* result);
int acosh_ssr_frep(double* arr, const size_t n, double* result);

#endif
