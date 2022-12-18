
#ifndef LMQ_SIN_H
#define LMQ_SIN_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of sin. Computes the element-wise sine and stores it in result.
 */
int sin_baseline(float* arr, const size_t n, float* result);
int sin_ssr(float* arr, const size_t n, float* result);
int sin_ssr_frep(float* arr, const size_t n, float* result);

int sin_parallel(float* arr, const size_t n, float* result);
int sin_ssr_parallel(float* arr, const size_t n, float* result);

/*
 * Naive implementation of sin using a an approximation formula.
 */
int sin_approx_baseline(float* arr, const size_t n, float* result);
int sin_approx_ssr(float* arr, const size_t n, float* result);

int sin_omp(float* arr, const size_t n, float* result);
int sin_ssr_omp(float* arr, const size_t n, float* result);

#endif