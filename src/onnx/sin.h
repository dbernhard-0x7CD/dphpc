
#ifndef LMQ_SIN_H
#define LMQ_SIN_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of sin. Computes the element-wise sine and stores it in result.
 */
int sin_baseline(double* arr, const size_t n, double* result);
int sin_ssr(double* arr, const size_t n, double* result);
int sin_ssr_frep(double* arr, const size_t n, double* result);

int sin_parallel(double* arr, const size_t n, double* result);
int sin_ssr_parallel(double* arr, const size_t n, double* result);

/*
 * Naive implementation of sin using a an approximation formula.
 */
int sin_approx_baseline(double* arr, const size_t n, double* result);
int sin_approx_ssr(double* arr, const size_t n, double* result);

int sin_omp(double* arr, const size_t n, double* result);
int sin_ssr_omp(double* arr, const size_t n, double* result);

#endif