
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

/*
 * Naive implementation of sin using a lookup table. Looks up the element-wise sine and stores it in result.
 */
int sin_baseline_lookup_table(float* arr, const size_t n, float* result, float* lookup_table, const size_t lookup_table_size);

int sin_ssr_lookup_table(float* arr, const size_t n, float* result, float* lookup_table, const size_t lookup_table_size);

int sin_omp(float* arr, const size_t n, float* result);

int sin_ssr_omp(const float* arr, const size_t n, float* result);

int sin_ssr_frep_omp(const float* arr, const size_t n, float* result);

#endif