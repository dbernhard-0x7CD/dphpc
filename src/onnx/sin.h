
#ifndef LMQ_SIN_H
#define LMQ_SIN_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of sin. Computes the element-wise sine and stores it in result.
 */
int sin_baseline(const float* arr, const size_t n, float* result);

int sin_ssr(const float* arr, const size_t n, float* result);

int sin_ssr_frep(const float* arr, const size_t n, float* result);

/*
 * Naive implementation of sin using a lookup table. Looks up the element-wise sine and stores it in result.
 */
int sin_baseline_lookup_table(const float* arr, const size_t n, float* result, const float* lookup_table, const size_t lookup_table_size);

int sin_ssr_lookup_table(const float* arr, const size_t n, float* result, const float* lookup_table, const size_t lookup_table_size);

#endif
