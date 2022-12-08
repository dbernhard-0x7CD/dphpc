
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

int sum_baseline(float *arr, const size_t n, float* result);
int sum_ssr(float *arr, const size_t n, float* result);
int sum_ssr_frep(float *arr, const size_t n, float* result);

int sum_parallel(float *arr, const size_t n, float* result);
int sum_ssr_parallel(float *arr, const size_t n, float* result);
int sum_ssr_frep_parallel(float *arr, const size_t n, float* result);

// int sum_omp_fail(float *arr, const size_t n, float* result);
int sum_omp(float *arr, const size_t n, float* result);
int sum_ssr_omp(float *arr, const size_t n, float* result);
int sum_ssr_frep_omp(float *arr, const size_t n, float* result);

#endif
