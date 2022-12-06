#ifndef LMQ_ABS_H
#define LMQ_ABS_H

#include <snrt.h>

int fabs_baseline(float *arr, const size_t n, float *result);
int fabs_ssr(float *arr, const size_t n, float *result);
int fabs_ssr_frep(float *arr, const size_t n, float *result);

int fabs_parallel(float *arr, const size_t n, float *result);
int fabs_ssr_parallel(float *arr, const size_t n, float *result);
int fabs_ssr_frep_parallel(float *arr, const size_t n, float *result);

int fabs_omp(float *arr, const size_t n, float *result);
int fabs_ssr_omp(float *arr, const size_t n, float *result);
int fabs_ssr_frep_omp(float *arr, const size_t n, float *result);

#endif
