
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

int sum_baseline(float *arr, const size_t n, float* result);
int sum_ssr(float *arr, const size_t n, float* result);
int sum_ssr_frep(float *arr, const size_t n, float* result);

#endif
