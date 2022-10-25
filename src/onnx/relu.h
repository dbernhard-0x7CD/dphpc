#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float relu_baseline(float *arr, const size_t n, float *result);
float relu_ssr(float *arr, const size_t n, float *result);
float relu_ssr_frep(float *arr, const size_t n, float *result);

#endif
