#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float fabs_baseline(float *arr, const size_t n, float *result);
float fabs_ssr(float *arr, const size_t n, float *result);
float fabs_ssr_frep(float *arr, const size_t n, float *result);

#endif