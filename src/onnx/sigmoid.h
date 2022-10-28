#ifndef LMQ_SIGMOID_H
#define LMQ_SIGMOID_H

#include <snrt.h>

float sigmoid_baseline(float *arr, const size_t n, float *result);
float sigmoid_ssr(float *arr, const size_t n,float *result);
float sigmoid_ssr_frep(float *arr, const size_t n, float *result);

#endif