#ifndef LMQ_SIGMOID_H
#define LMQ_SIGMOID_H

#include <snrt.h>

int sigmoid_baseline(float *arr, const size_t n, float *result);
int sigmoid_ssr(float *arr, const size_t n,float *result);
int sigmoid_ssr_frep(float *arr, const size_t n, float *result);

#endif