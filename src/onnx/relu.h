#ifndef LMQ_RELU_H
#define LMQ_RELU_H

#include <snrt.h>

float leakyrelu_baseline(float *arr, const size_t n, float alpha, float *result);
float leakyrelu_ssr(float *arr, const size_t n, float alpha, float *result);
float leakyrelu_ssr_frep(float *arr, const size_t n, float alpha, float *result);

#endif
