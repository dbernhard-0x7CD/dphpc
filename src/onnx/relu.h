#ifndef LMQ_RELU_H
#define LMQ_RELU_H

#include <snrt.h>

int leakyrelu_baseline(float *arr, const size_t n, float alpha, float *result);
int leakyrelu_ssr(float *arr, const size_t n, float alpha, float *result);
int leakyrelu_ssr_frep(float *arr, const size_t n, float alpha, float *result);

#endif
