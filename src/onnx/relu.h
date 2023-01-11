#ifndef LMQ_RELU_H
#define LMQ_RELU_H

#include <snrt.h>

int leakyrelu_baseline(double *arr, const size_t n, double alpha, double *result);
int leakyrelu_ssr(double *arr, const size_t n, double alpha, double *result);
int leakyrelu_ssr_frep(double *arr, const size_t n, double alpha, double *result);

#endif
