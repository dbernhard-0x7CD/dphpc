#ifndef LMQ_SIGMOID_H
#define LMQ_SIGMOID_H

#include <snrt.h>

int sigmoid_baseline(double *arr, const size_t n, double *result);
int sigmoid_ssr(double *arr, const size_t n,double *result);
int sigmoid_ssr_frep(double *arr, const size_t n, double *result);

#endif