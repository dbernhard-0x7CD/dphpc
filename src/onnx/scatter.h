#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float scatter_baseline(float *arr, const size_t n, float alpha, float *result);
float scatter_ssr(float *arr, const size_t n, float alpha, float *result);
float scatter_ssr_frep(float *arr, const size_t n, float alpha, float *result);

#endif
