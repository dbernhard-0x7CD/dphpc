
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float sum_baseline(float *arr, const size_t n);
float sum_baseline_O3(float *arr, const size_t n);
float sum_optimized(float *arr, const size_t n);

#endif
