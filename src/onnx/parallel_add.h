
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float parallel_add_baseline(float *x, float *y, const size_t n, float *result);
float parallel_add_ssr(float *x, float *y, const size_t n, float *result);

#endif
