
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

float add_baseline(float *x, float *y, const size_t n, float *result);
float add_ssr(float *x, float *y, const size_t n, float *result);
float add_ssr_frep(float *x, float *y, const size_t n, float *result);

#endif
