
#ifndef LMQ_DIV_H
#define LMQ_DIV_H

#include <snrt.h>

float div_baseline(float *x, float *y, const size_t n, float *result);
float div_ssr(float *x, float *y, const size_t n, float *result);
float div_ssr_frep(float *x, float *y, const size_t n, float *result);

#endif
