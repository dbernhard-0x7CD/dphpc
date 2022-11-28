
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

int add_baseline(float *a, float *b, const size_t n, float *result);
int add_ssr(float *a, float *b, const size_t n, float *result);
int add_ssr_frep(float *a, float *b, const size_t n, float *result);

int add_baseline_omp(float *a, float *b, const size_t n, float *result);
int add_ssr_omp(float *a, float *b, const size_t n, float *result);
int add_ssr_frep_omp(float *a, float *b, const size_t n, float *result);

#endif
