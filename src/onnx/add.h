
#ifndef LMQ_ADD_H
#define LMQ_ADD_H

#include <snrt.h>

int add_baseline(float *a, float *b, const size_t n, float *result);
int add_ssr(float *a, float *b, const size_t n, float *result);
int add_ssr_frep(float *a, float *b, const size_t n, float *result);

int add_omp(float *a, float *b, const size_t n, float *result);
int add_ssr_omp(float *a, float *b, const size_t n, float *result);
int add_ssr_frep_omp(float *a, float *b, const size_t n, float *result);

int add_parallel(float *a, float *b, const size_t n, float *result);
int add_ssr_parallel(float *a, float *b, const size_t n, float *result);
int add_ssr_frep_parallel(float *a, float *b, const size_t n, float *result);

#endif
