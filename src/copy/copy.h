
#ifndef LMQ_COPY_H
#define LMQ_COPY_H

#include <snrt.h>

/*
 * Naive implementation of copy. Copies n elements starting at source to target
 */
int copy_baseline(float* source, const size_t n, float* target);

int copy_ssr(float* source, const size_t n, float* target);

int copy_ssr_frep(float* source, const size_t n, float* target);

int copy_parallel(float* source, const size_t n, float* target);

int copy_ssr_parallel(float* source, const size_t n, float* target);

int copy_ssr_frep_parallel(float* source, const size_t n, float* target);

int copy_omp(float* source, const size_t n, float* target);

int copy_ssr_omp(float* source, const size_t n, float* target);

int copy_ssr_frep_omp(float* source, const size_t n, float* target);

#endif
