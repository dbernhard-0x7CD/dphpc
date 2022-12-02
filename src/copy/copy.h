
#ifndef LMQ_COPY_H
#define LMQ_COPY_H

#include <snrt.h>

/*
 * Naive implementation of copy. Copies n elements starting at source to target
 */
int copy_baseline(const float* source, const size_t n, float* target);

int copy_ssr(const float* source, const size_t n, float* target);

int copy_ssr_frep(const float* source, const size_t n, float* target);

int copy_parallel(const float* source, const size_t n, float* target);

int copy_ssr_parallel(const float* source, const size_t n, float* target);

int copy_ssr_frep_parallel(const float* source, const size_t n, float* target);

#endif
