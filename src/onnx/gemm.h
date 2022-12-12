
#ifndef LMQ_GEMM_H
#define LMQ_GEMM_H

#include <snrt.h>

int gemm_baseline(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr_frep(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);

int gemm_parallel(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr_parallel(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr_frep_parallel(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);

int gemm_omp(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr_omp(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);
int gemm_ssr_frep_omp(float* a, float* b, const size_t m, const size_t n, const size_t k, float* __restrict__ result);

#endif
