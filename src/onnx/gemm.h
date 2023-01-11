
#ifndef LMQ_GEMM_H
#define LMQ_GEMM_H

#include <snrt.h>

int gemm_baseline(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr_frep(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);

int gemm_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr_frep_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);

int gemm_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);
int gemm_ssr_frep_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result);

#endif
