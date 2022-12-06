#include <snrt.h>
#include "printf.h"

// matmul needs a much smaller size, otherwise allocations fail and runs take forever
#ifndef LMQ_SIZE
#define LMQ_SIZE 100
#endif

#include "lmq.h"
#include "benchmark.h"


int gemm_baseline(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result);
int gemm_ssr(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result);
int gemm_ssr_frep(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result);

int print_gemm_pattern(const float* a, size_t m, size_t n, size_t k, float* result, size_t result_len);
int print_other_gemm_pattern(const float* a, size_t m, size_t n, size_t k, float* result, size_t result_len);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    size_t M = size / 2;
    size_t N = size;
    size_t K = size * 2;

    float* x = allocate(M * N, sizeof(float));
    float* y = allocate(N * K, sizeof(float));
    float* result_ref = allocate(M * K, sizeof(float));
    float* result = allocate(M * K, sizeof(float));

    for (size_t i = 0; i < M * N; i++) {
        x[i] = (float)i;
    }

    for (size_t i = 0; i < N * K; i++) {
        y[i] = (float)i;
    }

    BENCH_VO(gemm_baseline, x, y, M, N, K, result_ref);
    
    BENCH_VO(gemm_ssr, x, y, M, N, K, result);
    verify_vector(result, result_ref, M * K);
    clear_vector(result, M * K);

    BENCH_VO(gemm_ssr_frep, x, y, M, N, K, result);
    verify_vector(result, result_ref, M * K);
    clear_vector(result, M * K);
 
    return 0;
}
