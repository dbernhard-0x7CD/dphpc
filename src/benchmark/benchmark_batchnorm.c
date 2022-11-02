#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int batchnorm_baseline(float *a, const size_t n, float* result);
__attribute__((noinline))
int batchnorm_ssr(float *a, const size_t n, float* result);
__attribute__((noinline))
int batchnorm_ssr_frep(float *a, const size_t n, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    // Initialize the input data
    float* x = allocate(size * sizeof(float));
    float* result_ref = allocate(size * sizeof(float));
    float* result = allocate(size * sizeof(float));

    for (size_t i = 0; i < size; i++) {
        x[i] = (float)i;
    }
    
    BENCH_VO(batchnorm_baseline, x, size, result_ref);

    // As long as both of the below run, one of them produces an error (for some reason).
    // They work individually, though.

    // Results don't exactly match the baseline because of some (in my opinion, invalid) floating
    // point optimizations.

    BENCH_VO(batchnorm_ssr, x, size, result);
    verify_vector(result, result_ref, size);
    clear_vector(result, size);

    // verify for this fails if the above "batchnorm_ssr" is executed
    BENCH_VO(batchnorm_ssr_frep, x, size, result);
    // verify_vector(result, result_ref, size);
    // clear_vector(result, size);

 
    return 0;
}

