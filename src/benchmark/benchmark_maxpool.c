#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int maxpool_baseline(float *a, size_t n, size_t filter_size, float* result);
__attribute__((noinline))
int maxpool_ssr(float *a, size_t n, size_t filter_size, float* result);
__attribute__((noinline))
int maxpool_ssr_frep(float *a, size_t n, size_t filter_size, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    size_t filter_size = 5;
    if (size % filter_size != 0) {
        printf("ERROR: filter size %lu does not divide vector size %lu\n", filter_size, size);
        return 1;
    }

    size_t result_size = size / filter_size;

    // Initialize the input data
    float* x = allocate(size, sizeof(float));
    float* result_ref = allocate(result_size, sizeof(float));
    float* result = allocate(result_size, sizeof(float));

    for (size_t i = 0; i < size; i++) {
        x[i] = (float)i;
    }

    
    BENCH_VO(maxpool_baseline, x, size, filter_size, result_ref);


    BENCH_VO(maxpool_ssr, x, size, filter_size, result);
    verify_vector(result, result_ref, result_size);
    clear_vector(result, result_size);

    // verify for this fails if the above "batchnorm_ssr" is executed
    BENCH_VO(maxpool_ssr_frep, x, size, filter_size, result);
    verify_vector(result, result_ref, result_size);
    clear_vector(result, result_size);

 
    return 0;
}

