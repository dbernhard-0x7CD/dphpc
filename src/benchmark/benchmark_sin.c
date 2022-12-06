#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "sin.h"
#include "benchmark.h"

#ifndef M_PI
#   define M_PI 3.14159265358979323846
#endif

const size_t lookup_table_size = 10000;

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_sin\n");

    float* x = allocate(size, sizeof(float)); // input
    float* lookup_table = allocate(lookup_table_size, sizeof(float)); // lookup table for sin
    float* result_ref = allocate(size, sizeof(float)); // reference output (ground truth)
    float* result = allocate(size, sizeof(float)); // output of optimized functions

    for (size_t x = 0; x < lookup_table_size; x++) {
        lookup_table[x] = sinf(M_PI/2.0 * x / lookup_table_size);
    }

    srandom(2); // setting seed 2
    x[0] = 0.0; // sin(0.0) is 0.0
    x[1] = M_PI/2.0; // sin(PI/2) is 1.0
    for (size_t i = 2; i < size; i++) {
        x[i] = 1.0 * random() / __LONG_MAX__;
    }

    BENCH_VO(sin_baseline, x, size, result_ref);
    
    BENCH_VO(sin_ssr, x, size, result);
    verify_vector(result, result_ref, size);

    clear_vector(result_ref, size);
    clear_vector(result, size);

    BENCH_VO(sin_baseline_lookup_table, x, size, result, lookup_table, lookup_table_size);

    BENCH_VO(sin_ssr_lookup_table, x, size, result, lookup_table, lookup_table_size);
    for(size_t i = 0; i < size; i++) {
        printf("%f vs. %f\n", x[i]*lookup_table_size / M_PI * 2, result[i]);
    }
    
    verify_vector(result, result_ref, size);
    
    return 0;
}

