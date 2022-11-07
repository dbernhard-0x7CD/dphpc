#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "dropout.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_dropout\n");

    // x is input; result is output of the optimized functions
    float* x = allocate(size, sizeof(float));
    float* result_ref = allocate(size, sizeof(float));
    float* result = allocate(size, sizeof(float));

    const float ratio = 0.5; // probability of dropout

    srandom(2);
    for (size_t i = 0; i < size; i++) {
        x[i] = 1.0 * random() / __LONG_MAX__;
    }

    // For debugging purposes
    // for (size_t i = 0; i < size; i++) {
    //     printf("Input at index %d is %f\n", i, x[i]);
    // }

    srandom(4);
    BENCH(dropout_baseline, x, size, ratio, result_ref);
    // debugging purposes:
    // for (size_t i = 0; i < size; i++) {
    //     printf("Reference output at index %d is %f\n", i, result_ref[i]);
    // }

    // reset the seed
    srandom(4);
    BENCH(dropout_ssr, x, size, ratio, result);
    verify_vector(result, result_ref, size);
    // for (size_t i = 0; i < size; i++) {
    //     printf("Output at index %d is %f\n", i, result[i]);
    // }
    clear_vector(result, size);

    // reset the seed
    srandom(4);
    BENCH(dropout_ssr_frep, x, size, ratio, result);
    verify_vector(result, result_ref, size);
    clear_vector(result, size);

    return 0;
}

