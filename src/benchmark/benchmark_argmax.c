#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "argmax.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_argmax\n");

    // x is input; result is output of the optimized functions
    float *x = allocate(size, sizeof(float));
    int result_ref;
    int result;

    srandom(2);
    for (size_t i = 0; i < size; i++) {
        x[i] = 1.0 * random() / __LONG_MAX__;
    }

    // For debugging purposes
    // for (size_t i = 0; i < size; i++) {
    //     printf("Input at index %d is %f\n", i, x[i]);
    // }

    BENCH_VO(argmax_baseline, x, size, &result_ref);
    
    BENCH_VO(argmax_ssr, x, size, &result);
    VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d\n", result_ref, result);
    result = -1;

    // BENCH_VO(argmax_ssr_frep, x, size, &result);
    // VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d\n", result_ref, result);
    // This is expected as no FREP implementation exists (for now)

    return 0;
}

