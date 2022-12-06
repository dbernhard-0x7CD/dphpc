#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "acos.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 0;

    printf("Running benchmark_acos\n");

    // x is input; result is output of the optimized functions
    float *ptr = snrt_cluster_memory().start;
    float *x = ptr;
    ptr += size + 1;
    float *result_ref = ptr;
    ptr += size + 1;
    float *result = ptr;

    srandom(2);
    x[0] = 0.0; // acos(0.0) is 1.57 (PI/2)
    x[1] = 1.0; // acos(1.0) is 0.0
    for (size_t i = 2; i < size; i++) {
        x[i] = 1.0 * random() / __LONG_MAX__;
    }

    // For debugging purposes
    // for (size_t i = 0; i < size; i++) {
    //     printf("Input at index %d is %f\n", i, x[i]);
    // }

    BENCH_VO(acos_baseline, x, size, result_ref);
    
    BENCH_VO(acos_ssr, x, size, result);
    verify_vector(result, result_ref, size);
    clear_vector(result, size);

    return 0;
}

