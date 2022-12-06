#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "sin.h"
#include "benchmark.h"

#ifndef M_E
#   define M_E 2.718281828459045
#endif

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_sin\n");

    for(size_t size=32;size<=LMQ_SIZE;size*=2){


        // x is input; result is output of the optimized functions
        float *ptr = snrt_cluster_memory().start;
        float *x = ptr;
        ptr += size + 1;
        float *result_ref = ptr;
        ptr += size + 1;
        float *result = ptr;

        srandom(42);
        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0 * random() / __LONG_MAX__;
        }

        BENCH_VO(sin_baseline, x, size, result_ref);
        
        BENCH_VO(sin_ssr, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

    }

    return 0;
}

