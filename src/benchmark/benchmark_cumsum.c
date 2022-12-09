#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "cumsum.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_cumsum\n");
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){

        // x is input; result is output of the optimized functions
        volatile float* x = allocate(size, sizeof(float));
        volatile float* result = allocate(size, sizeof(float));
        volatile float* result_ref = allocate(size, sizeof(float));

        srandom(2);
        for (size_t i = 0; i < size; i++) {
            x[i] = (float)i + 1.0;
        }

        // For debugging purposes
        // for (size_t i = 0; i < size; i++) {
        //     printf("Input at index %d is %f\n", i, x[i]);
        // }

        BENCH_VO(cumsum_baseline, x, size, result_ref);
        
        BENCH_VO(cumsum_ssr, x, size, result);
        // for (size_t i = 0; i < size; i++) {
        //     printf("result_ref at index %d is %f\n", i, result_ref[i]);
        // }
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
        
        BENCH_VO(cumsum_ssr_frep, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}

