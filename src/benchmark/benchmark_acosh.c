#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "acosh.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 0;

    printf("Running benchmark_acosh\n");
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        // x is input; result is output of the optimized functions
        double *x = allocate(size, sizeof(double));
        double *result_ref = allocate(size, sizeof(double));
        double *result  = allocate(size, sizeof(double));

        srandom(2);
        x[0] = 1.0; // acosh(1.0) is 0
        x[1] = 2.0; // acosh(2.0) is 1.317
        for (size_t i = 2; i < size; i++) {
            x[i] = 1.0 + 1.0 * random() / __LONG_MAX__;
        }

        // For debugging purposes
        // for (size_t i = 0; i < size; i++) {
        //     printf("Input at index %d is %f\n", i, x[i]);
        // }

        BENCH_VO(acosh_baseline, x, size, result_ref);
        
        BENCH_VO(acosh_ssr, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}

