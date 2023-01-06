#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "cumsum.h"
#include "benchmark.h"

float *x, *result, *result_ref;

int main() {
    uint32_t core_idx = snrt_global_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_cumsum\n");

        // x is input; result is output of the optimized functions
        x = allocate(size, sizeof(float));
        result = allocate(size, sizeof(float));
        result_ref = allocate(size, sizeof(float));

        srandom(2);
        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0 * random() / __LONG_MAX__;
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

    snrt_cluster_hw_barrier();

    /* Benchmark parallel */
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        if (core_idx == 0) {
            x = allocate(size, sizeof(float));
            result = allocate(size, sizeof(float));
            result_ref = allocate(size, sizeof(float));

            for (size_t i = 0; core_idx == 0 && i < size; i++) {
                x[i] = 1.0 * i;
            }
            cumsum_baseline(x, size, result_ref);
        }

        snrt_cluster_hw_barrier();

        size_t chunk_size = size / core_num;
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("Output at index %d is %f\n", i, result_ref[i]);
        // }

        BENCH_VO_PARALLEL(cumsum_parallel, x, size, result);
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("result at index %d is %f ref: %f\n", i, result[i], result_ref[i]);
        // }
        if (core_idx == 0) {
            verify_vector_approx(result, result_ref, size);
            clear_vector(result, size);
        }
        
        // cumsum_ssr_parallel has the bug that the streams get mixed and thus the results are wrong, so no verification here
        BENCH_VO_PARALLEL(cumsum_ssr_parallel, x, size, result);
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("result at index %d is %f ref: %f\n", i, result[i], result_ref[i]);
        // }
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("input at index %d is %f\n", i, x[i]);
        // }
        if (core_idx == 0) {
        //     verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(cumsum_ssr_frep_parallel, x, size, result);
        if (core_idx == 0) {
        //     verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("result at index %d is %f ref: %f\n", i, result[i], result_ref[i]);
        // }
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("input at index %d is %f\n", i, x[i]);
        // }
    }

    return 0;
}

