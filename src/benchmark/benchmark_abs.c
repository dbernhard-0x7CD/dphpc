#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "abs.h"
#include "benchmark.h"

float *x, *result, *result_ref;

int main() {
    uint32_t core_idx = snrt_global_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    // benchmark ssr+frep on a single core
    if (core_idx == 0) {
        printf("Running benchmark_abs\n");
    }

    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        float* x = allocate(size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        for (int i = 0; i < size; i++) {
            x[i] = (float)i - 20.0;
        }
        BENCH_VO(fabs_baseline, x, size, result_ref);
        
        BENCH_VO(fabs_ssr, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(fabs_ssr_frep, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
        /* Benchmark parallel cores */
        snrt_cluster_hw_barrier();
        size_t chunk_size = size / core_num;
        // printf("chunk_size: %d\n", chunk_size);

        BENCH_VO_PARALLEL(fabs_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_cluster_hw_barrier();
        
        BENCH_VO_PARALLEL(fabs_ssr_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_cluster_hw_barrier();

        BENCH_VO_PARALLEL(fabs_ssr_frep_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_cluster_hw_barrier();
    }

    __snrt_omp_bootstrap(core_idx);

    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        size_t chunk_size = size / core_num;
        /* Benchmark OMP */
        
        BENCH_VO(fabs_omp, x, size, result);
        /* This applies to all OMP functions:
        * Due to the (probably unintentional) behaviour of SSR each SSR stream ends with an extra element at position n which is '-inf' Thus we ignore those values when validating.
        */
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);
        
        BENCH_VO(fabs_ssr_omp, x, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO(fabs_ssr_frep_omp, x, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        clear_vector(result, size);

        __snrt_omp_destroy(core_idx);
    }
    return 0;
}

