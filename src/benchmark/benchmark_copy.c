#include <snrt.h>
#include <printf.h>

#include "lmq.h"
#include "copy.h"
#include "benchmark.h"

float *x, *result, *result_ref;

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    // for(size_t size=32;size<=LMQ_SIZE;size*=2){
    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        if (core_idx == 0) {
            printf("Running benchmark_copy\n");

            x = allocate(size, sizeof(float));
            result_ref = allocate(size, sizeof(float));
            result = allocate(size, sizeof(float));
            // float *x_l1cache = snrt_l1alloc(size * sizeof(float));
            // float *result_l1cache = snrt_l1alloc(size * sizeof(float));

            // Random initialized array
            for (size_t i = 0; i < size; i++) {
                x[i] = i + 1.0;
            //  x_l1cache[i] = i + 1.0;
            }

            BENCH_VO(copy_baseline, x, size, result_ref);

            BENCH_VO(copy_ssr, x, size, result);
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
            // for (size_t i = 0; i < size; i++) {
            //     printf("Result at %d is %f\n", i, result[i]);
            //     result[i] = -1.0;
            // }

            BENCH_VO(copy_ssr_frep, x, size, result);
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
            // for (size_t i = 0; i < size; i++) {
            //     printf("Result at %d is %f\n", i, result[i]);
            //     result[i] = -1.0;
            // }
            
        }
        snrt_global_barrier();
        
        size_t chunk_size = size / core_num;
        // printf("chunk_size: %d\n", chunk_size);

        BENCH_VO_PARALLEL(copy_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();
        
        BENCH_VO_PARALLEL(copy_ssr_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();
        // printf("Core %d exited second.\n", core_idx);

        BENCH_VO_PARALLEL(copy_ssr_frep_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();
    }
    __snrt_omp_bootstrap(core_idx);

    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        size_t chunk_size = size / core_num;


        BENCH_VO(copy_omp, x, size, result);
        /* This applies to all OMP functions:
        * Due to the (probably unintentional) behaviour of SSR each SSR stream ends with an extra element at position n which is '-inf' Thus we ignore those values when validating.
        */
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);
        
        BENCH_VO(copy_ssr_omp, x, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO(copy_ssr_frep_omp, x, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        clear_vector(result, size);
    }

    __snrt_omp_destroy(core_idx);

    return 0;
}
