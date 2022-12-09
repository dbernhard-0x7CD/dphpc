#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"
#include <math.h>

float *x, *y, *result_ref, *result;

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core
    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        if (core_idx == 0){
            // Initialize the input data
            x = allocate(size, sizeof(float));
            y = allocate(size, sizeof(float));
            result_ref = allocate(size, sizeof(float));
            result = allocate(size, sizeof(float));
            cycles_count = allocate(core_num, sizeof(size_t));

            for (unsigned i = 0; i < size; i++) {
                x[i] = (float)i;
                y[i] = (float)i;
            }
            
            BENCH_VO(add_baseline, x, y, size, result_ref);

            BENCH_VO(add_ssr, x, y, size, result);
            verify_vector(result, result_ref, size);
            clear_vector(result, size);

            BENCH_VO(add_ssr_frep, x, y, size, result);
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }
        snrt_global_barrier();


        // ======================= Parallel benchmarks with barriers ===========================
        size_t chunk_size = size / core_num;
        cycles_count[core_idx] = 0;
        BENCH_VO_PARALLEL(add_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();

        cycles_count[core_idx] = 0;
        BENCH_VO_PARALLEL(add_ssr_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();

        cycles_count[core_idx] = 0;
        BENCH_VO_PARALLEL(add_ssr_frep_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector_omp(result, result_ref, size, chunk_size);
            clear_vector(result, size);
        }
        snrt_global_barrier();
    }

    // ======================= Parallel benchmarks with OMP ===========================
    __snrt_omp_bootstrap(core_idx);
    for(size_t size=32;size<=LMQ_SIZE;size*=2){
        size_t chunk_size = size / core_num;

        // Some overhead
        printf("Chunk size: %d\n", chunk_size);

        BENCH_VO(add_omp, x, y, size, result);
        /* This applies to all OMP functions:
        * Due to the (probably unintentional) behaviour of SSR each SSR stream ends with an extra element at position n which is '-inf' Thus we ignore those values when validating.
        */
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO(add_ssr_omp, x, y, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO(add_ssr_frep_omp, x, y, size, result);
        verify_vector_omp(result, result_ref, size, chunk_size);
        clear_vector(result, size);
    }

    __snrt_omp_destroy(core_idx);

    return 0;
}

