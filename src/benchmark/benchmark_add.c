#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"
#include <math.h>

double *x, *y, *result_ref, *result;

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    // benchmark ssr+frep on a single core

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_add\n");

        // Initialize the input data
        x = allocate(size, sizeof(double));
        y = allocate(size, sizeof(double));
        result_ref = allocate(size, sizeof(double));
        result = allocate(size, sizeof(double));

        for (unsigned i = 0; i < size; i++) {
            x[i] = (double)i;
            y[i] = (double)i;
        }
        
        BENCH_VO(add_baseline, x, y, size, result_ref);

        BENCH_VO(add_ssr, x, y, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(add_ssr_frep, x, y, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    snrt_cluster_hw_barrier();
    /* Benchmark parallel */
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        // =========== Parallel benchmarks with barriers ===========
        BENCH_VO_PARALLEL(add_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(add_ssr_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(add_ssr_frep_parallel, x, y, size, result);
        if (core_idx == 0){
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }
    }

    // ======== Parallel benchmarks with OMP =================
    __snrt_omp_bootstrap(core_idx);
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        size_t chunk_size = size / core_num;

        // Some overhead
        printf("Chunk size: %d\n", chunk_size);

        BENCH_VO_OMP(add_omp, x, y, size, result);
        verify_vector(result, result_ref, size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO_OMP(add_ssr_omp, x, y, size, result);
        verify_vector(result, result_ref, size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO_OMP(add_ssr_frep_omp, x, y, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    __snrt_omp_destroy(core_idx);

    return 0;
}

