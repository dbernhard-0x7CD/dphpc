#include <snrt.h>
#include <printf.h>

#include "lmq.h"
#include "copy.h"
#include "benchmark.h"

double *x, *result, *result_ref;

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_copy\n");

        x = allocate(size, sizeof(double));
        result_ref = allocate(size, sizeof(double));
        result = allocate(size, sizeof(double));
        // double *x_l1cache = snrt_l1alloc(size * sizeof(double));
        // double *result_l1cache = snrt_l1alloc(size * sizeof(double));

        // Random initialized array
        for (size_t i = 0; i < size; i++) {
            x[i] = i + 1.0;
        //  x_l1cache[i] = i + 1.0;
        }

        BENCH_VO(copy_baseline, x, size, result_ref);
        
        BENCH_VO(copy_snitch, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

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

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        BENCH_VO_PARALLEL(copy_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }
        
        BENCH_VO_PARALLEL(copy_ssr_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(copy_ssr_frep_parallel, x, size, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }
    }

    // Benchmark OMP
    __snrt_omp_bootstrap(core_idx);

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        BENCH_VO_OMP(copy_omp, x, size, result);
        verify_vector(result, result_ref, size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);
        
        BENCH_VO_OMP(copy_ssr_omp, x, size, result);
        verify_vector(result, result_ref, size);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, size);

        BENCH_VO_OMP(copy_ssr_frep_omp, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    __snrt_omp_destroy(core_idx);

    return 0;
}
