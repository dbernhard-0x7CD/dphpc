#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"
#include "benchmark.h"

double *x;
int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1;

    // sum from 1 to size (inclusive)
    double result_ref = -1.0;
    double result = -1.0;

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_sum\n");

        x = allocate(size, sizeof(double));
        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0 * random() / __LONG_MAX__;
            // x[i] = i;
        }

        BENCH(sum_baseline, x, size, &result_ref);
        printf("Baseline: %f\n", result_ref);

        BENCH(sum_ssr, x, size, &result);
        VERIFY_INT_APPROX(result, result_ref, "MISMATCH Expected %f but got %f\n", result_ref, result);
        result = -1.0;

        BENCH(sum_ssr_frep, x, size, &result);
        VERIFY_INT_APPROX(result, result_ref, "MISMATCH Expected %f but got %f\n", result_ref, result);
        result = -1.0;
    }

    /* Benchmark parallel cores */
    snrt_cluster_hw_barrier();

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        // calculate reference solution for this size
        sum_baseline(x, size, &result_ref);
        if (core_idx == 0) {
            printf("Baseline result for size %lu: %f\n", size, result_ref);
        }

        BENCH_VO_PARALLEL(sum_parallel, x, size, &result);
        if (core_idx == 0) {
            VERIFY_INT(result, result_ref, "MISMATCH Expected %f but got %f\n", result_ref, result);
            printf("sum_parallel result: %f\n", result);
            result = -1.0;
        }

        BENCH_VO_PARALLEL(sum_ssr_parallel, x, size, &result);
        if (core_idx == 0) {
            VERIFY_INT(result, result_ref, "MISMATCH Expected %f but got %f\n", result_ref, result);
            printf("sum_ssr_parallel result: %f\n", result);
            result = -1.0;
        }
    
        BENCH_VO_PARALLEL(sum_ssr_frep_parallel, x, size, &result);
        if (core_idx == 0) {
            VERIFY_INT(result, result_ref, "MISMATCH Expected %f but got %f\n", result_ref, result);
            printf("sum_ssr_frep_parallel result: %f\n", result);
        }
    }

    __snrt_omp_bootstrap(core_idx);

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        // Not possible with current snitch version. See README.md
    }
    __snrt_omp_destroy(core_idx);

    return 0;
}
