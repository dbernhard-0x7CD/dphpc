#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"
#include "benchmark.h"

float *x;
int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1;

    // sum from 1 to size (inclusive)
    float result_ref = -1.0;
    float result = -1.0;

    if (core_idx == 0) {
        printf("Running benchmark_sum\n");

        x = allocate(size, sizeof(float));
        for (size_t i = 0; i < size; i++) {
            x[i] = i;
        }

        BENCH(sum_baseline, x, size, &result_ref);
        printf("Baseline: %f\n", result_ref);

        BENCH(sum_ssr, x, size, &result);
        VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
        result = -1.0;

        BENCH(sum_ssr_frep, x, size, &result);
        VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
        result = -1.0;
    }
    
    /* Benchmark parallel cores */
    snrt_cluster_hw_barrier();

    BENCH_VO_PARALLEL(sum_parallel, x, size, &result);
    if (core_idx == 0) {
        VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
        printf("sum result: %f\n", result);
        result = -1.0;
    }

    BENCH_VO_PARALLEL(sum_ssr_parallel, x, size, &result);
    if (core_idx == 0) {
        VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
        printf("sum_ssr result: %f\n", result);
        result = -1.0;
    }
    
    BENCH_VO_PARALLEL(sum_ssr_frep_parallel, x, size, &result);
    if (core_idx == 0) {
        VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
        printf("sum_ssr_frep result: %f\n", result);

    }

    __snrt_omp_bootstrap(core_idx);

    BENCH_VO_OMP(sum_omp, x, size, &result);
    printf("sum_omp result: %f\n", result);
    VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
    result = -1.0;

    // This is still a WIP (or not possible)
    BENCH_VO_OMP(sum_ssr_omp, x, size, &result);
    printf("sum_ssr_omp result: %f\n", result);
    VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);
    result = -1.0;

    __snrt_omp_destroy(core_idx);

    return 0;
}
