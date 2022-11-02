#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_sum\n");

    // sum from 1 to size (inclusive)
    float *x = allocate(size, sizeof(float));

    for (size_t i = 0; i < size; i++) {
        x[i] = 1 + i;
    }

    float result_ref = -1.0;
    float result = -1.0;

    BENCH(sum_baseline, x, size, &result_ref);

    BENCH(sum_ssr, x, size, &result);
    VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);

    BENCH(sum_ssr_frep, x, size, &result);
    VERIFY_INT(result, result_ref, "Expected %f but got %f\n", result_ref, result);

    return 0;
}

