#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_sum\n");

    // sum from 1 to 100 (inclusive)
    float* x = snrt_l1alloc(size * sizeof(float));
    for (size_t i = 0; i < size; i++) {
        x[i] = 1 + i;
    }

    BENCH(sum_baseline, x, size);
    BENCH(sum_ssr, x, size);
    BENCH(sum_ssr_frep, x, size);

    return 0;
}

