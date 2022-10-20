#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"

#define BENCH(func_name, ...) \
    do { \
        unsigned long start = read_csr(mcycle); \
        float result = func_name(__VA_ARGS__); \
        unsigned long end = read_csr(mcycle); \
        printf(#func_name": %lu cycles, result: %f\n", end - start, result); \
    } while(0);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_sum\n");

    // sum from 1 to 100 (inclusive)
    float x[100];
    for (int i = 0; i < 100; i++) {
        x[i] = 1 + i;
    }

    BENCH(sum_baseline, x, 100);
    BENCH(sum_ssr, x, 100);
    BENCH(sum_ssr_frep, x, 100);

    return 0;
}

