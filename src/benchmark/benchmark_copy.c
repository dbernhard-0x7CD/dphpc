#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "copy.h"

/*
 * Benchmarks a vector operation which has no single result.
 */
#define BENCH_VO(func_name, ...) \
    do { \
        size_t start = read_csr(mcycle); \
        int rc = func_name(__VA_ARGS__); \
        size_t end = read_csr(mcycle); \
        printf(#func_name": %lu cycles. Return code: %d\n", end - start, rc); \
    } while(0);

void verify(float* value, const float* reference, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("expected %f, but got %f\n", reference[i], value[i]);
        }
    }
}

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_copy\n");
    
    const size_t size = 500;
    volatile float* x = snrt_l1alloc(size * sizeof(float));
    volatile float* result_ref = snrt_l1alloc(size * sizeof(float));
    volatile float* result = snrt_l1alloc(size * sizeof(float));

    // Random initialized array
    srand(core_idx);
    for (size_t i = 0; i < size; i++) {
        x[i] = i + 1.0;
    }

    BENCH_VO(copy_baseline, x, size, result_ref);

    BENCH_VO(copy_ssr, x, size, result);
    verify(result, result_ref, size);
//    for (size_t i = 0; i < size; i++) {
//        printf("Result at %d is %f\n", i, result[i]);
//        result[i] = -1.0;
//    }

    BENCH_VO(copy_ssr_frep, x, size, result);
    verify(result, result_ref, size);
//    for (size_t i = 0; i < size; i++) {
//        printf("Result at %d is %f\n", i, result[i]);
//        result[i] = -1.0;
//    }

    return 0;
}
