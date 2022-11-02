#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "copy.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_copy\n");
    
    float *x = allocate(size, sizeof(float));
    float *result_ref = allocate(size, sizeof(float));
    float *result = allocate(size, sizeof(float));

    // Random initialized array
    for (size_t i = 0; i < size; i++) {
        x[i] = i + 1.0;
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

    return 0;
}
