#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "abs.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    float* x = snrt_l1alloc(size * sizeof(float));
    float* result_ref = snrt_l1alloc(size * sizeof(float));
    float* result = snrt_l1alloc(size * sizeof(float));

    for (int i = 0; i < size; i++) {
        x[i] = (float)i;
    }

    BENCH_VO(fabs_baseline, x, size, result_ref);
    
    BENCH_VO(fabs_ssr, x, size, result);
    verify_vector(result, result_ref, size);
    clear_vector(result, size);

    BENCH_VO(fabs_ssr_frep, x, size, result);
    verify_vector(result, result_ref, size);
    clear_vector(result, size);
 
    return 0;
}
