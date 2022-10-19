#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "sum.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Running benchmark_sum\n");

    // sum from 1 to 100 (inclusive)
    float x[100];
    for (int i = 0; i < 100; i++) {
        x[i] = 1 + i;
    }
    float result = 0;
    
    size_t start = read_csr(mcycle);
    result = sum_baseline(x, 100);
    size_t end = read_csr(mcycle);

    printf("sum_baseline_O0 took %d cycles and result is %f\n", end - start, result);
 
    start = read_csr(mcycle);
    result = sum_baseline_O3(x, 100);
    end = read_csr(mcycle);

    printf("sum_baseline_O3 took %d cycles and result is %f\n", end - start, result);
    return 0;
}

