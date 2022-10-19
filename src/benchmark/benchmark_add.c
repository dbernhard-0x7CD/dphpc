#include <snrt.h>
#include "printf.h"

#include "lmq.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_add\n");
    const int size = 10;

    // sum from 1 to 100 (inclusive)
    float *ptr = snrt_cluster_memory().start;
    float *x = ptr;
    ptr += size + 1;

    float *y = ptr;
    ptr += size + 1;

    float *result = ptr;
    ptr += size + 1;

    for (int i = 0; i < size; i++) {
        x[i] = (float)i;
        y[i] = (float)i;
    }
    
    size_t start = read_csr(mcycle);
    add_baseline(x, y, size, result);
    size_t end = read_csr(mcycle);

    printf("add_baseline took %d cycles\n", end - start);

    for (int i = 0; i < size; i++) {
        printf("result at index %i is %f\n", i, result[i]);
    }
 
    return 0;
}

