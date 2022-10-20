#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"

void verify(float* value, float* reference, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("expected %f, but got %f\n", reference[i], value[i]);
        }
    }
}

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    const int size = 500;

    // sum from 1 to 100 (inclusive)
    // float *ptr = snrt_cluster_memory().start;
    // float *x = ptr;
    // ptr += size + 1;

    // float *y = ptr;
    // ptr += size + 1;

    // float *result = ptr;
    // ptr += size + 1;

    // float *result_ref = ptr;
    // ptr += size + 1;


    float* x = snrt_l1alloc(size * sizeof(float));
    float* y = snrt_l1alloc(size * sizeof(float));
    float* result_ref = snrt_l1alloc(size * sizeof(float));
    float* result = snrt_l1alloc(size * sizeof(float));

    for (int i = 0; i < size; i++) {
        x[i] = (float)i;
        y[i] = (float)i;
    }
    
    size_t start = read_csr(mcycle);
    add_baseline(x, y, size, result_ref);
    size_t end = read_csr(mcycle);

    printf("add_baseline took %lu cycles\n", end - start);

    start = read_csr(mcycle);
    add_ssr(x, y, size, result);
    end = read_csr(mcycle);
    printf("add_ssr took %lu cycles\n", end - start);
    verify(result, result_ref, size);
 
    return 0;
}

