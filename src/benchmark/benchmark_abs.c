#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "abs.h"

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

    float* x = snrt_l1alloc(size * sizeof(float));
    float* result_ref = snrt_l1alloc(size * sizeof(float));
    float* result = snrt_l1alloc(size * sizeof(float));

    for (int i = 0; i < size; i++) {
        x[i] = (float)i;
    }
    
    size_t start = read_csr(mcycle);
    add_baseline(x, size, result_ref);
    size_t end = read_csr(mcycle);

    printf("abs_baseline took %lu cycles\n", end - start);

    start = read_csr(mcycle);
    add_ssr(x, size, result);
    end = read_csr(mcycle);
    printf("abs_ssr took %lu cycles\n", end - start);

    verify(result, result_ref, size);

    start = read_csr(mcycle);
    add_ssr_frep(x, size, result);
    end = read_csr(mcycle);
    printf("abs_ssr_frep took %lu cycles\n", end - start);

    verify(result, result_ref, size);
 
    return 0;
}

