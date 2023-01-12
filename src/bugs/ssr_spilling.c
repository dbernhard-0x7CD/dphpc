#include "snrt.h"

#include "printf.h"
#include <stdlib.h>
#include <math.h>


int cumsum(double *a, const size_t n, double* result) {
    size_t core_idx = snrt_cluster_core_idx();
    if (core_idx >= 4) return 0;
    
    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    // // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    // calc sum
    volatile register double sum = 0;

    snrt_ssr_enable();
    asm volatile(
        "addi a1, zero, 0\n"
        "fcvt.d.w ft1, a1\n"     // ft1 stores the cumulative sum. Set it to 0.0
        "frep.o %[n], 2, 0, 0 \n"
            "fadd.d ft1, ft0, ft1\n" // ft1 <- ft0 (streamed arr[i]) + ft1
            "fmv.d ft2, ft1\n"       // write out
        :: [n] "r"(n-1) 
        : "ft0", "ft1", "ft2", "a1", "memory"
    );
    snrt_ssr_disable();

    return 0;
}

double* x;
double* y;

int main() {
    size_t core_idx = snrt_cluster_core_idx();
    size_t core_num = snrt_cluster_core_num() - 1;

    if (core_idx == 0) {
        printf("Demonstrating spilling SSR\n");
    }

    /*
     * Core 0 allocates the memory.
     */
    const size_t size = core_num * 10;;
    if (core_idx == 0) {
        x = snrt_global_memory().start;
        y = snrt_global_memory().start + size * sizeof(double);

        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0;
            printf("Value at %d is %lf\n", i, x[i]);
        }
    }
    snrt_cluster_hw_barrier();

    size_t local_n = (int)(size / core_num);
    double* arr_start = x + core_idx * local_n;
    double* result = y + core_idx * local_n;

    cumsum(arr_start, local_n, result);

    snrt_cluster_hw_barrier();
    if (core_idx == 0) {
        for (signed i = 0; i < size; i++) {
            printf("Result at %d is %lf\n", i, y[i]);
        }
    }

    return 0;
}
