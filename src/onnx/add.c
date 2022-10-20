#include "printf.h"
#include <snrt.h>

#include "lmq.h"

/*
 * Naive implementation of add. Adds a and b element wise into result.
 */
int add_baseline(const float *a, const float* b, const size_t n, float* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = a[i] + b[i];
    }
    return 0;
}


int add_ssr(const float *a, const float* b, const size_t n, float* result) {

    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    register volatile float ft2 asm("ft2");
    asm volatile("" : "=f"(ft0), "=f"(ft1), "=f"(ft2));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fadd.s ft2, ft0, ft1 \n"
            ::: "ft0", "ft1", "ft2"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0), "f"(ft1), "f"(ft2));

    return 0;
}