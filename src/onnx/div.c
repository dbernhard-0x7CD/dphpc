#include "printf.h"
#include <snrt.h>

#include "lmq.h"

/*
 * Naive implementation of div. Divides a and b element wise into result.
 */
__attribute__((noinline))
int div_baseline(double *a, double* b, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = a[i] / b[i];
    }
    return 0;
}


__attribute__((noinline))
int div_ssr(double *a, double* b, const size_t n, double* result) {

    register volatile double ft0 asm("ft0");
    register volatile double ft1 asm("ft1");
    register volatile double ft2 asm("ft2");
    asm volatile("" : "=f"(ft0), "=f"(ft1));

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
            "fdiv.d ft2, ft0, ft1 \n"
            ::: "ft0", "ft1", "ft2"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));

    return 0;
}

__attribute__((noinline))
int div_ssr_frep(double *a, double* b, const size_t n, double* result) {
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

    asm volatile(
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fdiv.d ft2, ft0, ft1 \n"
        :: [n_frep] "r"(n - 1) : "ft0", "ft1", "ft2"
    );

    snrt_ssr_disable();

    return 0;
}
