#include "printf.h"
#include <snrt.h>

#include <math.h>
#include "lmq.h"

/*
 * Naive implementation of abs. Calculates for each element in x its absolute value and stores it in result
 */
__attribute__((noinline))
int fabs_baseline(float *arr,  const size_t n, float* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = fabsf(arr[i]);
    }

    return 0;
}


__attribute__((noinline))
int fabs_ssr(float *arr, const size_t n, float* result) {

    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fabs.s ft1, ft0 \n"
            ::: "ft0", "ft1"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int fabs_ssr_frep(float *x, const size_t n, float* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*x));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "frep.o %[n], 1, 0, 0\n"
        "fabs.s ft1, ft0 \n"
        :: [n]"r"(n - 1)
        : "ft0", "ft1"
    );

    snrt_ssr_disable();

    return 0;
}