#include "printf.h"
#include <snrt.h>

#include "lmq.h"

/*
 * Naive implementation of add. Adds a and b element wise into result.
 */
__attribute__((noinline))
int relu_baseline(float *x,  const size_t n, float* result) {
    for (size_t i = 0; i < n; i++) {
        if(x[i] > 0){
            result[i] = x[i];
        } else {
            result[i] = 0;
        }
    }
    return 0;
}


__attribute__((noinline))
int relu_ssr(float *x, const size_t n, float* result) {

    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*x));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        float val;
        asm volatile(
            "fmv.s %[tmp], ft0 \n"
            : [tmp] "=r"(val) :: "ft0"
        );
        if (val < 0) {
            val = 0;
        }
        asm volatile(
            "fmv.s ft1, %[tmp] \n"
            :: [tmp] "r"(val) : "ft1"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int relu_ssr_frep(float *x, const size_t n, float* result) {

    // register volatile float ft0 asm("ft0");
    // register volatile float ft1 asm("ft1");
    // register volatile float ft2 asm("ft2");
    // asm volatile("" : "=f"(ft0), "=f"(ft1));

    // snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    // snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    // snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    // snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    // snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    // snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    // snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    // snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    // snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    // snrt_ssr_enable();

    // asm volatile(
    //     "frep.o %[n_frep], 1, 0, 0 \n"
    //     "fadd.s ft2, ft0, ft1 \n"
    //     :: [n_frep] "r"(n - 1) : "ft0", "ft1", "ft2"
    // );

    // snrt_ssr_disable();
    // asm volatile("" :: "f"(ft2));

    // return 0;
    relu_baseline(x, n, result);
}