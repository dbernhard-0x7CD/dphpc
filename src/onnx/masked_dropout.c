
#include <snrt.h>
#include <stdlib.h>

#include "printf.h"
#include <math.h>

/*
 * Naive implementation of masked dropout.
 */
__attribute__((noinline))
int masked_dropout_baseline(const float* arr,  const float* mask, const size_t n, const float ratio, float* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = 1.0 / (1.0 - ratio) * mask[i] * arr[i];
    }

    return 0;
}

__attribute__((noinline))
int masked_dropout_ssr(const float* arr, const float* mask, const size_t n, const float ratio, float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    register volatile float ft2 asm("ft2");
    
    asm volatile("" : "=f"(ft0), "=f"(ft1));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream mask into ft1
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*mask));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, mask);

    // stream from ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();
    register volatile float fa0 = 1.; // Register containing one
    for (size_t i = 0; i < n; i++) {
        asm volatile(
            // "fmul.s ft2, ft0, ft1\n" // ft2 <- mask[i] * arr[i]
            "fsub.s fa1, %[fa0], %[ratio]\n" // fa1 <- 1. - ratio
            "fdiv.s fa1, %[fa0], fa1\n" // fa1 <- 1. / fa1
            "fmul.s fa1, ft0, fa1\n" // fa1 <- arr[i] * fa1
            "fmul.s ft2, ft1, fa1\n" // ft2 <- mask[i] * fa1
            :
            : [ fa0 ] "f"(fa0), [ratio] "f"(ratio)
            : "ft0", "ft1", "ft2", "fa1"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));
    return 0;
}

__attribute__((noinline))
int masked_dropout_ssr_frep(const float* arr, const float* mask, const size_t n, float ratio, float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    register volatile float ft2 asm("ft2");
    
    asm volatile("" : "=f"(ft0), "=f"(ft1));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream mask into ft1
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*mask));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, mask);

    // stream from ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();
    register volatile float fa0 = 1.; // Register containing one
    // TODO: Figure out how we can ue a register (i.e. fa1) to read nd write from when we re doing frep
    asm volatile(
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fsub.s fa1, %[fa0], %[ratio]\n" // fa1 <- 1. - ratio
        "fdiv.s fa1, %[fa0], fa1\n" // fa1 <- 1. / fa1
        "fmul.s fa1, ft0, fa1\n" // fa1 <- arr[i] * fa1
        "fmul.s ft2, ft1, fa1\n" // ft2 <- mask[i] * fa1
        :
        : [n_frep] "r"(n - 1), [ fa0 ] "f"(fa0), [ratio] "f"(ratio)
        : "ft0", "ft1", "ft2", "fa1"
    );

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));
    return 0;
}