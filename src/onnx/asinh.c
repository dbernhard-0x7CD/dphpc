
#include <snrt.h>

#include <math.h>
#include <asinh.h>

/*
 * Naive implementation of asinh. Calculates the acos of n elements starting at arr.
 */
__attribute__((noinline))
int asinh_baseline(const double* arr, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = asinhf(arr[i]);
    }

    return 0;
}

__attribute__((noinline))
int asinh_ssr(const double* arr, const size_t n, double* result) {
    register volatile double ft0 asm("ft0");
    register volatile double ft1 asm("ft1");

    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream from ft1 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fmv.d fa0, ft0\n" // fa0 <- ft0
            ::: "fa0", "ft0"
        );

        __builtin_ssr_disable();

        asm volatile(
            "call %[add_one]\n"
            :: [add_one] "i"(asinhf)
            : 
            "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", 
            "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
            "ra"
        );

        __builtin_ssr_enable();
        
        asm volatile(
            "fmv.d ft1, fa0" // ft1 <- fa0
            ::: "ft1", "fa0"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int asinh_ssr_frep(const double* arr, const size_t n, double* result) {
    // asinh does not benefit from frep
    // fall back to ssr
    asinh_ssr(arr, n, result);
    return 0;
}
