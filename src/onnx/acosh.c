
#include <snrt.h>

#include <math.h>
#include <acosh.h>

/*
 * Naive implementation of acosh. Calculates the acos of n elements starting at arr.
 */
__attribute__((noinline))
int acosh_baseline(double* arr, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = acosh(arr[i]);
    }

    return 0;
}

__attribute__((noinline))
int acosh_ssr(double* arr, const size_t n, double* result) {
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
        volatile register double d;
        asm volatile(
            "fmv.d %[var], ft0\n" // d <- ft0
            : [var]"=f"(d)
            :: "ft0", "memory"
        );

        __builtin_ssr_disable();
        d = acosh(d);
        __builtin_ssr_enable();
        
        asm volatile(
            "fmv.d ft1, %[var]" // ft1 <- d
            :: [var]"f"(d)
            : "ft1", "memory"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int acosh_ssr_frep(double* arr, const size_t n, double* result) {
    (void) arr, (void) n, (void) result;
    /*
     * I do not think we can optimize anything with FREP.
     * As we have a call to another function which consists of many more
     * assembly instructions.
     */
    return 0;
}
