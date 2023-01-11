
#include <snrt.h>

#include <max.h>
#include <float.h>
#include <math.h>

/*
 * Naive implementation of max. Calculates the argmax of n elements starting at arr.
 */
__attribute__((noinline))
int max_baseline(const double* arr, const size_t n, double* result) {
    double mv = FLT_MIN;

    for (size_t i = 0; i < n; i++) {
        mv = fmaxf(mv, arr[i]);
    }

    *result = mv;

    return 0;
}

__attribute__((noinline))
int max_ssr(const double* arr, const size_t n, double* result) {
    register volatile double ft0 asm("ft0");

    register volatile double max;
    max = FLT_MIN;

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    asm volatile(
        "addi a0, zero, 0\n"                // a0 <- 0; a0 is the index
        "fmv.d ft1, %[m]\n"        // ft1 stores the max
        "1:\n"
            "addi a0, a0, 1\n"
            "fmax.d %[m], %[m], ft0\n"
        "3:"
        "blt a0, %[n], 1b\n"
        "2:\n" // exit
        : [m] "+f" (max)
        : [n] "r"(n)
        : "ft0", "ft1", "ft2", "a0"
    );

    snrt_ssr_disable();

    *result = max;

    return 0;
}

__attribute__((noinline))
int max_ssr_frep(const double* arr, const size_t n, double* result) {
    register volatile double ft0 asm("ft0");

    register volatile double max;
    max = FLT_MIN;

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    asm volatile(
    "frep.o %[n], 1, 0, 0\n"
        "fmax.d %[m], %[m], ft0\n"
    : [m] "+f" (max)
    : [n] "r"(n-1)
    : "ft0", "ft1"
    );

    snrt_ssr_disable();

    *result = max;

    return 0;
}
