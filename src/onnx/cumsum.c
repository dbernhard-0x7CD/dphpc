
#include <snrt.h>

#include <cumsum.h>
#include <float.h>

/*
 * Naive implementation of cumulative sum. Calculates the cumulative sum of n elements starting at arr.
 */
__attribute__((noinline))
int cumsum_baseline(const float* arr, const size_t n, float* result) {
    float sum = 0.0;

    for (size_t i = 0; i < n; i++) {
        sum += arr[i];

        result[i] = sum;
    }

    return 0;
}

__attribute__((noinline))
int cumsum_ssr(const float* arr, const size_t n, volatile float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    // i need my own loop
    asm volatile(
        "addi a0, zero, 0\n"      // a0 counts
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"     // ft1 stores the cumulative sum. Set it to 0.0
        "1:\n"
            "addi a0, a0, 1\n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- ft0 (streamed arr[i]) + ft1
            "fmv.s ft2, ft1\n"
        "3:"
        "blt a0, %[n], 1b\n"
        :: [n] "r"(n) 
        : "ft0", "ft1", "ft2", "a0", "a1"
    );

    snrt_ssr_disable();

    asm volatile("" :: "f"(ft2));

    return 0;
}

__attribute__((noinline))
int cumsum_ssr_frep(const float* arr, const size_t n, volatile float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"        // ft1 stores the cumulative sum. set it to 0.0
        "frep.o %[n], 2, 0, 0 \n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- fa0 + ft1
            "fmv.s ft2, ft1\n"
        :: [n] "r"(n-1)
        : "ft0", "ft1", "ft2", "a0", "a1"
    );

    snrt_ssr_disable();
    
    asm volatile("" :: "f"(ft2));

    return 0;
}
