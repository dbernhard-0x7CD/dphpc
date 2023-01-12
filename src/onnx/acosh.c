
#include <snrt.h>

#include <math.h>
#include <acosh.h>

/*
 * Naive implementation of acosh. Calculates the acos of n elements starting at arr.
 */
__attribute__((noinline))
int acosh_baseline(double* arr, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = acoshf(arr[i]);
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
        asm volatile(
            "fmv.d fa0, ft0\n" // fa0 <- ft0
            ::: "fa0", "ft0"
        );

        /*
         * We disable SSR as every read to 'ft0' will fetch the
         * next element from the defined stream. And any called function
         * may use the ft0 register (as it is caller saved)
         */
        __builtin_ssr_disable();

        /*
         * As this is a function call we MUST have "ra" in the clobber.
         * Else the compiler does not know that this function needs to 
         * store 'ra' on the stack (or in some caller saved register) as it
         * may get modified in the call.
         * Same for all other caller saved registers below (in the clobber).
        */
        asm volatile(
            "call %[add_one]\n"
            :: [add_one] "i"(acoshf)
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
int acosh_ssr_frep(double* arr, const size_t n, double* result) {
    (void) arr, (void) n, (void) result;
    /*
     * I do not think we can optimize anything with FREP.
     * As we have a call to another function which consists of many more
     * assembly instructions.
     */
    return 0;
}
