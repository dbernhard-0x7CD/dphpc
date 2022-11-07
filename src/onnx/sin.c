#include <snrt.h>
#include <math.h>
#include "sin.h"

/*
 * Naive implementation of sin. Computes the element-wise sine and stores it in result.
 */
__attribute__((noinline)) 
int sin_baseline(const float* arr, const size_t n, float* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = sinf(arr[i]);
    }
    return 0;
}

__attribute__((noinline)) 
int sin_ssr(const float* arr, const size_t n, float* result) {

    // Adress pattern configuration
    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1); // load every element only once
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr); // read from arr

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1); // load every element only once
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result); // write to result

    // The SSR extension is disabled by default, as code that 
    // does not benefit from the use of streams must have the
    // full set of registers available (compatibility).

    // Enabling stream semantics
    snrt_ssr_enable();

    // The SSR region itself can contain any sequence of assembly instructions.

    // Note that while the SSR extension allows for many address stepping and
    // data transfer instructions to be removed from the instruction stream,
    // the program must still issue the **exact number** of compute instructions
    // to fully exhaust the pattern in the address generator. This means that 
    // the fundamental loop nest containing the compute instruction must still
    // be present.

    // Computation
    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fmv.s fa0, ft0\n" // fa0 <- ft0
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
            :: [add_one] "i"(sinf)
            : 
            "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", 
            "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
            "ra"
        );

        __builtin_ssr_enable();
        
        asm volatile(
            "fmv.s ft1, fa0" // ft1 <- fa0
            ::: "ft1", "fa0"
        );
    }

    // Disabling stream semantics
    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline)) 
int sin_ssr_frep(const float* arr, const size_t n, float* result) {

    /*
     * I do not think we can optimize anything with FREP.
     * As we have a call to another function which consists of many more
     * assembly instructions.
     */
    sin_ssr(arr, n, result);

    return 0;
}
