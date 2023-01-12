#include <snrt.h>
#include <math.h>
#include <stdlib.h>
#include "omp.h"
#include "sin.h"

#ifndef M_PI
#   define M_PI 3.14159265358979323846
#endif

/*
 * Naive implementation of sin. Computes the element-wise sine and stores it in result.
 */
__attribute__((noinline)) 
int sin_baseline(double* arr, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = sin(arr[i]);
    }
    return 0;
}

__attribute__((noinline)) 
int sin_ssr(double* arr, const size_t n, double* result) {
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
            :: [add_one] "i"(sin)
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

    // Disabling stream semantics
    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline)) 
int sin_ssr_frep(double* arr, const size_t n, double* result) {
    (void) arr, (void) n, (void) result;
    /*
     * We cannot optimize anything with FREP.
     * As we have a call to another function which consists of many more
     * assembly instructions.
     */

    return 0;
}

__attribute__((noinline)) 
int sin_parallel(double* arr, const size_t n, double* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    for (unsigned i = 0; i < local_n; i++) {
        result[core_idx * local_n + i] = sin(arr[core_idx * local_n + i]);
    }

    if (do_extra) {
        result[core_num * local_n + core_idx] = sin(arr[core_num * local_n + core_idx]);
    }

    return 0;
}

__attribute__((noinline)) 
int sin_ssr_parallel(double* arr, const size_t n, double* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(double));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(double));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result + core_idx * local_n);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_n; i++) {
        asm volatile(
            "fmv.d fa0, ft0\n" // fa0 <- ft0
            ::: "fa0", "ft0"
        );

        /*
         * We disable SSR as every read to 'ft0' will fetch the
         * next element from the defined stream. And any called function
         * may use the ft0 register (as it is caller saved)
         */
        snrt_ssr_disable();

        /*
         * As this is a function call we MUST have "ra" in the clobber.
         * Else the compiler does not know that this function needs to 
         * store 'ra' on the stack (or in some caller saved register) as it
         * may get modified in the call.
         * Same for all other caller saved registers below (in the clobber).
        */
        asm volatile(
            "call %[sin]\n"
            :: [sin] "i"(sin)
            : 
            "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", 
            "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
            "ra"
        );

        snrt_ssr_enable();

        asm volatile(
            "fmv.d ft1, fa0" // ft1 <- fa0
            ::: "ft1", "fa0"
        );
    }

    // Disabling stream semantics
    snrt_ssr_disable();

    if (do_extra) {
        result[core_num * local_n + core_idx] = sin(arr[core_num * local_n + core_idx]);
    }

    return 0;
}

/*
 * Naive implementation of sin using a an approximation formula.
 */
__attribute__((noinline)) 
int sin_approx_baseline(double* arr, const size_t n, double* result) {
    const double Q = 0.775;
    const double P = 0.225;
    const double B = 4.0/M_PI;
    const double C = -4.0/(M_PI*M_PI);
    for (size_t i = 0; i < n; i++) {
        double y = (B * arr[i]) + (C * (arr[i] * arr[i]));
        result[i] = (Q * y) + (P * (y * y));
    }
    return 0;
}

__attribute__((noinline)) 
int sin_approx_ssr(double* arr, const size_t n, double* result) {
    // Adress pattern configuration
    register volatile double ft0 asm("ft0"); // input arr
    register volatile double ft1 asm("ft1"); // output result
    
    asm volatile("" : "=f"(ft0));

    // Stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // Stream from ft1 to result
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    volatile size_t i;
    const double Q = 0.775;
    const double P = 0.225;
    const double B = 4.0/M_PI;
    const double C = -4.0/(M_PI*M_PI);

    asm volatile(
        "li %[i], 0\n" // i = 0
        "0: "
        "fmv.d fa0, ft0\n" // fa0 <- arr[i]
        "fmul.d fa1, %[B], fa0\n" // fa1 <- B * arr[i]
        "fmul.d fa0, fa0, fa0\n" // fa0 <- arr[i] * arr[i]
        "fmul.d fa0, %[C], fa0\n" // fa0 <- C * fa0 = C * arr[i] * arr[i]
        "fadd.d fa1, fa1, fa0\n" // fa1 <- fa1 + fa0 = B * arr[i] + C * arr[i] * arr[i]
        "fmul.d fa0, fa1, fa1\n" // fa0 <- fa1 * fa1
        "fmul.d fa0, %[P], fa0\n" // fa0 <- P * fa0 = P * fa1 * fa1
        "fmul.d fa1, %[Q], fa1\n" // fa1 <- Q * fa1
        "fadd.d ft1, fa1, fa0\n" // ft1 <- fa1 + fa0
        "addi %[i], %[i], 1\n" // i <- i+1
        "blt %[i], %[n], 0b\n" // go to 0 if i < n
        : [i] "+r"(i)
        : [n] "r"(n), [Q] "f"(Q), [P] "f"(P), [B] "f"(B), [C] "f"(C)
        : "ft0", "ft1", "fa0", "fa0"
    );

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0));

    return 0;
}

__attribute__((noinline)) 
int sin_omp(double* arr, const size_t n, double* result) {
    #pragma omp parallel for schedule(static) // in the following line it's necessary to use 'signed'
    for (signed i = 0; i < n; i++) {
        result[i] = sin(arr[i]);
    }
    return 0;
}

int sin_ssr_omp(double* arr, const size_t n, double* result) {
    // The last thread is not used in OpenMP.
    // I do not know why.
    unsigned core_num = snrt_cluster_core_num() - 1;

#pragma omp parallel
    {
        unsigned core_idx = snrt_cluster_core_idx();
        size_t local_n = n / core_num;
        int do_extra = 0;

        // Calculate which core does one more to account for the leftovers
        if (core_idx < n - local_n * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n + 1, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result + core_idx * local_n);

        // The SSR extension is disabled by default, as code that 
        // does not benefit from the use of streams must have the
        // full set of registers available (compatibility).

        // Enabling stream semantics
        snrt_ssr_enable();

        // The SSR region itself can contain any sequence of assembly instructions.

        for (size_t i = 0; i < local_n; i++) {
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
                "call %[sin]\n"
                :: [sin] "i"(sin)
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

        // Disabling stream semantics
        snrt_ssr_disable();
        
        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            result[local_n * core_num + core_idx] = sin(arr[local_n * core_num + core_idx]);
        }
    }

    return 0;
}
