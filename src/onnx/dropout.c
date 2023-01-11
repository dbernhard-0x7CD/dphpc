
#include <snrt.h>
#include <stdlib.h>

#include "printf.h"
#include <math.h>

/*
 * Naive implementation of dropout.
 */
__attribute__((noinline))
int dropout_baseline(const double* arr, const size_t n, const double ratio, double* result) {
    for (size_t i = 0; i < n; i++) {
        if (1.0 * rand() / RAND_MAX <= ratio){
            result[i] = 0;
        } else {
            result[i] = 1.0 / (1.0 - ratio) * arr[i];
        }
    }

    return 0;
}

__attribute__((noinline))
int dropout_ssr(const double* arr, const size_t n, const double ratio, double* result) {
    register volatile double ft0 asm("ft0");
    register volatile double ft2 asm("ft2");
    
    asm volatile("" : "=f"(ft0));
   
    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream from ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    /*
     * (dbernhard): I think this computation is dominated by the rand() calls
     * and thus we do not see much speedup.
    */
    register double fa0 = 1.0 / (1. - ratio); // register containing the factor  
    for (size_t i = 0; i < n; i++) {
        snrt_ssr_disable();
        register double r = (double)rand();
        snrt_ssr_enable();

        if (r / (double)RAND_MAX <= ratio) {
            r = 0.0;
        } else {
            r = 1.0;
        }

        asm volatile(
            "fmul.d fa1, ft0, %[fa0]\n" // fa1 <- arr[i] * fa0
            "fmul.d ft2, %[mask], fa1\n" // fa1 <- mask[i] * fa1
            :
            : [fa0] "f"(fa0), [mask] "f" (r)
            : "ft0", "ft1", "ft2", "fa0", "fa1"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));

    return 0;
}

__attribute__((noinline))
int dropout_ssr_frep(const double* arr, const size_t n, double ratio, double* result) {
    register volatile double ft0 asm("ft0");
    register volatile double ft2 asm("ft2");
    
    asm volatile("" : "=f"(ft0));
    
    double* mask = allocate(n, sizeof(double));

    for (size_t i = 0; i < n; i++) {
        int x = (int)(((double) rand() / RAND_MAX) - ratio + 1.0);
        mask[i] = (double)x;
    }
   
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

    /*
     * (dbernhard): I think this computation is dominated by the rand() calls
     * and thus we do not see much speedup.
    */
    register double fa0 = 1.0 / (1. - ratio); // register containing the factor  

    asm volatile(
        "frep.o %[n_frep], 2, 0, 0\n"
        "fmul.d fa1, ft0, %[fa0]\n" // fa1 <- arr[i] * fa0
        "fmul.d ft2, ft1, fa1\n" // fa1 <- mask[i] * fa1
        :
        : [n_frep] "r"(n-1), [fa0] "f"(fa0)
        : "ft0", "ft1", "ft2", "fa0", "fa1"
    );

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));

    return 0;
}
