#include "printf.h"
#include <snrt.h>

#include "lmq.h"

/*
 * Naive implementation of add. Adds a and b element wise into result.
 */
__attribute__((noinline))
int leakyrelu_baseline(double *x,  const size_t n, double alpha, double* result) {
    for (size_t i = 0; i < n; i++) {
        if(x[i] > 0){
            result[i] = x[i];
        } else {
            result[i] = alpha * x[i];
        }
    }
    return 0;
}


__attribute__((noinline))
int leakyrelu_ssr(double *x, const size_t n, double alpha, double* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*x));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "beqz %[n_rep], 3f \n"
        "fmv.w.x ft3, zero \n"
        "2: \n"
        "fmv.d ft2, ft0 \n"
        "flt.d t0, ft2, ft3 \n"
        "beqz t0, 1f \n"
        "fmul.d ft2, ft2, %[alpha] \n"
        "1: \n"
        "fmv.d ft1, ft2 \n"
        "addi %[n_rep], %[n_rep], -1 \n"
        "bgtz %[n_rep], 2b \n"
        "3: \n"
        :: [n_rep] "r"(n), [alpha] "f"(alpha) : "ft0", "ft1", "ft2", "ft3", "t0"
    );

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int leakyrelu_ssr_frep(double *x, const size_t n, double alpha, double* result) {

    // Not possible with frep

    return 0;
}