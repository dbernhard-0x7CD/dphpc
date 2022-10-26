#include "printf.h"
#include <snrt.h>

#include "lmq.h"

__attribute__((noinline))
int scatter_baseline(float *data, const size_t data_len, size_t* indices, float* updates, const size_t index_len, float* result) {
    memcpy(result, data, data_len * sizeof(*data));
    for (size_t i = 0; i < index_len; i++) {
        result[indices[i]] = updates[i];
    }
    return 0;
}


__attribute__((noinline))
int scatter_ssr(float *data, const size_t data_len, size_t* indices, float* updates, const size_t index_len, float* result) {

    register volatile float ft0 asm("ft0");
    register volatile float ft1 asm("ft1");
    asm volatile("" : "=f"(ft0));

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
        "fmv.s ft2, ft0 \n"
        "flt.s t0, ft2, ft3 \n"
        "beqz t0, 1f \n"
        "fmul.s ft2, ft2, %[alpha] \n"
        "1: \n"
        "fmv.s ft1, ft2 \n"
        "addi %[n_rep], %[n_rep], -1 \n"
        "bgtz %[n_rep], 2b \n"
        "3: \n"
        :: [n_rep] "r"(n), [alpha] "f"(alpha) : "ft0", "ft1", "ft2", "ft3", "t0"
    );

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int scatter_ssr_frep(float *data, const size_t data_len, size_t* indices, float* updates, const size_t index_len, float* result) {

    // register volatile float ft0 asm("ft0");
    // register volatile float ft1 asm("ft1");
    // register volatile float ft2 asm("ft2");
    // asm volatile("" : "=f"(ft0), "=f"(ft1));

    // snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    // snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    // snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    // snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    // snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    // snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    // snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    // snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    // snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    // snrt_ssr_enable();

    // asm volatile(
    //     "frep.o %[n_frep], 1, 0, 0 \n"
    //     "fadd.s ft2, ft0, ft1 \n"
    //     :: [n_frep] "r"(n - 1) : "ft0", "ft1", "ft2"
    // );

    // snrt_ssr_disable();
    // asm volatile("" :: "f"(ft2));

    // return 0;
    return scatter_baseline(x, n, alpha, result);
}