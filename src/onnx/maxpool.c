#include "printf.h"
#include <snrt.h>

#include "lmq.h"


__attribute__((noinline))
int maxpool_baseline(float *a, size_t n, size_t filter_size, float* result) {
    for (size_t i = 0; filter_size * i < n; ++i) {
        float max = a[filter_size * i];
        for (int j = 1; j < filter_size; ++j) {
            float val = a[filter_size * i + j];
            if (val > max) {
                max = val;
            }
        }
        result[i] = max;
    }
    return 0;
}


__attribute__((noinline))
int maxpool_ssr(float *a, size_t n, size_t filter_size, float* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; filter_size * i < n; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            :
            :
            : "ft0", "ft2"
        );
        for (int j = 1; j < filter_size; ++j) {
            asm volatile(
                "fmax.s ft2, ft2, ft0 \n"
                :
                :
                : "ft0", "ft2"
            );
        }
        asm volatile(
            "fmv.s ft1, ft2 \n"
            :
            :
            : "ft1", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int maxpool_ssr_frep(float *a, size_t n, size_t filter_size, float* result) {
    if (filter_size == 1) {
        return 0;
    }
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; filter_size * i < n; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmax.s ft2, ft2, ft0 \n"
            "fmv.s ft1, ft2 \n"
            :
            : [n_frep] "r"(filter_size - 2)
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}