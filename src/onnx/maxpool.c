#include "printf.h"
#include <snrt.h>

#include "lmq.h"

size_t pool_output_size(size_t n, size_t filter_size, size_t stride) {
    return 1 + (n - filter_size) / stride;
}

__attribute__((noinline))
int maxpool_baseline(float *a, size_t n, size_t filter_size, size_t stride, float* result) {
    size_t out_size = pool_output_size(n, filter_size, stride);
    for (size_t i = 0; i < out_size; ++i) {
        float max = a[stride * i];
        for (size_t j = 1; j < filter_size; ++j) {
            float val = a[stride * i + j];
            if (val > max) {
                max = val;
            }
        }
        result[i] = max;
    }
    return 0;
}


__attribute__((noinline))
int maxpool_ssr(float *a, size_t n, size_t filter_size, size_t stride, float* result) {
    size_t out_size = pool_output_size(n, filter_size, stride);
    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, out_size, sizeof(*a), sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, out_size, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < out_size; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            :
            :
            : "ft0", "ft2"
        );
        for (size_t j = 1; j < filter_size; ++j) {
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
int maxpool_ssr_frep(float *a, size_t n, size_t filter_size, size_t stride, float* result) {
    size_t out_size = pool_output_size(n, filter_size, stride);
    if (filter_size == 1) {
        return 0;
    }
    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, out_size, sizeof(*a), sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, out_size, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < out_size; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmax.s ft2, ft2, ft0 \n"
            "fmv.s ft1, ft2 \n"
            :
            : [n_frep] "r"(filter_size - 2), [n_outer_frep] "r"(out_size - 1)
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int maxpool2d_baseline(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result) {
    size_t outn0 = pool_output_size(n0, f0, s0);
    size_t outn1 = pool_output_size(n1, f1, s1);

    for (size_t i = 0; i < outn1; ++i) {
        for (size_t j = 0; j < outn0; ++j) {
            float max = a[n0 * s1 * i + s0 * j];
            for (size_t k = 0; k < f1; ++k) {
                for (size_t l = 0; l < f0; ++l) {
                    float val = a[n0 * (s1 * i + k) + s0 * j + l];
                    if (val > max) {
                        max = val;
                    }
                }
            }
            result[i * outn0 + j] = max;
        }
    }
    return 0;
}


__attribute__((noinline))
int maxpool2d_ssr(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result) {
    size_t outn0 = pool_output_size(n0, f0, s0);
    size_t outn1 = pool_output_size(n1, f1, s1);

    snrt_ssr_loop_4d(SNRT_SSR_DM0, f0, f1, outn0, outn1, sizeof(*a), sizeof(*a) * n0, sizeof(*a) * s0, sizeof(*a) * s1 * n0);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_4D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, outn0 * outn1, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < outn0 * outn1; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            :
            :
            : "ft0", "ft2"
        );
        for (size_t k = 1; k < f0 * f1; ++k) {
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
int maxpool2d_ssr_frep(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result) {
    if (f0 * f1 == 1) {
        return 1;
    }

    size_t outn0 = pool_output_size(n0, f0, s0);
    size_t outn1 = pool_output_size(n1, f1, s1);

    snrt_ssr_loop_4d(SNRT_SSR_DM0, f0, f1, outn0, outn1, sizeof(*a), sizeof(*a) * n0, sizeof(*a) * s0, sizeof(*a) * s1 * n0);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_4D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, outn0 * outn1, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < outn0 * outn1; ++i) {
        asm volatile(
            "fmv.s ft2, ft0 \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmax.s ft2, ft2, ft0 \n"
            "fmv.s ft1, ft2 \n"
            :
            : [n_frep] "r"(f0 * f1 - 2)
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}