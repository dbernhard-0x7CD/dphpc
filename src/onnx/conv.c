#include "printf.h"
#include <snrt.h>

#include "lmq.h"

size_t conv_output_size(size_t n, size_t filter_size, size_t stride, size_t dilation) {
    size_t effective_filter_size = 1 + (filter_size - 1) * dilation;
    return 1 + (n - effective_filter_size) / stride;
}

__attribute__((noinline))
int conv_baseline(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result) {
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);
    for (size_t i = 0; i < out_size; ++i) {
        float acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * i + dilation * j] * filter[j];
        }
        result[i] = acc;
    }
    return 0;
}


__attribute__((noinline))
int conv_ssr(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result) {
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);

    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, out_size, sizeof(*a) * dilation, sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a);

    snrt_ssr_loop_2d(SNRT_SSR_DM1, filter_size, out_size, sizeof(*a), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_2D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, out_size, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < out_size; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
        for (size_t j = 0; j < filter_size; ++j) {
            asm volatile(
                "fmadd.s ft3, ft0, ft1, ft3 \n"
                :
                :
                : "ft0", "ft1", "ft2", "ft3"
            );
        }
        asm volatile(
            "fmv.s ft2, ft3 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv_ssr_frep(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result) {
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);

    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, out_size, sizeof(*a) * dilation, sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a);

    snrt_ssr_loop_2d(SNRT_SSR_DM1, filter_size, out_size, sizeof(*a), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_2D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, out_size, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < out_size; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmadd.s ft3, ft0, ft1, ft3 \n"
            "fmv.s ft2, ft3 \n"
            :
            : [n_frep] "r"(filter_size - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv2d_baseline(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result) {
    size_t outn0 = conv_output_size(n0, f0, s0, d0);
    size_t outn1 = conv_output_size(n1, f1, s1, d1);

    for (size_t i = 0; i < outn1; ++i) {
        for (size_t j = 0; j < outn0; ++j) {
            float acc = 0;
            for (size_t k = 0; k < f1; ++k) {
                for (size_t l = 0; l < f0; ++l) {
                    acc += a[n0 * (s1 * i + k * d1) + s0 * j + l * d0] * filter[k * f0 + l];
                }
            }
            result[i * outn0 + j] = acc;
        }
    }
    return 0;
}


__attribute__((noinline))
int conv2d_ssr(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result) {
    size_t outn0 = conv_output_size(n0, f0, s0, d0);
    size_t outn1 = conv_output_size(n1, f1, s1, d1);

    snrt_ssr_loop_4d(SNRT_SSR_DM0, f0, f1, outn0, outn1, sizeof(*a) * d0, sizeof(*a) * n0 * d1, sizeof(*a) * s0, sizeof(*a) * s1 * n0);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_4D, a);

    snrt_ssr_loop_4d(SNRT_SSR_DM1, f0, f1, outn0, outn1, sizeof(*a), sizeof(*a) * f0, 0, 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_4D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, outn0 * outn1, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < outn0 * outn1; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
        for (size_t j = 0; j < f0 * f1; ++j) {
            asm volatile(
                "fmadd.s ft3, ft0, ft1, ft3 \n"
                :
                :
                : "ft0", "ft1", "ft2", "ft3"
            );
        }
        asm volatile(
            "fmv.s ft2, ft3 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv2d_ssr_frep(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result) {
    size_t outn0 = conv_output_size(n0, f0, s0, d0);
    size_t outn1 = conv_output_size(n1, f1, s1, d1);

    snrt_ssr_loop_4d(SNRT_SSR_DM0, f0, f1, outn0, outn1, sizeof(*a) * d0, sizeof(*a) * n0 * d1, sizeof(*a) * s0, sizeof(*a) * s1 * n0);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_4D, a);

    snrt_ssr_loop_4d(SNRT_SSR_DM1, f0, f1, outn0, outn1, sizeof(*a), sizeof(*a) * f0, 0, 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_4D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, outn0 * outn1, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < outn0 * outn1; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmadd.s ft3, ft0, ft1, ft3 \n"
            "fmv.s ft2, ft3 \n"
            :
            : [n_frep] "r"(f0 * f1 - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}