#include "printf.h"
#include <snrt.h>

#include "lmq.h"

size_t conv_output_size(size_t n, size_t filter_size, size_t stride, size_t dilation) {
    size_t effective_filter_size = 1 + (filter_size - 1) * dilation;
    return 1 + (n - effective_filter_size) / stride;
}

__attribute__((noinline))
int conv_baseline(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);
    for (size_t i = 0; i < out_size; ++i) {
        double acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * i + dilation * j] * filter[j];
        }
        result[i] = acc;
    }
    return 0;
}


__attribute__((noinline))
int conv_ssr(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
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
            "fmv.w.x ft4, zero \n"
            "fcvt.d.s ft3, ft4 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
        for (size_t j = 0; j < filter_size; ++j) {
            asm volatile(
                "fmadd.d ft3, ft0, ft1, ft3 \n"
                :
                :
                : "ft0", "ft1", "ft2", "ft3"
            );
        }
        asm volatile(
            "fmv.d ft2, ft3 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv_ssr_frep(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
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
            "fmv.w.x ft4, zero \n"
            "fcvt.d.s ft3, ft4 \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmadd.d ft3, ft0, ft1, ft3 \n"
            "fmv.d ft2, ft3 \n"
            :
            : [n_frep] "r"(filter_size - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv2d_baseline(double *a, double* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, double* result) {
    size_t outn0 = conv_output_size(n0, f0, s0, d0);
    size_t outn1 = conv_output_size(n1, f1, s1, d1);

    for (size_t i = 0; i < outn1; ++i) {
        for (size_t j = 0; j < outn0; ++j) {
            double acc = 0;
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
int conv2d_ssr(double *a, double* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, double* result) {
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
            "fmv.w.x ft4, zero \n"
            "fcvt.d.s ft3, ft4 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
        for (size_t j = 0; j < f0 * f1; ++j) {
            asm volatile(
                "fmadd.d ft3, ft0, ft1, ft3 \n"
                :
                :
                : "ft0", "ft1", "ft2", "ft3"
            );
        }
        asm volatile(
            "fmv.d ft2, ft3 \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv2d_ssr_frep(double *a, double* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, double* result) {
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
            "fmv.w.x ft4, zero \n"
            "fcvt.d.s ft3, ft4 \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmadd.d ft3, ft0, ft1, ft3 \n"
            "fmv.d ft2, ft3 \n"
            :
            : [n_frep] "r"(f0 * f1 - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int conv_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);

    // Parallelize over out_size
    size_t local_n = out_size / core_num;

    if (snrt_is_dm_core()) {
        return 0;
    }

    int do_extra = 0;
    if (core_idx < out_size - local_n * core_num) {
        do_extra = 1;
    }

    for (size_t i = 0; i < local_n; ++i) {
        volatile double acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * (core_idx * local_n + i) + dilation * j] * filter[j];
        }

        result[core_idx * local_n + i] = acc;
    }

    if (do_extra) {
        double acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * (core_num * local_n + core_idx) + dilation * j] * filter[j];
        }

        result[core_idx + core_num * local_n] = acc;
    }

    return 0;
}

int conv_ssr_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);

    // Parallelize over out_size
    size_t local_n = out_size / core_num;

    if (snrt_is_dm_core()) {
        return 0;
    }

    int do_extra = 0;
    if (core_idx < out_size - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, local_n, sizeof(*a) * dilation, sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a + stride * local_n * core_idx);

    snrt_ssr_loop_2d(SNRT_SSR_DM1, filter_size, local_n, sizeof(*a), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_2D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_n * core_idx);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_n; ++i) {
        volatile register double acc = 0.0;

        for (size_t j = 0; j < filter_size; ++j) {
            asm volatile(
                "fmadd.d %[acc], ft0, ft1, %[acc] \n"
                : [acc] "+f" (acc)
                : 
                : "ft0", "ft1", "ft2"
            );
        }
        asm volatile(
            "fmv.d ft2, %[acc] \n"
            :
            : [acc] "f" (acc)
            : "ft0", "ft1", "ft2"
        );

    }

    snrt_ssr_disable();

    if (do_extra) {
        double acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * (core_num * local_n + core_idx) + dilation * j] * filter[j];
        }

        result[core_idx + core_num * local_n] = acc;
    }

    return 0;
}

int conv_ssr_frep_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t out_size = conv_output_size(n, filter_size, stride, dilation);

    // Parallelize over out_size
    size_t local_n = out_size / core_num;

    if (snrt_is_dm_core()) {
        return 0;
    }

    int do_extra = 0;
    if (core_idx < out_size - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_2d(SNRT_SSR_DM0, filter_size, local_n, sizeof(*a) * dilation, sizeof(*a) * stride);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, a + stride * local_n * core_idx);

    snrt_ssr_loop_2d(SNRT_SSR_DM1, filter_size, local_n, sizeof(*a), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_2D, filter);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_n * core_idx);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_n; ++i) {
        volatile register double acc = 0.0;
        asm volatile(
            "frep.o %[n_frep], 1, 0, 0\n"
            "fmadd.d %[acc], ft0, ft1, %[acc]\n"
            "fmv.d ft2, %[acc] \n"
            : [acc] "+f" (acc)
            : [n_frep] "r" (filter_size - 1)
            : "ft0", "ft1", "ft2"
        );
    }

    snrt_ssr_disable();

    if (do_extra) {
        double acc = 0;
        for (size_t j = 0; j < filter_size; ++j) {
            acc += a[stride * (core_num * local_n + core_idx) + dilation * j] * filter[j];
        }

        result[core_idx + core_num * local_n] = acc;
    }

    return 0;
}
