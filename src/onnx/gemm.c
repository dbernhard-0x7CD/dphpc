#include <snrt.h>

#include <stddef.h>

#include "gemm.h"
#include "printf.h"

/*
 * Naive implementation of gemm.
 * arr is in row major format and has dimensions (m, k)
 */
__attribute__((noinline))
int gemm_baseline(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
    for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < k; ++j) {
            double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[i * n + l] * b[l * k + j];
            }
            result[i * k + j] = acc; // result_{i, j} = acc
        }
    }
    return 0;
}

int print_other_gemm_pattern(const double* b, size_t m, size_t n, size_t k, double* result, size_t result_len) {
    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, m, k, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (int i = 0; i < result_len; ++i) {
        asm volatile(
            "fmv.d ft2, ft1"
            :
            :
            : "ft1", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

int print_gemm_pattern(const double* a, size_t m, size_t n, size_t k, double* result, size_t result_len) {
    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (int i = 0; i < result_len; ++i) {
        asm volatile(
            "fmv.d ft2, ft0"
            :
            :
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int gemm_ssr(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {

    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a);

    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < m * k; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            :
            :
            : "ft0", "ft1", "ft2", "ft3"
        );
        for (size_t j = 0; j < n; ++j) {
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
int gemm_ssr_frep(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a);

    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < m * k; ++i) {
        asm volatile(
            "fmv.w.x ft3, zero \n"
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmadd.d ft3, ft0, ft1, ft3 \n"
            "fmv.d ft2, ft3 \n"
            :
            : [n_frep] "r"(n - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int gemm_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_m = m / core_num;

    int do_extra = 0;
    if (core_idx < m - local_m * core_num) {
        do_extra = 1;
    }

    for (size_t i = core_idx * local_m; i < (core_idx + 1) * local_m; ++i) {
        for (size_t j = 0; j < k; ++j) {
            double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[i * n + l] * b[l * k + j];
            }
            result[i * k + j] = acc;
        }
    }

    if (do_extra) {
        for (size_t j = 0; j < k; ++j) {
            double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[(core_num * local_m + core_idx) * n + l] * b[l * k + j];
            }
            result[(core_num * local_m + core_idx) * k + j] = acc;
        }
    }

    return 0;
}

__attribute__((noinline))
int gemm_ssr_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_m = m / core_num;

    int do_extra = 0;
    if (core_idx < m - local_m * core_num) {
        do_extra = 1;
    }

    // parallelize over m
    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, local_m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a + local_m * core_idx * n);

    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_m * core_idx * k);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_m * k; ++i) {
        register double temp = 0.0;
        for (size_t j = 0; j < n; ++j) {
            asm volatile(
                "fmadd.d %[temp], ft0, ft1, %[temp] \n"
                : [temp] "+f" (temp)
                :
                : "ft0", "ft1"
            );
        }
        // write to result[i, j]
        asm volatile(
            "fmv.d ft2, %[temp] \n"
            :
            : [temp] "f"(temp)
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();

    // This is only overhead in O(#threads)
    if (do_extra) {
        for (size_t j = 0; j < k; ++j) {
            double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[(core_num * local_m + core_idx) * n + l] * b[l * k + j];
            }
            result[(core_num * local_m + core_idx) * k + j] = acc;
        }
    }

    return 0;
}

__attribute__((noinline))
int gemm_ssr_frep_parallel(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_m = m / core_num;

    int do_extra = 0;
    if (core_idx < m - local_m * core_num) {
        do_extra = 1;
    }
    
    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, local_m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a + local_m * core_idx * n);

    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_m * core_idx * k);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_m * k; ++i) {
        volatile register double temp = 0.0;
        asm volatile(
            "frep.o %[n], 1, 0, 0\n"
            "fmadd.d %[temp], ft0, ft1, %[temp] \n"
            "fmv.d ft2, %[temp]"
            : [temp] "+f" (temp)
            : [n] "r"(n-1)
            : "ft0", "ft1", "ft2"
        );
    }

    snrt_ssr_disable();

    // This is only overhead in O(#threads)
    if (do_extra) {
        for (size_t j = 0; j < k; ++j) {
            double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[(core_num * local_m + core_idx) * n + l] * b[l * k + j];
            }
            result[(core_num * local_m + core_idx) * k + j] = acc;
        }
    }

    return 0;
}

int gemm_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
#pragma omp parallel for collapse(1)
    for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < k; ++j) {
            volatile double acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[i * n + l] * b[l * k + j];
            }
            result[i * k + j] = acc; // result_{i, j} = acc
        }
    }

    return 0;
}


int gemm_ssr_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
#pragma omp parallel
    {
        size_t core_num = snrt_cluster_core_num() - 1;
        size_t core_idx = snrt_cluster_core_idx();
        size_t local_m = m / core_num;

        int do_extra = 0;
        if (core_idx < m - local_m * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, local_m, sizeof(*a), 0, sizeof(*a) * n);
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a + local_m * core_idx * n);

        snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_m * k, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_m * core_idx * k);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_m * k; ++i) {
            register double temp = 0.0;
            for (size_t j = 0; j < n; ++j) {
                asm volatile(
                    "fmadd.d %[temp], ft0, ft1, %[temp] \n"
                    : [temp] "+f" (temp)
                    :
                    : "ft0", "ft1"
                );
            }
            // write to result[i, j]
            asm volatile(
                "fmv.d ft2, %[temp] \n"
                :
                : [temp] "f"(temp)
                : "ft0", "ft2"
            );
        }

        snrt_ssr_disable();

        // This is only overhead in O(#threads)
        if (do_extra) {
            for (size_t j = 0; j < k; ++j) {
                double acc = 0;
                for (size_t l = 0; l < n; ++l) {
                    acc += a[(core_num * local_m + core_idx) * n + l] * b[l * k + j];
                }
                result[(core_num * local_m + core_idx) * k + j] = acc;
            }
        }
    }

    return 0;
}

int gemm_ssr_frep_omp(double* a, double* b, const size_t m, const size_t n, const size_t k, double* __restrict__ result) {
#pragma omp parallel
    {
        size_t core_num = snrt_cluster_core_num() - 1;
        size_t core_idx = snrt_cluster_core_idx();
        size_t local_m = m / core_num;

        int do_extra = 0;
        if (core_idx < m - local_m * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, local_m, sizeof(*a), 0, sizeof(*a) * n);
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a + local_m * core_idx * n);

        snrt_ssr_loop_3d(SNRT_SSR_DM1, n, k, m, sizeof(*b) * k, sizeof(*b), 0);
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_m * k, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + local_m * core_idx * k);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_m * k; ++i) {
            volatile register double temp = 0.0;
            asm volatile(
                "frep.o %[n], 1, 0, 0\n"
                "fmadd.d %[temp], ft0, ft1, %[temp] \n"
                "fmv.d ft2, %[temp]"
                : [temp] "+f" (temp)
                : [n] "r"(n-1)
                : "ft0", "ft1", "ft2"
            );
        }

        snrt_ssr_disable();

        // This is only overhead in O(#threads)
        if (do_extra) {
            for (size_t j = 0; j < k; ++j) {
                double acc = 0;
                for (size_t l = 0; l < n; ++l) {
                    acc += a[(core_num * local_m + core_idx) * n + l] * b[l * k + j];
                }
                result[(core_num * local_m + core_idx) * k + j] = acc;
            }
        }

    }

    return 0;
}
