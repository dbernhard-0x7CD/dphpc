#include <snrt.h>

#include <stddef.h>
/*
 * Naive implementation of transpose.
 * arr is in row major format and has dimensions (r, s)
 */
__attribute__((noinline))
int gemm_baseline(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result) {
    for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < k; ++j) {
            float acc = 0;
            for (size_t l = 0; l < n; ++l) {
                acc += a[i * n + l] * b[l * k + j];
            }
            result[i * k + j] = acc;
        }
    }
    return 0;
}

int print_other_gemm_pattern(const float* b, size_t m, size_t n, size_t k, float* result, size_t result_len) {
    snrt_ssr_loop_3d(SNRT_SSR_DM1, n, m, k, sizeof(*b) * k, sizeof(*b), 0);
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_3D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (int i = 0; i < result_len; ++i) {
        asm volatile(
            "fmv.s ft2, ft1"
            :
            :
            : "ft1", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

int print_gemm_pattern(const float* a, size_t m, size_t n, size_t k, float* result, size_t result_len) {
    snrt_ssr_loop_3d(SNRT_SSR_DM0, n, k, m, sizeof(*a), 0, sizeof(*a) * n);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, m * k, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (int i = 0; i < result_len; ++i) {
        asm volatile(
            "fmv.s ft2, ft0"
            :
            :
            : "ft0", "ft2"
        );
    }

    snrt_ssr_disable();
    return 0;
}

__attribute__((noinline))
int gemm_ssr(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result) {

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
int gemm_ssr_frep(const float* a, const float* b, size_t m, size_t n, size_t k, float* __restrict__ result) {
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
            "fmadd.s ft3, ft0, ft1, ft3 \n"
            "fmv.s ft2, ft3 \n"
            :
            : [n_frep] "r"(n - 1)
            : "ft0", "ft1", "ft2", "ft3"
        );
    }

    snrt_ssr_disable();
    return 0;
}
