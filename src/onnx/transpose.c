
#include <snrt.h>

#include <transpose.h>
#include <float.h>

/*
 * Naive implementation of transpose.
 * arr is in row major format and has dimensions (r, s)
 */
__attribute__((noinline))
int transpose_baseline(const float* arr, const size_t r, const size_t s, float* result) {
    
    for (size_t i = 0; i < r; i++) {
        for (size_t j = 0; j < s; j++) {
            result[j * r + i] = arr[i * s + j];
        }
    }
    
    return 0;
}

__attribute__((noinline))
int transpose_ssr(const float* arr, const size_t r, const size_t s, float* result) {
    // stream arr into ft0

    // arr is in row major form
    snrt_ssr_loop_2d(SNRT_SSR_DM0, r, s * r, sizeof(*arr) * s, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, arr);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, r * s, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < r*s; i++) {
        asm volatile(
            "fmv.s ft1, ft0\n"
            ::: "ft0"
        );
    }

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int transpose_ssr_frep(const float* arr, const size_t r, const size_t s, float* result) {
    // stream arr into ft0

    // arr is in row major form
    snrt_ssr_loop_2d(SNRT_SSR_DM0, r, s * r, sizeof(*arr) * s, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_2D, arr);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, r * s, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    register float temp;

    asm volatile(
        "frep.o %[n_frep], 1, 0, 0\n"
        "fmv.s ft1, ft0\n"
        :: [n_frep] "r"(r*s-1)
        : "ft0"
    );

    snrt_ssr_disable();

    return 0;
}
