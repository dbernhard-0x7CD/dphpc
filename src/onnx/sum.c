#include "printf.h"

#include "lmq.h"
#include "sum.h"

__attribute__((noinline)) 
int sum_baseline(float *arr, const size_t n, float* result) {
    float s = 0;

    for (size_t i = 0; i < n; i++) {
        s += arr[i];
    }

    *result = s;

    return 0;
}

__attribute__((noinline)) 
int sum_ssr(float *arr, const size_t n, float* result) {

    register volatile float ft0 asm("ft0");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    register float s = 0;
    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fadd.s %[s], ft0, %[s] \n"
            : [s] "+f"(s) :: "ft0"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0));

    *result = s;

    return 0;
}

__attribute__((noinline)) 
int sum_ssr_frep(float *arr, const size_t n, float* result) {

    register volatile float ft0 asm("ft0");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    float s;
    asm volatile(
        "addi x5, zero, 0\n"
        "fcvt.s.w %[s], x5\n" // sets s to zero
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fadd.s %[s], ft0, %[s] \n"
        : [s] "+f"(s) : [n_frep] "r"(n - 1) : "ft0"
    );

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0));

    *result = s;

    return 0;
}
