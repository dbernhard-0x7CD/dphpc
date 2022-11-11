#include "printf.h"
#include <snrt.h>

#include "lmq.h"

__attribute__((noinline))
int batchnorm_baseline(float *a, const size_t n, float* result) {
    float sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += a[i];
    }
    float mean = sum / n;

    float square_sum = 0;
    for (size_t i = 0; i < n; i++) {
        square_sum += (a[i] - mean) * (a[i] - mean);
    }
    float variance = square_sum / n;
    float stddev = sqrt_approx(variance);

    // printf("%.10f %.10f %.10f %.10f %.10f\n", sum, mean, square_sum, variance, stddev);

    for (size_t i = 0; i < n; i++) {
        volatile float a_val = a[i];
        volatile float res;
        // necessary to avoid fast-math like float optimizations
        asm volatile(
            "fsub.s ft2, %[a_val], %[mean] \n"
            "fdiv.s %[res], ft2, %[stddev] \n"
            : [res] "=f"(res)
            : [mean] "f"(mean), [stddev] "f"(stddev), [a_val] "f"(a_val)
            : "ft2"
        );
        result[i] = res;
        // result[i] = (a[i] - mean) / stddev;
    }
    
    return 0;
}


__attribute__((noinline))
int batchnorm_ssr(float *a, const size_t n, float* result) {

    volatile float sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_enable();

        for (size_t i = 0; i < n; i++) {
            asm volatile(
                "fadd.s %[s], %[s], ft0 \n"
                : [s] "+f"(sum) 
                :
                : "ft0"
            );
        }

        snrt_ssr_disable();
    }
    volatile float mean = sum / n;
    volatile float square_sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_enable();

        for (size_t i = 0; i < n; i++) {
            asm volatile(
                "fsub.s ft1, ft0, %[mean] \n"
                "fmadd.s %[s], ft1, ft1, %[s] \n"
                : [s] "+f"(square_sum) 
                : [mean] "f"(mean) 
                : "ft0", "ft1"
            );
        }

        snrt_ssr_disable();
    }
    volatile float variance = square_sum / n;
    volatile float stddev = sqrt_approx(variance);
    
    // printf("%.10f %.10f %.10f %.10f %.10f\n", sum, mean, square_sum, variance, stddev);
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

        snrt_ssr_enable();

        for (size_t i = 0; i < n; i++) {
            asm volatile(
                "fsub.s ft2, ft0, %[mean] \n"
                "fdiv.s ft1, ft2, %[stddev] \n"
                :
                : [mean] "f"(mean), [stddev] "f"(stddev)
                : "ft0", "ft1", "ft2"
            );
        }

        snrt_ssr_disable();
    }
    return 0;
}

__attribute__((noinline))
int batchnorm_ssr_frep(float *a, const size_t n, float* result) {
    volatile float sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fadd.s %[s], %[s], ft0 \n"
            : [s] "+f"(sum) 
            : [n_frep] "r"(n - 1)
            : "ft0"
        );

        snrt_ssr_disable();
    }
    volatile float mean = sum / n;
    volatile float square_sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 2, 0, 0 \n"
            "fsub.s ft1, ft0, %[mean] \n"
            "fmadd.s %[s], ft1, ft1, %[s] \n"
            : [s] "+f"(square_sum) 
            : [mean] "f"(mean), [n_frep] "r"(n - 1)
            : "ft0", "ft1"
        );

        snrt_ssr_disable();
    }
    volatile float variance = square_sum / n;
    volatile float stddev = sqrt_approx(variance);
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 2, 0, 0 \n"
            "fsub.s ft2, ft0, %[mean] \n"
            "fdiv.s ft1, ft2, %[stddev] \n"
            :
            : [mean] "f"(mean), [stddev] "f"(stddev), [n_frep] "r"(n - 1)
            : "ft0", "ft1", "ft2"
        );

        snrt_ssr_disable();
    }
    return 0;
}