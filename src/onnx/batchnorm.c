#include "printf.h"
#include <snrt.h>

#include "lmq.h"

__attribute__((noinline))
int batchnorm_baseline(double *a, const size_t n, double* result) {
    double sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += a[i];
    }
    double mean = sum / n;

    double square_sum = 0;
    for (size_t i = 0; i < n; i++) {
        square_sum += (a[i] - mean) * (a[i] - mean);
    }
    double variance = square_sum / n;
    double stddev = sqrt_approx(variance);

    // printf("%.10f %.10f %.10f %.10f %.10f\n", sum, mean, square_sum, variance, stddev);

    for (size_t i = 0; i < n; i++) {
        volatile double a_val = a[i];
        volatile double res;
        // necessary to avoid fast-math like double optimizations
        asm volatile(
            "fsub.d ft2, %[a_val], %[mean] \n"
            "fdiv.d %[res], ft2, %[stddev] \n"
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
int batchnorm_ssr(double *a, const size_t n, double* result) {

    volatile double sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);
        
        snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

        snrt_ssr_enable();

        for (size_t i = 0; i < n; i++) {
            asm volatile(
                "fadd.d %[s], %[s], ft0 \n"
                : [s] "+f"(sum) 
                :
                : "ft0"
            );
        }

        snrt_ssr_disable();
    }
    volatile double mean = sum / n;
    volatile double square_sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);
        
        snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

        snrt_ssr_enable();

        for (size_t i = 0; i < n; i++) {
            asm volatile(
                "fsub.d ft1, ft0, %[mean] \n"
                "fmadd.d %[s], ft1, ft1, %[s] \n"
                : [s] "+f"(square_sum) 
                : [mean] "f"(mean) 
                : "ft0", "ft1"
            );
        }

        snrt_ssr_disable();
    }
    volatile double variance = square_sum / n;
    volatile double stddev = sqrt_approx(variance);
    
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
                "fsub.d ft2, ft0, %[mean] \n"
                "fdiv.d ft1, ft2, %[stddev] \n"
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
int batchnorm_ssr_frep(double *a, const size_t n, double* result) {
    volatile double sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);
        
        snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fadd.d %[s], %[s], ft0 \n"
            : [s] "+f"(sum) 
            : [n_frep] "r"(n - 1)
            : "ft0"
        );

        snrt_ssr_disable();
    }
    volatile double mean = sum / n;
    volatile double square_sum = 0;
    {
        snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 2, 0, 0 \n"
            "fsub.d ft1, ft0, %[mean] \n"
            "fmadd.d %[s], ft1, ft1, %[s] \n"
            : [s] "+f"(square_sum) 
            : [mean] "f"(mean), [n_frep] "r"(n - 1)
            : "ft0", "ft1"
        );

        snrt_ssr_disable();
    }
    volatile double variance = square_sum / n;
    volatile double stddev = sqrt_approx(variance);
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
            "fsub.d ft2, ft0, %[mean] \n"
            "fdiv.d ft1, ft2, %[stddev] \n"
            :
            : [mean] "f"(mean), [stddev] "f"(stddev), [n_frep] "r"(n - 1)
            : "ft0", "ft1", "ft2"
        );

        snrt_ssr_disable();
    }
    return 0;
}