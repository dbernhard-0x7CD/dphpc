#include "printf.h"
#include <snrt.h>

#include <math.h>
#include "lmq.h"

/*
 * Naive implementation of abs. Calculates for each element in x its absolute value and stores it in result
 */
__attribute__((noinline))
int fabs_baseline(double *arr,  const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = fabs(arr[i]);
    }

    return 0;
}


__attribute__((noinline))
int fabs_ssr(double *arr, const size_t n, double* result) {

    register volatile double ft0 asm("ft0");
    register volatile double ft1 asm("ft1");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fabs.d ft1, ft0 \n"
            ::: "ft0", "ft1"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft1));

    return 0;
}

__attribute__((noinline))
int fabs_ssr_frep(double *x, const size_t n, double* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*x));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "frep.o %[n], 1, 0, 0\n"
        "fabs.d ft1, ft0 \n"
        :: [n]"r"(n - 1)
        : "ft0", "ft1"
    );

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int fabs_parallel(double *arr, const size_t n, double *result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    for (unsigned i = 0; i < local_n; i++) {
        result[core_idx * local_n + i] = fabsf(arr[core_idx * local_n + i]);
    }

    if (do_extra) {
        result[core_num * local_n + core_idx] = fabsf(arr[core_num * local_n + core_idx]);
    }

    return 0;
}

__attribute__((noinline))
int fabs_ssr_parallel(double *arr, const size_t n, double *result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(double));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(double));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result + core_idx * local_n);
    
    snrt_ssr_enable();

    for (size_t i = 0; i < local_n; i++) {
        asm volatile(
            "fabs.d ft1, ft0 \n"
            ::: "ft0", "ft1"
        );
    }

    snrt_ssr_disable();

    if (do_extra) {
        result[core_num * local_n + core_idx] = fabsf(arr[core_num * local_n + core_idx]);
    }

    return 0;
}

__attribute__((noinline))
int fabs_ssr_frep_parallel(double *arr, const size_t n, double *result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(double));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(double));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result + core_idx * local_n);
    
    snrt_ssr_enable();

    asm (
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fabs.d ft1, ft0 \n"
        :: [n_frep] "r"(local_n - 1) : "ft0", "ft2"
    );
    
    snrt_ssr_disable();

    if (do_extra) {
        result[core_num * local_n + core_idx] = fabsf(arr[core_num * local_n + core_idx]);
    }

    return 0;
}

__attribute__((noinline))
int fabs_omp(double *arr, const size_t n, double *result) {
#pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
        result[i] = fabsf(arr[i]);
    }

    return 0;
}

int fabs_ssr_omp(double *arr, const size_t n, double *result) {
    // The last thread is not used in OpenMP.
    // This is probably the DM core.
    unsigned core_num = snrt_cluster_core_num() - 1;

#pragma omp parallel
    {
        unsigned core_idx = snrt_cluster_core_idx();
        size_t local_n = n / core_num;
        int do_extra = 0;

        // Calculate which core does one more to account for the leftovers
        if (core_idx < n - local_n * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_n; i++) {
            asm volatile(
                "fabs.d ft2, ft0 \n"
                ::: "ft0", "ft2"
            );
        }
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            result[local_n * core_num + core_idx] = fabsf(arr[local_n * core_num + core_idx]);
        }
    }

    return 0;
}

int fabs_ssr_frep_omp(double *arr, const size_t n, double *result) {
    // The last thread is not used in OpenMP.
    // This is probably the DM core.
    unsigned core_num = snrt_cluster_core_num() - 1;

#pragma omp parallel
    {
        unsigned core_idx = snrt_cluster_core_idx();
        size_t local_n = n / core_num;
        int do_extra = 0;

        // Calculate which core does one more to account for the leftovers
        if (core_idx < n - local_n * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

        snrt_ssr_enable();

        asm (
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fabs.d ft2, ft0 \n"
            :: [n_frep] "r"(local_n - 1) : "ft0", "ft2"
        );
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            result[local_n * core_num + core_idx] = fabs(arr[local_n * core_num + core_idx]);
        }
    }

    return 0;
}
