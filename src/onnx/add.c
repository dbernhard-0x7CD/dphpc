#include "printf.h"
#include <snrt.h>
#include "omp.h"

#include "lmq.h"

/*
 * Naive implementation of add. Adds a and b element wise into result.
 */
__attribute__((noinline))
int add_baseline(double *a, double* b, const size_t n, double* result) {
    for (size_t i = 0; i < n; i++) {
        result[i] = a[i] + b[i];
    }
    return 0;
}


__attribute__((noinline))
int add_ssr(double *a, double* b, const size_t n, double* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fadd.d ft2, ft0, ft1 \n"
            ::: "ft0", "ft1", "ft2"
        );
    }

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int add_ssr_frep(double *a, double* b, const size_t n, double* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fadd.d ft2, ft0, ft1 \n"
        :: [n_frep] "r"(n - 1) : "ft0", "ft1", "ft2"
    );

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int add_parallel(double *a, double *b, const size_t n, double *result) {
    unsigned core_num = snrt_cluster_core_num() - 1;
    unsigned core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    int do_extra = 0;

    // Calculate which core does one more to account for the leftovers
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    for (unsigned i = core_idx * local_n; i < (core_idx + 1) * local_n; i++) {
        result[i] = a[i] + b[i];
    }

    if (do_extra) {
        result[local_n * core_num + core_idx] = a[local_n * core_num + core_idx] + b[local_n * core_num + core_idx];
    }

    return 0;
}

__attribute__((noinline))
int add_ssr_parallel(double *a, double* b, const size_t n, double* result) {
    // The last thread is not used in OpenMP.
    // This is probably the DM core.
    unsigned core_num = snrt_cluster_core_num() - 1;
    unsigned core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    int do_extra = 0;

    // Calculate which core does one more to account for the leftovers
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

    snrt_ssr_enable();

    for (size_t i = 0; i < local_n; i++) {
        asm volatile(
            "fadd.d ft2, ft0, ft1 \n"
            ::: "ft0", "ft1", "ft2"
        );
    }
    
    snrt_ssr_disable();

    // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
    if (do_extra) {
        result[local_n * core_num + core_idx] = a[local_n * core_num + core_idx] + b[local_n * core_num + core_idx];
    }

    return 0;
}

__attribute__((noinline))
int add_ssr_frep_parallel(double *a, double* b, const size_t n, double* result) {
    // The last thread is not used in OpenMP.
    // I do not know why.
    unsigned core_num = snrt_cluster_core_num() - 1;
    unsigned core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    int do_extra = 0;

    // Calculate which core does one more to account for the leftovers
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

    snrt_ssr_enable();

    asm volatile(
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fadd.d ft2, ft0, ft1 \n"
        :: [n_frep] "r"(local_n - 1) : "ft0", "ft1", "ft2"
    );
    
    snrt_ssr_disable();

    // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
    if (do_extra) {
        result[local_n * core_num + core_idx] = a[local_n * core_num + core_idx] + b[local_n * core_num + core_idx];
    }

    return 0;
}

__attribute__((noinline)) 
int add_omp(double *a, double *b, const size_t n, double *result) {

#pragma omp parallel for schedule(static) // in the following line it's necessary to use 'signed'
    for (unsigned i = 0; i < n; i++) {
        result[i] = a[i] + b[i];
    }

    return 0;
}

__attribute__((noinline)) 
int add_ssr_omp(double *a, double *b, const size_t n, double *result) {
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

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(*b));
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_n; i++) {
            asm volatile(
                "fadd.d ft2, ft0, ft1 \n"
                ::: "ft0", "ft1", "ft2"
            );
        }
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            result[local_n * core_num + core_idx] = a[local_n * core_num + core_idx] + b[local_n * core_num + core_idx];
        }
    }

    return 0;
}

__attribute__((noinline)) 
int add_ssr_frep_omp(double *a, double *b, const size_t n, double *result) {
    // The last thread is not used in OpenMP.
    // I do not know why.
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

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*a));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(*b));
        snrt_ssr_repeat(SNRT_SSR_DM1, 1);
        snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

        snrt_ssr_enable();

        asm volatile(
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fadd.d ft2, ft0, ft1 \n"
            :: [n_frep] "r"(local_n - 1) : "ft0", "ft1", "ft2"
        );
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            result[local_n * core_num + core_idx] = a[local_n * core_num + core_idx] + b[local_n * core_num + core_idx];
        }
    }

    return 0;
}
