
#include "copy.h"
#include "omp.h"

#include <snrt.h>
#include "printf.h"

__attribute__((noinline))
int copy_snitch(double* source, const size_t n, double* target) {
    snrt_memcpy(target, source, n * sizeof(double));

    return 0;
}

__attribute__((noinline))
int copy_baseline(double* source, const size_t n, double* target) {

    for (uint32_t i = 0; i < n; i++) {
        target[i] = source[i];
    }

    return 0;
}

__attribute__((noinline))
int copy_ssr(double* source, const size_t n, double* target) {
    register volatile double ft0 asm("ft0");
    register volatile double ft2 asm("ft2");

    // stream into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*source));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source);

    // stream from ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*target));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, target);

    snrt_ssr_enable();

    for (size_t i = 0; i < n; i++) {
        asm volatile(
           "fmv.d ft2, ft0 \n"
           ::: "ft0", "ft2"
        );
    }
    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));
    
    return 0;
}
__attribute__((noinline))
int copy_ssr_frep(double* source, const size_t n, double* target) {
    register volatile double ft0 asm("ft0");
    register volatile double ft2 asm("ft2");
    
    // input is ft0; TODO: Why is this needed?
    asm volatile("" : "=f"(ft0));

    // stream into register ft0 the source
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*source));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source);

    // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*target));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, target);

    snrt_ssr_enable();

    asm (
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fmv.d ft2, ft0 \n"
        :: [n_frep] "r"(n - 1) : "ft0", "ft2"
    );
    
    snrt_ssr_disable();

    // Output is ft2; TODO: Why is this needed?
    asm volatile("" :: "f"(ft2), "f"(ft0));
    
    return 0;
}

__attribute__((noinline))
int copy_parallel(double* source, const size_t n, double* target) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    for (unsigned i = 0; i < local_n; i++) {
        target[core_idx * local_n + i] = source[core_idx * local_n + i];
    }

    if (do_extra) {
        target[core_num * local_n + core_idx] = source[core_num * local_n + core_idx];
    }

    return 0;
}

__attribute__((noinline))
int copy_ssr_parallel(double* source, const size_t n, double* target) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(double));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(double));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, target + core_idx * local_n);
    
    snrt_ssr_enable();

    for (unsigned i = 0; i < local_n; i++) {
        asm volatile(
            "fmv.d ft1, ft0\n"
            ::: "ft0", "ft1"
        );
    }

    snrt_ssr_disable();

    if (do_extra) {
        target[core_num * local_n + core_idx] = source[core_num * local_n + core_idx];
    }

    return 0;
}

__attribute__((noinline))
int copy_ssr_frep_parallel(double* source, const size_t n, double* target) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(double));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(double));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, target + core_idx * local_n);
    
    snrt_ssr_enable();
    
    asm (
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fmv.d ft1, ft0 \n"
        :: [n_frep] "r"(local_n - 1) : "ft0", "ft1"
    );
    
    snrt_ssr_disable();

    if (do_extra) {
        target[core_num * local_n + core_idx] = source[core_num * local_n + core_idx];
    }

    return 0;
}

int copy_omp(double* source, const size_t n, double* target) {

#pragma omp parallel for
    for (size_t i = 0; i < n; i++) {
        target[i] = source[i];
    }

    return 0;
}

int copy_ssr_omp(double* source, const size_t n, double* target) {
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

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*source));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*target));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, target + core_idx * local_n);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_n; i++) {
            asm volatile(
                "fmv.d ft2, ft0 \n"
                ::: "ft0", "ft2"
            );
        }
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            target[local_n * core_num + core_idx] = source[local_n * core_num + core_idx];
        }
    }

    return 0;
}

int copy_ssr_frep_omp(double* source, const size_t n, double* target) {
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

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*source));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

        snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*target));
        snrt_ssr_repeat(SNRT_SSR_DM2, 1);
        snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, target + core_idx * local_n);

        snrt_ssr_enable();

        asm (
            "frep.o %[n_frep], 1, 0, 0 \n"
            "fmv.d ft2, ft0 \n"
            :: [n_frep] "r"(local_n - 1) : "ft0", "ft2"
        );
        
        snrt_ssr_disable();

        // Could also be done in ssr, but this only adds O(number of threads) which we assume is low.
        if (do_extra) {
            target[local_n * core_num + core_idx] = source[local_n * core_num + core_idx];
        }
    }

    return 0;

}
