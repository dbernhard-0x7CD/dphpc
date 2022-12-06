
#include "copy.h"

#include <snrt.h>
#include "printf.h"

__attribute__((noinline))
int copy_baseline(const float* source, const size_t n, float* target) {
    snrt_memcpy(target, source, n * sizeof(float));

    return 0;
}

__attribute__((noinline))
int copy_ssr(const float* source, const size_t n, float* target) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

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
           "fmv.s ft2, ft0 \n"
           ::: "ft0", "ft2"
        );
    }
    snrt_ssr_disable();
    asm volatile("" :: "f"(ft2));
    
    return 0;
}
__attribute__((noinline))
int copy_ssr_frep(const float* source, const size_t n, float* target) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");
    
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
        "fmv.s ft2, ft0 \n"
        :: [n_frep] "r"(n - 1) : "ft0", "ft2"
    );
    
    snrt_ssr_disable();

    // Output is ft2; TODO: Why is this needed?
    asm volatile("" :: "f"(ft2), "f"(ft0));
    
    return 0;
}

__attribute__((noinline))
int copy_parallel(const float* source, const size_t n, float* target) {
    size_t core_num = snrt_global_core_num() - 1;
    size_t core_idx = snrt_global_core_idx();

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
int copy_ssr_parallel(const float* source, const size_t n, float* target) {
    size_t core_num = snrt_global_core_num() - 1;
    size_t core_idx = snrt_global_core_idx();

    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(float));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(float));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, target + core_idx * local_n);
    
    snrt_ssr_enable();

    for (unsigned i = 0; i < local_n; i++) {
        asm volatile(
            "fmv.s ft1, ft0\n"
            ::: "ft0", "ft1"
        );
    }

    if (do_extra) {
        target[core_num * local_n + core_idx] = source[core_num * local_n + core_idx];
    }

    snrt_ssr_disable();

    return 0;
}

__attribute__((noinline))
int copy_ssr_frep_parallel(const float* source, const size_t n, float* target) {
    size_t core_num = snrt_global_core_num() - 1;
    size_t core_idx = snrt_global_core_idx();

    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(float));
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, source + core_idx * local_n);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, local_n, sizeof(float));
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, target + core_idx * local_n);
    
    snrt_ssr_enable();
    
    asm (
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fmv.s ft1, ft0 \n"
        :: [n_frep] "r"(local_n - 1) : "ft0", "ft1"
    );
    
    snrt_ssr_disable();

    if (do_extra) {
        target[core_num * local_n + core_idx] = source[core_num * local_n + core_idx];
    }

    return 0;
}
