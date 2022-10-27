
#include "copy.h"

#include <snrt.h>

__attribute__((noinline))
int copy_baseline(const float* source, const size_t n, float* target) {
    snrt_memcpy(target, source, n * sizeof(float));

    return 0;
}

__attribute__((noinline))
int copy_ssr(const float* source, const size_t n, float* target) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

    // input is ft0
    asm volatile("" : "=f"(ft0));

    // stream into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*source));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, (float *)source);

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
    asm volatile("" :: "f"(ft2));
    
    return 0;
}