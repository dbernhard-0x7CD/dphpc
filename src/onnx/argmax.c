
#include <snrt.h>

#include <argmax.h>
#include <float.h>

/*
 * Naive implementation of argmax. Calculates the argmax of n elements starting at arr.
 */
__attribute__((noinline))
int argmax_baseline(const float* arr, const size_t n, int* result) {
    float max = FLT_MIN;
    size_t index = -1;

    for (size_t i = 0; i < n; i++) {
        if (arr[i] > max) {
            max = arr[i];
            index = i;
        }
    }

    *result = index;

    return 0;
}

__attribute__((noinline))
int argmax_ssr(const float* arr, const size_t n, int* result) {
    register volatile float ft0 asm("ft0");

    register float max asm("ft1");
    max = FLT_MIN;

    register int max_index;

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    // i need my own loop
    asm volatile(
        "addi a0, zero, 0\n"            // a0 <- 0; a0 is the index
        "addi a1, zero, -1\n"           // a1 stores the max_index
        "1:\n"
            "addi a0, a0, 1\n"
            "fmv.s fa0, ft0\n"
            "fle.s a2, %[max], fa0\n"
            "beqz a2, 3f\n"
            "fmv.s %[max], fa0\n"
            "mv a1, a0\n"
        "3:"
        "blt a0, %[n], 1b\n"
        "2:\n" // exit
        "add %[max_index], a1, -1\n"        // as a1 is one too high
        : [max] "+f" (max), [max_index] "=r" (max_index)
        : [n] "r"(n) 
        : "ft0", "ft2", "a0", "a1", "a2"
    );

    snrt_ssr_disable();

    *result = max_index;

    return 0;
}

__attribute__((noinline))
int argmax_ssr_frep(const float* arr, const size_t n, int* result) {
    //
    //
    // WIP by David
    //
    //
    return 0;
}
