#include "printf.h"
#include <math.h>
#include <stdlib.h>

#include "lmq.h"
#include "snrt.h"
#include "float.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) return 1;

    printf("Demonstrating the SSR anomaly\n");

    // x is input; result is output of the optimized functions
    const size_t size = 10;
    const size_t write_up_to = 3;
    float* x = allocate(size, sizeof(float));

    for (size_t i = 0; i < size; i++) {
        x[i] = i;
    }

    // TODO
    register volatile float ft0 asm("ft0");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, write_up_to , sizeof(*x));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_write(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_enable();

    register float s = 0;
    for (size_t i = 0; i < write_up_to; i++) {
        asm volatile(
            "fadd.s ft0, %[s], %[s] \n"
            : [s] "+f"(s)
            : [zero] "f" (s)
            : "ft0"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0));

    for (size_t i = 0; i < size; i++) {
        printf("Value at %d is %f\n", i, x[i]);
    }


    return 0;
}
