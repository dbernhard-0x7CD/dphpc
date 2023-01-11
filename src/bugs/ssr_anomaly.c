#include "printf.h"
#include <stdlib.h>

#include "lmq.h"
#include "snrt.h"
#include "float.h"

/*
 * This shows that SSR will write -inf at the end of every stream.
 *
 * We write up to index 2 (so 3 write instructions) the value '0.0'.
 * We expect that the value at index 3 is untouched but it's '-inf'.
 */
int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // Let this run only on core 0
    if (core_idx != 0) {
        snrt_cluster_hw_barrier();
        return EXIT_SUCCESS;
    }

    printf("Demonstrating the SSR anomaly\n");

    // x is input, each element has the value of its index;
    // We then write up to index 'write_up_to' (exclusive) zeroes.
    // What we actually observe is that at index 'write_up_to'
    // we have a value of -inf which somehow was also written.
    const size_t size = 10;
    const volatile uint32_t write_up_to = 4;
    volatile double* x = allocate(size, sizeof(double));

    for (size_t i = 0; i < size; i++) {
        x[i] = i;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, write_up_to, sizeof(double));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_write(SNRT_SSR_DM0, SNRT_SSR_1D, x);

    snrt_ssr_enable();
    for (uint32_t i = 0; i < write_up_to; i++) {
        asm volatile(
            "addi x5, zero, 0\n"    // x5 <-- 0
            "fcvt.d.w ft1, x5\n"    // ft1 <-- double(x5)
            "fmv.d ft0, ft1\n"      // ft0 <-- ft1 (write to x[i])
            ::: "ft0", "ft1", "x5"
        );
    }
    snrt_ssr_disable();

    for (size_t i = 0; i < size; i++) {
        printf("Value at %d is %lf\n", i, x[i]);
    }

    snrt_cluster_hw_barrier();
    return 0;
}
