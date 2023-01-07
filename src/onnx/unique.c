#include <snrt.h>

#include <stdlib.h>

#include <unique.h>
#include <float.h>

/*
 * Find the unique elements of the input array.
 * The output 'result' contains all unique values of the 'arr'.
 * The other (otpional) outputs are omitted.
 */
__attribute__((noinline)) 
int unique_baseline(float* arr, const size_t n, float* result) {
    size_t curr_n_unique_elements = 0;
    for(size_t i = 0; i < n; i++) {
        int unique = 1;
        for(size_t j = i+1; j < n; j++) {
            if(arr[i] == arr[j]) {
                unique = 0;
            }
        }
        if(unique == 1) {
            // Found a new unique value
            result[curr_n_unique_elements] = arr[i];
            curr_n_unique_elements++;
        }
    }
    return 0;
}

__attribute__((noinline)) 
int unique_ssr(float* arr, const size_t n, float* result) {
    // Stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // Stream from ft1 to result
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_write(SNRT_SSR_DM1, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    volatile size_t i;
    volatile size_t j;
    volatile int unique;
    volatile int comp;

    asm volatile(
        "li %[i], 0\n" // i = 0
        "0: "
        "fmv.s fa0, ft0\n" // fa0 <- arr[i]
        "li %[unique], 1\n" // unique <- 1
        "addi %[j], %[i], 1\n" // j <- i+1
        "1: "
        "fmv.s fa1, ft0\n" // fa1 <- arr[j]
        "feq.s %[comp], fa0, fa1\n" // compute result of fa0 == fa1, i.e., arr[i] == arr[j] and store in comp
        "beq %[comp], zero, 2f\n" // go to 2 if arr[i] != arr[j]
        "li %[unique], 0\n" // unique <- 0
        "2: "
        "addi %[j], %[j], 1\n" // j <- j+1
        "blt %[j], %[n], 1b\n" // go to 1 if j < n
        "beq %[unique], zero, 3f\n" // go to 3 if unique != 1
        "fmv.s ft1, fa0\n" // ft1 <- fa0
        "3: "
        "addi %[i], %[i], 1\n" // i <- i+1
        "blt %[i], %[n], 0b\n" // go to 0 if i < n
        : [i] "+r"(i), [j] "+r"(j), [unique] "+r"(unique), [comp] "+r"(comp)
        : [n] "r"(n)
        : "ft0", "ft1", "fa0", "fa1"
    );

    snrt_ssr_disable();

    return 0;
}