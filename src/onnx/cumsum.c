
#include <snrt.h>

#include <cumsum.h>
#include <float.h>
#include "lmq.h"
#include "printf.h"

/*
 * Naive implementation of cumulative sum. Calculates the cumulative sum of n elements starting at arr.
 */
__attribute__((noinline))
int cumsum_baseline(const float* arr, const size_t n, float* result) {
    float sum = 0.0;

    for (size_t i = 0; i < n; i++) {
        sum += arr[i];

        result[i] = sum;
    }

    return 0;
}

__attribute__((noinline))
int cumsum_ssr(const float* arr, const size_t n, volatile float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    // i need my own loop
    asm volatile(
        "addi a0, zero, 0\n"      // a0 counts
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"     // ft1 stores the cumulative sum. Set it to 0.0
        "1:\n"
            "addi a0, a0, 1\n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- ft0 (streamed arr[i]) + ft1
            "fmv.s ft2, ft1\n"
        "3:"
        "blt a0, %[n], 1b\n"
        :: [n] "r"(n) 
        : "ft0", "ft1", "ft2", "a0", "a1"
    );

    snrt_ssr_disable();

    asm volatile("" :: "f"(ft2));

    return 0;
}

__attribute__((noinline))
int cumsum_ssr_frep(const float* arr, const size_t n, volatile float* result) {
    register volatile float ft0 asm("ft0");
    register volatile float ft2 asm("ft2");

    // ft0 is input
    asm volatile("" : "=f"(ft0));

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result);

    snrt_ssr_enable();

    asm volatile(
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"        // ft1 stores the cumulative sum. set it to 0.0
        "frep.o %[n], 2, 0, 0 \n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- fa0 + ft1
            "fmv.s ft2, ft1\n"
        :: [n] "r"(n-1)
        : "ft0", "ft1", "ft2", "a0", "a1"
    );

    snrt_ssr_disable();
    
    asm volatile("" :: "f"(ft2));

    return 0;
}

float* shared;
int cumsum_parallel(const float* arr, const size_t n, float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    
    // The DM core should not do anything
    if (snrt_is_dm_core()) {
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        return 0;
    }

    volatile float my_sum = arr[core_idx * local_n];

    if (core_idx == 0) {
        shared = allocate(core_num, sizeof(float));
    }
    snrt_cluster_hw_barrier();

    /* In this case do_extra works different; The core 0 does all the work */
    int do_extra = 0;
    if (0 != n - local_n * core_num && core_idx == 0) {
        do_extra = 1;
    }

    // let each calc it's prefix sum
    result[core_idx * local_n] = my_sum;
    for (unsigned i = 1; i < local_n; i++) {
        my_sum += arr[core_idx * local_n + i];
        result[core_idx * local_n + i] = my_sum;
    }

    shared[core_idx] = my_sum;
    snrt_cluster_hw_barrier();

    if (core_idx == 0) {
        for (size_t i = 1; i < core_num; i++) {
            // printf("intermediate sums at %d is %f\n", i, shared[i]);
            shared[i] = shared[i-1] + shared[i];
        }
    }
    // if (core_idx == 0) {
    //     for (size_t i = 0; i < core_num; i++) {
    //         printf("calculated sums at %d is %f\n", i, shared[i]);
    //     }
    // }
    snrt_cluster_hw_barrier();

    /* Now every core adds the global stuff */
    // printf("Core %d adds %f\n", core_idx, shared[core_idx-1]);
    for (unsigned i = 0; i < local_n && core_idx > 0; i++) {
        result[core_idx * local_n + i] = result[core_idx * local_n + i] + shared[core_idx-1];
        // printf("Setting result to %f\n", result[core_idx * local_n + i]);
    }
    snrt_cluster_hw_barrier();

    if (do_extra) {
        my_sum = shared[core_num - 1];
        for (unsigned i = 0; i < n - local_n * core_num; i++) {
            my_sum += arr[core_num * local_n + i];

            result[core_num * local_n + i] = my_sum;
        }
    }

    return 0;
}

int cumsum_ssr_parallel(const float* arr, const size_t n, volatile float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    
    // The DM core should not do anything
    if (snrt_is_dm_core()) {
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        return 0;
    }

    snrt_cluster_hw_barrier();
    if (core_idx == 0) {
        shared = allocate(core_num, sizeof(float));
    }
    snrt_cluster_hw_barrier();

    /* In this case do_extra works different; The core 0 does all the work */
    int do_extra = 0;
    if (0 != n - local_n * core_num && core_idx == 0) {
        do_extra = 1;
    }

    // stream arr into ft0
    // disable ft1 stream
    snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, 4);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);
 
    // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

    snrt_ssr_enable();

    // // i need my own loop
    volatile register float my_sum = 0.0;
    asm volatile(
        "addi a0, zero, 0\n"      // a0 counts
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"     // ft1 stores the cumulative sum. Set it to 0.0
        "1:\n"
            "addi a0, a0, 1\n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- ft0 (streamed arr[i]) + ft1
            "fmv.s ft2, ft1\n"
        "3:"
        "blt a0, %[n], 1b\n"
        "fmv.s %[target], ft1\n"
        : [target] "=f"(my_sum)
        : [n] "r"(local_n) 
        : "ft0", "ft1", "ft2", "a0", "a1"
    );

    snrt_ssr_disable();

    // printf("I'm core %d and have sum %f\n", core_idx, my_sum);

    snrt_cluster_hw_barrier();
    shared[core_idx] = my_sum;
    snrt_cluster_hw_barrier();

    if (core_idx == 0) {
        // printf("intermediate sums at %d is %f\n", 0, shared[0]);
        for (size_t i = 1; i < core_num; i++) {
            // printf("intermediate sums at %d is %f\n", i, shared[i]);
            shared[i] = shared[i-1] + shared[i];
        }
    }
    // if (core_idx == 0) {
    //     for (size_t i = 0; i < core_num; i++) {
    //         printf("calculated sums at %d is %f\n", i, shared[i]);
    //     }
    // }

    /* Now every core adds the global stuff */
    // printf("Core %d adds %f\n", core_idx, shared[core_idx-1]);
    for (unsigned i = 0; i < local_n && core_idx > 0; i++) {
        result[core_idx * local_n + i] = result[core_idx * local_n + i] + shared[core_idx-1];
        // printf("Setting result to %f\n", result[core_idx * local_n + i]);
    }
    snrt_cluster_hw_barrier();

    if (do_extra) {
        my_sum = shared[core_num - 1];
        for (unsigned i = 0; i < n - local_n * core_num; i++) {
            my_sum += arr[core_num * local_n + i];

            result[core_num * local_n + i] = my_sum;
        }
    }

    return 0;
}

int cumsum_ssr_frep_parallel(const float* arr, const size_t n, volatile float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;
    
    // The DM core should not do anything
    if (snrt_is_dm_core()) {
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        return 0;
    }

    snrt_cluster_hw_barrier();
    if (core_idx == 0) {
        shared = allocate(core_num, sizeof(float));
    }
    snrt_cluster_hw_barrier();

    /* In this case do_extra works different; The core 0 does all the work */
    int do_extra = 0;
    if (0 != n - local_n * core_num && core_idx == 0) {
        do_extra = 1;
    }

    // stream arr into ft0
    // disable ft1 stream
    snrt_ssr_loop_1d(SNRT_SSR_DM1, 0, 0);

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, 4);
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);
 
    // stream from register ft2 into result
    snrt_ssr_loop_1d(SNRT_SSR_DM2, local_n, sizeof(*result));
    snrt_ssr_repeat(SNRT_SSR_DM2, 1);
    snrt_ssr_write(SNRT_SSR_DM2, SNRT_SSR_1D, result + core_idx * local_n);

    snrt_ssr_enable();

    // // i need my own loop
    volatile register float my_sum = 0.0;
    asm volatile(
        "addi a1, zero, 0\n"
        "fcvt.s.w ft1, a1\n"     // ft1 stores the cumulative sum. Set it to 0.0
        "frep.o %[n], 2, 0, 0 \n"
            "fadd.s ft1, ft0, ft1\n" // ft1 <- ft0 (streamed arr[i]) + ft1
            "fmv.s ft2, ft1\n"
        "fmv.s %[target], ft1\n"
        : [target] "=f"(my_sum)
        : [n] "r"(local_n - 1) 
        : "ft0", "ft1", "ft2", "a1"
    );

    snrt_ssr_disable();

    // printf("I'm core %d and have sum %f\n", core_idx, my_sum);

    snrt_cluster_hw_barrier();
    shared[core_idx] = my_sum;
    snrt_cluster_hw_barrier();

    if (core_idx == 0) {
        // printf("intermediate sums at %d is %f\n", 0, shared[0]);
        for (size_t i = 1; i < core_num; i++) {
            // printf("intermediate sums at %d is %f\n", i, shared[i]);
            shared[i] = shared[i-1] + shared[i];
        }
    }
    // if (core_idx == 0) {
    //     for (size_t i = 0; i < core_num; i++) {
    //         printf("calculated sums at %d is %f\n", i, shared[i]);
    //     }
    // }

    /* Now every core adds the global stuff */
    // printf("Core %d adds %f\n", core_idx, shared[core_idx-1]);
    for (unsigned i = 0; i < local_n && core_idx > 0; i++) {
        result[core_idx * local_n + i] = result[core_idx * local_n + i] + shared[core_idx-1];
        // printf("Setting result to %f\n", result[core_idx * local_n + i]);
    }
    snrt_cluster_hw_barrier();

    if (do_extra) {
        my_sum = shared[core_num - 1];
        for (unsigned i = 0; i < n - local_n * core_num; i++) {
            my_sum += arr[core_num * local_n + i];

            result[core_num * local_n + i] = my_sum;
        }
    }

    return 0;

    return 0;
}