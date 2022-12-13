#include "printf.h"

#include "lmq.h"
#include "sum.h"
#include <snrt.h>
#include "omp.h"

__attribute__((noinline)) 
int sum_baseline(float *arr, const size_t n, float* result) {
    float s = 0;

    for (size_t i = 0; i < n; i++) {
        s += arr[i];
    }

    *result = s;

    return 0;
}

__attribute__((noinline)) 
int sum_ssr(float *arr, const size_t n, float* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    volatile register float s = 0.0;
    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fadd.s %[s], ft0, %[s] \n"
            : [s] "+f"(s) :: "ft0"
        );
    }

    snrt_ssr_disable();

    *result = s;

    return 0;
}

__attribute__((noinline)) 
int sum_ssr_frep(float *arr, const size_t n, float* result) {
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    float s;
    asm volatile(
        "addi x5, zero, 0\n"
        "fcvt.s.w %[s], x5\n" // sets s to zero
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fadd.s %[s], ft0, %[s] \n"
        : [s] "+f"(s) : [n_frep] "r"(n - 1) : "ft0"
    );

    snrt_ssr_disable();

    *result = s;

    return 0;
}

float* result_arr;
__attribute__((noinline)) 
int sum_parallel(float *arr, const size_t n, float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    /*
     * We need this array to store the result of each core.
     * As a reduction cannot be compiled (results in endless loop)
     */
    if (core_idx == 0) {
        result_arr = allocate(core_num , sizeof(float));
    }

    // sum parallel
    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }
    float priv_sum = 0.0;

    for (unsigned i = local_n * core_idx; i < local_n * (core_idx + 1); i++) {
        priv_sum += arr[i];
        // printf("Core %d is adding %f\n", core_idx, arr[i]);
    }

    if (do_extra) {
        priv_sum += arr[core_num * local_n + core_idx];
    }

    // For some reason the following barrier is needed
    snrt_cluster_hw_barrier();
    // printf("Core %d sets it to %f\n", core_idx, priv_sum);

    result_arr[core_idx] = priv_sum;

    snrt_cluster_hw_barrier();
    
    if (core_idx == 0) {
        float sum = 0.0;
        for (uint32_t i = 0; i < core_num; i++) {
            sum += result_arr[i];
            // printf("Core %d has sum: %f\n", i, result_arr[i]);
        }
        
        *result = sum;
    }

    return 0;
}

__attribute__((noinline)) 
int sum_ssr_parallel(float *arr, const size_t n, float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    /*
     * We need this array to store the result of each core.
     * As a reduction cannot be compiled (results in endless loop)
     */
    if (core_idx == 0) {
        result_arr = allocate(core_num , sizeof(float));
    }
    
    // sum parallel
    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

    snrt_ssr_enable();

    register float priv_sum = 0;
    for (size_t i = 0; i < local_n; i++) {
        asm volatile(
            "fadd.s %[s], ft0, %[s] \n"
            : [s] "+f"(priv_sum) :: "ft0"
        );
    }

    snrt_ssr_disable();

    // This is only constant overhead (actually O(#cores))
    if (do_extra) {
        priv_sum += arr[core_num * local_n + core_idx];
    }

    // For some reason the following barrier is needed
    snrt_cluster_hw_barrier();
    // printf("Core %d sets it to %f\n", core_idx, priv_sum);

    result_arr[core_idx] = priv_sum;

    snrt_cluster_hw_barrier();
    
    if (core_idx == 0) {
        float sum = 0.0;
        for (int i = 0; i < core_num; i++) {
            sum += result_arr[i];
            // printf("Core %d has sum: %f\n", i, result_arr[i]);
        }
        
        *result = sum;
    }

    return 0;
}

__attribute__((noinline)) 
int sum_ssr_frep_parallel(float *arr, const size_t n, float* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    /*
     * We need this array to store the result of each core.
     * As a reduction cannot be compiled (results in endless loop)
     */
    if (core_idx == 0) {
        result_arr = allocate(core_num , sizeof(float));
    }
    
    // sum parallel
    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

    snrt_ssr_enable();

    register float priv_sum;
    asm volatile(
        "addi x5, zero, 0\n"
        "fcvt.s.w %[s], x5\n" // sets s to zero
        "frep.o %[n_frep], 1, 0, 0 \n"
        "fadd.s %[s], ft0, %[s] \n"
        : [s] "+f"(priv_sum) : [n_frep] "r"(local_n - 1) : "ft0"
    );

    snrt_ssr_disable();

    // This is only constant overhead (actually O(#cores))
    if (do_extra) {
        priv_sum += arr[core_num * local_n + core_idx];
    }

    // For some reason the following barrier is needed
    snrt_cluster_hw_barrier();
    // printf("Core %d sets it to %f\n", core_idx, priv_sum);

    result_arr[core_idx] = priv_sum;

    snrt_cluster_hw_barrier();
    
    if (core_idx == 0) {
        float sum = 0.0;
        for (int i = 0; i < core_num; i++) {
            sum += result_arr[i];
            // printf("Core %d has sum: %f\n", i, result_arr[i]);
        }
        
        *result = sum;
    }

    return 0;
}

// __attribute__((noinline)) 
// int sum_omp_fail(float *arr, const size_t n, float* result) {
//     float sum = 0.0;
// 
// #pragma omp parallel for reduction(+:sum)
//     for (unsigned i = 0; i < n; i++) {
//         sum += arr[i];
//     }
// 
//     return sum;
// }

__attribute__((noinline)) 
int sum_omp(float *arr, const size_t n, float* result) {
    unsigned core_num = snrt_cluster_core_num() - 1;
    /*
     * We need this array to store the result of each core.
     * As a reduction cannot be compiled (results in endless loop)
     */
    float* result_arr = allocate(snrt_cluster_core_num(), sizeof(float));
#pragma omp parallel
    {
        float priv_sum = 0.0;
        unsigned core_idx = snrt_cluster_core_idx();
        // printf("HERE %d\n", core_idx);
        size_t local_n = n / core_num;
        int do_extra = 0;
        if (core_idx < n - local_n * core_num) {
            do_extra = 1;
        }

        for (unsigned i = local_n * core_idx; i < local_n * (core_idx + 1); i++) {
            priv_sum += arr[i];
        }

        if (do_extra) {
            priv_sum += arr[core_num * local_n + core_idx];
        }

        result_arr[core_idx] = priv_sum;
    }

    // Core 0 is alone again, or is he not?
    float sum = 0.0;
    for (int i = 0; i < core_num; i++) {
        sum += result_arr[i];
    }

    *result = sum;

    return 0;
}

float* result_arr;
__attribute__((noinline)) 
int sum_ssr_omp(float *arr, const size_t n, float* result) {
    unsigned core_num = snrt_cluster_core_num() - 1;
    /*
     * We need this array to store the result of each core.
     * As a reduction cannot be compiled (results in endless loop)
     */
    float* result_arr = allocate(snrt_cluster_core_num(), sizeof(float));
#pragma omp parallel
    {
        register float priv_sum = 0.0;
        unsigned core_idx = snrt_cluster_core_idx();
        // printf("HERE %d\n", core_idx);
        size_t local_n = n / core_num;
        int do_extra = 0;
        if (core_idx < n - local_n * core_num) {
            do_extra = 1;
        }

        snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
        snrt_ssr_repeat(SNRT_SSR_DM0, 1);
        snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + core_idx * local_n);

        snrt_ssr_enable();

        for (size_t i = 0; i < local_n; i++) {
            asm volatile(
                "fadd.s %[s], ft0, %[s] \n"
                : [s] "+f"(priv_sum) :: "ft0"
            );
        }

        snrt_ssr_disable();

        if (do_extra) {
            // priv_sum += arr[core_num * local_n + core_idx];
        }

        result_arr[core_idx] = priv_sum;
    }

    // Core 0 is alone again, or is he not?
    float sum = 0.0;
    for (int i = 0; i < core_num; i++) {
        printf("Core %d sum: %f\n", i, result_arr[i]);
        sum += result_arr[i];
    }

    *result = sum;

    return 0;
}

__attribute__((noinline)) 
int sum_ssr_frep_omp(float *arr, const size_t n, float* result) {

    return 0;
}
