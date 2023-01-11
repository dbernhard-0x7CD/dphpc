
#include <snrt.h>

#include <argmax.h>
#include <printf.h>
#include <float.h>

/*
 * Naive implementation of argmax. Calculates the argmax of n elements starting at arr.
 */
__attribute__((noinline))
int argmax_baseline(const double* arr, const size_t n, int* result) {
    double max = FLT_MIN;
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
int argmax_ssr(const double* arr, const size_t n, int* result) {
    register double max asm("ft1");
    max = FLT_MIN;

    register int max_index;

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
            "fmv.d fa0, ft0\n"
            "fle.d a2, %[max], fa0\n"
            "beqz a2, 3f\n"
            "fmv.d %[max], fa0\n"
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
int argmax_ssr_frep(const double* arr, const size_t n, int* result) {

    /**
     * Using FREP we would need the same code repeated, but argmax
     * needs a branch each iteration this is not possible.
     * This branch makes pipelining impossible.
    */
    return 0;
}

// To allow IPC
double* shared_max;
size_t* shared_indices;
int argmax_parallel(double* arr, const size_t n, int* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }
    double priv_max = FLT_MIN;
    size_t priv_max_index = -1;

    if (core_idx == 0) {
        shared_max = allocate(core_num , sizeof(double));
        shared_indices = allocate(core_num , sizeof(size_t));
    }
    snrt_cluster_hw_barrier();

    for (size_t i = local_n * core_idx; i < local_n * (core_idx + 1); i++) {
        if (arr[i] > priv_max) {
            priv_max = arr[i];
            priv_max_index = i;
        }
    }
    if (do_extra) {
        if (arr[local_n * core_num + core_idx] > priv_max) {
            priv_max = arr[local_n * core_num + core_idx];
            priv_max_index = local_n * core_num + core_idx;
        }
    }

    snrt_cluster_hw_barrier();
    shared_max[core_idx] = priv_max;
    shared_indices[core_idx] = priv_max_index;
    snrt_cluster_hw_barrier();

    if (core_idx == 0) {
        double max = FLT_MIN;
        size_t index = -1;
        for (size_t i = 0; i < core_num; i++) {
            if (shared_max[i] > max) {
                max = shared_max[i];
                index = shared_indices[i];
            }
        }
        *result = index;
    }

    return 0;
}

int argmax_ssr_parallel(double* arr, const size_t n, int* result) {
    size_t core_num = snrt_cluster_core_num() - 1;
    size_t core_idx = snrt_cluster_core_idx();
    size_t local_n = n / core_num;

    if (snrt_is_dm_core()) {
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        snrt_cluster_hw_barrier();
        return 0;
    }

    int do_extra = 0;
    if (core_idx < n - local_n * core_num) {
        do_extra = 1;
    }

    double priv_max = FLT_MIN;
    volatile int priv_max_index = -1;

    if (core_idx == 0) {
        shared_max = allocate(core_num , sizeof(double));
        shared_indices = allocate(core_num , sizeof(size_t));
    }
    snrt_cluster_hw_barrier();

    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, local_n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr + local_n * core_idx);

    snrt_ssr_enable();

    asm volatile(
        "add a0, %[index], zero\n"            // a0 <- 0; a0 is the index
        "addi a1, zero, -1\n"           // a1 stores the max_index
        "1:\n"
            "addi a0, a0, 1\n"
            "fmv.d fa0, ft0\n"
            "fle.d a2, %[max], fa0\n"
            "beqz a2, 3f\n"
            "fmv.d %[max], fa0\n"
            "mv a1, a0\n"
        "3:"
        "blt a0, %[n], 1b\n"
        "2:\n" // exit
        "add %[max_index], a1, -1\n"        // as a1 is one too high
        : [max] "+f" (priv_max), [max_index] "=r" (priv_max_index)
        : [n] "r"(local_n * (core_idx + 1)), [index] "r" (local_n * core_idx)
        : "ft0", "ft2", "a0", "a1", "a2"
    );

    snrt_ssr_disable();

    if (do_extra) {
        if (arr[local_n * core_num + core_idx] > priv_max) {
            priv_max = arr[local_n * core_num + core_idx];
            priv_max_index = local_n * core_num + core_idx;
        }
    }

    snrt_cluster_hw_barrier();
    shared_max[core_idx] = priv_max;
    shared_indices[core_idx] = priv_max_index;
    snrt_cluster_hw_barrier();

    // This is not using SSR, but this is O(#cores) which is low
    if (core_idx == 0) {
        double max = FLT_MIN;
        size_t index = -1;
        for (size_t i = 0; i < core_num; i++) {
            if (shared_max[i] > max) {
                max = shared_max[i];
                index = shared_indices[i];
            }
        }
        *result = index;
    }

    return 0;
}
