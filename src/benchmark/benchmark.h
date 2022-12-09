
#ifndef LMQ_BENCHMARK_H
#define LMQ_BENCHMARK_H

#include <snrt.h>
#include "printf.h"

#ifndef LMQ_START_SIZE
#define LMQ_START_SIZE 10
#endif

#ifndef LMQ_SIZE
#define LMQ_SIZE 1024
#endif

#ifndef LMQ_RUNS
#define LMQ_RUNS 20
#endif

size_t* cycles_count;

volatile size_t size = LMQ_SIZE;
volatile size_t runs = LMQ_RUNS;

/*
 * Benchmarks a function with a single float output and prints the result.
 */
#define BENCH(func_name, ...) BENCH_VO(func_name, __VA_ARGS__)

/*
 * Benchmarks a vector operation which has no single result.
 */
#define BENCH_VO(func_name, ...)                        \
    do {                                                \
        for(int cur_run=0;cur_run<runs;cur_run++){      \
            size_t _start_ = read_csr(mcycle);              \
            int _result_code_ = func_name(__VA_ARGS__);     \
            size_t _end_ = read_csr(mcycle);                \
            printf(#func_name", size: %d: %lu cycles. Return code: %d\n", \
                    size, _end_ - _start_, _result_code_);        \
        }                                           \
    } while(0);

#define VERIFY_INT(value, reference, ...)           \
    do { if (value != reference) {                  \
        printf(__VA_ARGS__);                        \
    } } while(0);

/*
 * Benchmarks a vector operation which has no single result.
 */
#define BENCH_VO_PARALLEL(func_name, ...)               \
    do {                                                \
        for(int cur_run=0;cur_run<runs;cur_run++){      \
            size_t core_num = snrt_cluster_core_num() - 1;  \
            size_t core_idx = snrt_cluster_core_idx();      \
            size_t _start_ = read_csr(mcycle);              \
            snrt_cluster_hw_barrier();                      \
            size_t _start2_ = read_csr(mcycle);             \
            int _result_code_ = func_name(__VA_ARGS__);     \
            size_t _end2_ = read_csr(mcycle);               \
            snrt_cluster_hw_barrier();                      \
            size_t _end_ = read_csr(mcycle);                \
            size_t cycles = _end_ - _start_;                \
            size_t cycles2 = _end2_ - _start2_;             \
            snrt_cluster_sw_barrier();                      \
            /* printf("core %d inner: %d\n", core_idx, cycles2);*/ \
            /* printf("core %d outer: %d\n", core_idx, cycles); */ \
            /* for debugging purposes */                    \
            /* printf("(%d): %d\n ", snrt_cluster_core_idx(), cycles);                                      */  \
            if (snrt_cluster_core_idx() == 0) {             \
                printf(#func_name", size: %d: %lu cycles. Return code: %d\n", \
                        size, cycles, _result_code_);       \
            }                                               \   
        }                                               \
    } while(0);

/*
 * Compares the vector starting at value element wise with the vector at reference.
    Prints if they do not match.
 */
static inline void verify_vector(const float* value, const float* reference, const size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("MISMATCH at i=%d: expected %.10f, but got %.10f\n", i, reference[i], value[i]);
        }
    }
};

/*
 * Compares the vector starting at value element wise with the vector at reference. This ignores values that are multiples of the chunk size + 1.
  This comes from the SSR anomaly that they write -inf after the last element.
 */
static inline void verify_vector_omp(const float* value, const float* reference, const size_t n, const size_t chunk_size) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i] && i % chunk_size != 0 ) {
            printf("MISMATCH at i=%d: expected %.10f, but got %.10f\n", i, reference[i], value[i]);

            return;
        }
    }
};

/*
 * Compares the vector starting at value element wise with the vector at reference.
    Prints if they do not match.
 */
static inline void verify_vector_int(const int* value, const int* reference, const size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("At i=%d: expected %.10i, but got %.10i\n", i, reference[i], value[i]);
        }
    }
};

/*
 * Sets all elements in the vector (of size n) to 0.0;
 */
static inline void clear_vector(float* arr, const size_t n) {
    for (size_t i = 0; i < n; i++) {
        arr[i] = 0.0;
    }
}

/*
 * Sets all elements in the vector (of size n) to 0.0;
 */
static inline void clear_vector_int(short* arr, const size_t n) {
    for (size_t i = 0; i < n; i++) {
        arr[i] = 0;
    }
}


#endif
