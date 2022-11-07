
#ifndef LMQ_BENCHMARK_H
#define LMQ_BENCHMARK_H

#include <snrt.h>
#include "printf.h"

const size_t size = 500;

/*
 * Benchmarks a function with a single float output and prints the result.
 */
#define BENCH(func_name, ...) BENCH_VO(func_name, __VA_ARGS__)
/*
 * Benchmarks a vector operation which has no single result.
 */
#define BENCH_VO(func_name, ...)                        \
    do {                                                \
        size_t _start_ = read_csr(mcycle);              \
        int _result_code_ = func_name(__VA_ARGS__);     \
        size_t _end_ = read_csr(mcycle);                \
        printf(#func_name": %lu cycles. Return code: %d\n", \
                _end_ - _start_, _result_code_);        \
    } while(0);

#define VERIFY_INT(value, reference, ...)           \
    do { if (value != reference) {                  \
        printf(__VA_ARGS__);                        \
    } } while(0);

/*
 * Compares the vector starting at value element wise with the vector at reference.
    Prints if they do not match.
 */
static inline void verify_vector(const float* value, const float* reference, const size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("At i=%d: expected %.10f, but got %.10f\n", i, reference[i], value[i]);
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

