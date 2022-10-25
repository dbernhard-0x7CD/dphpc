
#ifndef LMQ_BENCHMARK_H
#define LMQ_BENCHMARK_H

#include <snrt.h>

const size_t size = 500;

/*
 * Benchmarks a function with a single float output and prints the result.
 */
#define BENCH(func_name, ...)                           \
    do {                                                \
        unsigned long start = read_csr(mcycle);         \
        float result = func_name(__VA_ARGS__);          \
        unsigned long end = read_csr(mcycle);           \
        printf(#func_name": %lu cycles, result: %f\n",  \
            end - start, result);                       \
    } while(0);

/*
 * Benchmarks a vector operation which has no single result.
 */
#define BENCH_VO(func_name, ...) \
    do { \
        size_t start = read_csr(mcycle); \
        int rc = func_name(__VA_ARGS__); \
        size_t end = read_csr(mcycle); \
        printf(#func_name": %lu cycles. Return code: %d\n", end - start, rc); \
    } while(0);

/*
 * Compares the vector starting at value element wise with the vector at reference.
    Prints if they do not match.
 */
static inline void verify_vector(const float* value, const float* reference, const size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (value[i] != reference[i]) {
            printf("expected %f, but got %f\n", reference[i], value[i]);
        }
    }
};

/*
 * Sets all elements in the vector (of size n) to 0.0;
 */
static inline void clear_vector(float* arr, const size_t n) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = 0.0;
    }
}


#endif

