#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int maxpool_baseline(float *a, size_t n, size_t filter_size, size_t stride, float* result);
__attribute__((noinline))
int maxpool_ssr(float *a, size_t n, size_t filter_size, size_t stride, float* result);
__attribute__((noinline))
int maxpool_ssr_frep(float *a, size_t n, size_t filter_size, size_t stride, float* result);

__attribute__((noinline))
int maxpool2d_baseline(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result);
__attribute__((noinline))
int maxpool2d_ssr(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result);
__attribute__((noinline))
int maxpool2d_ssr_frep(float *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, float* result);

size_t pool_output_size(size_t n, size_t filter_size, size_t stride);
void print_pattern(float *a, size_t n, size_t filter_size, size_t stride, float* result);

int run2d() {
    size_t f0 = 5;
    size_t f1 = 4;
    size_t s0 = 3;
    size_t s1 = 2;

    size_t outn0 = 300;
    size_t outn1 = 500;

    size_t n0 = (outn0 - 1) * s0 + f0;
    size_t n1 = (outn1 - 1) * s1 + f1;

    float* x = allocate(n0 * n1, sizeof(float));
    float* result_ref = allocate(outn0 * outn1, sizeof(float));
    float* result = allocate(outn0 * outn1, sizeof(float));

    for (size_t i = 0; i < n0 * n1; i++) {
        x[i] = (float)i;
    }

    printf("real size: %lu\n", n0 * n1);
    BENCH_VO(maxpool2d_baseline, x, n0, n1, f0, f1, s0, s1, result_ref);

    BENCH_VO(maxpool2d_ssr, x, n0, n1, f0, f1, s0, s1, result);
    verify_vector(result, result_ref, outn0 * outn1);
    clear_vector(result, outn0 * outn1);

    BENCH_VO(maxpool2d_ssr_frep, x, n0, n1, f0, f1, s0, s1, result);
    verify_vector(result, result_ref, outn0 * outn1);
    clear_vector(result, outn0 * outn1);
}

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    for(size_t size=32;size<=LMQ_SIZE;size*=2){


        size_t filter_size = 5;
        size_t stride = 2;

        size_t input_size = (size - 1) * stride + filter_size;

        // Initialize the input data
        float* x = allocate(input_size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        for (size_t i = 0; i < size; i++) {
            x[i] = (float)i;
        }

        BENCH_VO(maxpool_baseline, x, input_size, filter_size, stride, result_ref);


        BENCH_VO(maxpool_ssr, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        // verify for this fails if the above "batchnorm_ssr" is executed
        BENCH_VO(maxpool_ssr_frep, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        for (size_t i = 0; i < input_size; i++) {
            x[i] = (float)i;
        }

        BENCH_VO(maxpool_baseline, x, input_size, filter_size, stride, result_ref);


        BENCH_VO(maxpool_ssr, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(maxpool_ssr_frep, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    run2d();

    return 0;
}



