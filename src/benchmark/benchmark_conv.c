#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int conv_baseline(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result);
__attribute__((noinline))
int conv_ssr(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result);
__attribute__((noinline))
int conv_ssr_frep(float *a, float* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, float* result);

__attribute__((noinline))
int conv2d_baseline(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result);
__attribute__((noinline))
int conv2d_ssr(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result);
__attribute__((noinline))
int conv2d_ssr_frep(float *a, float* filter, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, size_t d0, size_t d1, float* result);

size_t conv_output_size(size_t n, size_t filter_size, size_t stride, size_t dilation);
// void print_pattern(float *a, size_t n, size_t filter_size, size_t stride, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) {
        return 0;
    }

    for(size_t size=LMQ_START_SIZE; size<=LMQ_SIZE;size*=2){
        size_t filter_size = 5;
        size_t stride = 2;
        size_t dilation = 2;

        size_t input_size = (size - 1) * stride + (1 + (filter_size - 1) * dilation);

        // Initialize the input data
        float* x = allocate(input_size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        float* filter = allocate(filter_size, sizeof(float));

        for (size_t i = 0; i < input_size; i++) {
            x[i] = (float)i;
        }

        for (size_t i = 0; i < filter_size; ++i) {
            filter[i] = 3.f - i;
        }

        BENCH_VO(conv_baseline, x, filter, input_size, filter_size, stride, dilation, result_ref);

        BENCH_VO(conv_ssr, x, filter, input_size, filter_size, stride, dilation, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(conv_ssr_frep, x, filter, input_size, filter_size, stride, dilation, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}



