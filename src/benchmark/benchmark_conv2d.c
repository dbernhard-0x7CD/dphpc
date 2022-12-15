#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

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
        size_t f0 = 5;
        size_t f1 = 4;
        size_t s0 = 3;
        size_t s1 = 2;
        size_t d0 = 2;
        size_t d1 = 1;

        size_t outn0 = sqrt_approx(size);
        size_t outn1 = sqrt_approx(size);

        size_t n0 = (outn0 - 1) * s0 + (1 + (f0 - 1) * d0);
        size_t n1 = (outn1 - 1) * s1 + (1 + (f1 - 1) * d1);

        float* x = allocate(n0 * n1, sizeof(float));
        float* result_ref = allocate(outn0 * outn1, sizeof(float));
        float* result = allocate(outn0 * outn1, sizeof(float));
        float* filter = allocate(f0 * f1, sizeof(float));

        for (size_t i = 0; i < n0 * n1; i++) {
            x[i] = (float)i;
        }

        for (size_t i = 0; i < f0 * f1; ++i) {
            filter[i] = 10.f - i;
        }

        BENCH_VO(conv2d_baseline, x, filter, n0, n1, f0, f1, s0, s1, d0, d1, result_ref);

        BENCH_VO(conv2d_ssr, x, filter, n0, n1, f0, f1, s0, s1, d0, d1, result);
        verify_vector(result, result_ref, outn0 * outn1);
        clear_vector(result, outn0 * outn1);

        BENCH_VO(conv2d_ssr_frep, x, filter, n0, n1, f0, f1, s0, s1, d0, d1, result);
        verify_vector(result, result_ref, outn0 * outn1);
        clear_vector(result, outn0 * outn1);
    }

    return 0;
}



