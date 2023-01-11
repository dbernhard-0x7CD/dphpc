#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int maxpool_baseline(double *a, size_t n, size_t filter_size, size_t stride, double* result);
__attribute__((noinline))
int maxpool_ssr(double *a, size_t n, size_t filter_size, size_t stride, double* result);
__attribute__((noinline))
int maxpool_ssr_frep(double *a, size_t n, size_t filter_size, size_t stride, double* result);

__attribute__((noinline))
int maxpool2d_baseline(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);
__attribute__((noinline))
int maxpool2d_ssr(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);
__attribute__((noinline))
int maxpool2d_ssr_frep(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);

size_t pool_output_size(size_t n, size_t filter_size, size_t stride);
void print_pattern(double *a, size_t n, size_t filter_size, size_t stride, double* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        size_t filter_size = 5;
        size_t stride = 2;

        size_t input_size = (size - 1) * stride + filter_size;

        // Initialize the input data
        double* x = allocate(input_size, sizeof(double));
        double* result_ref = allocate(size, sizeof(double));
        double* result = allocate(size, sizeof(double));

        for (size_t i = 0; i < input_size; i++) {
            x[i] = (double)i;
        }

        BENCH_VO(maxpool_baseline, x, input_size, filter_size, stride, result_ref);


        BENCH_VO(maxpool_ssr, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(maxpool_ssr_frep, x, input_size, filter_size, stride, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}



