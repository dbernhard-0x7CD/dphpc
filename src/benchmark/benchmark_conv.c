#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int conv_baseline(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);
__attribute__((noinline))
int conv_ssr(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);
__attribute__((noinline))
int conv_ssr_frep(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);

__attribute__((noinline))
int conv_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);
__attribute__((noinline))
int conv_ssr_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);
__attribute__((noinline))
int conv_ssr_frep_parallel(double *a, double* filter, size_t n, size_t filter_size, size_t stride, size_t dilation, double* result);

size_t conv_output_size(size_t n, size_t filter_size, size_t stride, size_t dilation);
// void print_pattern(double *a, size_t n, size_t filter_size, size_t stride, double* result);

double *x, *result, *result_ref, *filter;

int main() {
    uint32_t core_idx = snrt_global_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    size_t filter_size = 5;
    size_t stride = 2;
    size_t dilation = 2;

    for(size_t size=LMQ_START_SIZE; size<=LMQ_SIZE && core_idx == 0;size*=2){
        size_t input_size = (size - 1) * stride + (1 + (filter_size - 1) * dilation);

        // Initialize the input data
        x = allocate(input_size, sizeof(double));
        result_ref = allocate(size, sizeof(double));
        result = allocate(size, sizeof(double));

        filter = allocate(filter_size, sizeof(double));

        for (size_t i = 0; i < input_size; i++) {
            x[i] = (double)i;
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

    snrt_cluster_hw_barrier();

    /* Benchmark parallel */
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        size_t input_size = (size - 1) * stride + (1 + (filter_size - 1) * dilation);
        conv_baseline(x, filter, input_size, filter_size, stride, dilation, result_ref);

        BENCH_VO_PARALLEL(conv_parallel, x, filter, input_size, filter_size, stride, dilation, result);
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("res at %d is %f\n", i, result[i]);
        // }

        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(conv_ssr_parallel, x, filter, input_size, filter_size, stride, dilation, result);
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("conv_ssr_parallel res at %d is %f\n", i, result[i]);
        // }
        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }

        BENCH_VO_PARALLEL(conv_ssr_frep_parallel, x, filter, input_size, filter_size, stride, dilation, result);
        // for (size_t i = 0; core_idx == 0 && i < size; i++) {
        //     printf("conv_ssr_frep_parallel res at %d is %f\n", i, result[i]);
        // }
        if (core_idx == 0) {
            verify_vector(result, result_ref, size);
            clear_vector(result, size);
        }
    }
    return 0;
}



