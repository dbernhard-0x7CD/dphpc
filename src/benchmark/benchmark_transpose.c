#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_transpose\n");

    for(size_t size=32;size<=LMQ_SIZE;size*=2){


        int ox = (int)sqrt_approx(size);
        int rows = ox;
        int cols = ox;

        // x is input; result is output of the optimized functions
        float* x = allocate(rows * cols, sizeof(float));
        float* result_ref = allocate(rows * cols, sizeof(float));
        float* result = allocate(rows * cols, sizeof(float));

        for (size_t i = 0; i < rows; i++) {
            for (size_t j = 0; j < cols; j++) {
                x[i * cols + j] = i * cols + j;
            }
        }

        BENCH_VO(transpose_baseline, x, rows, cols, result_ref);
        // printf("Result_ref: \n");
        // print_matrix(result_ref, cols, rows);
        // for (size_t i = 0; i < size; i++) {
        //     printf("Result at index %d is %f\n", i, result_ref[i]);
        // }
        BENCH_VO(transpose_ssr, x, rows, cols, result);
        // printf("Result:\n");
        // print_matrix(result, cols, rows);
        verify_vector(result, result_ref, cols * rows);
        clear_vector(result, rows * cols);

        BENCH_VO(transpose_ssr_frep, x, rows, cols, result);
        // printf("Result:\n");
        // print_matrix(result, cols, rows);
        verify_vector(result, result_ref, cols * rows);
        clear_vector(result, rows * cols);

    }

    return 0;
}

