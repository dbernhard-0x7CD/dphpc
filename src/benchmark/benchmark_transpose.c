#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_transpose\n");
        
        int ox = (int)sqrt_approx(size);
        int rows = ox;
        int cols = ox;

        // x is input; result is output of the optimized functions
        double* x = allocate(rows * cols, sizeof(double));
        double* result_ref = allocate(rows * cols, sizeof(double));
        double* result = allocate(rows * cols, sizeof(double));

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

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2) {
        // TODO
    }
    return 0;
}

