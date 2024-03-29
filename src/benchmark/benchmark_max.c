#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "max.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_max\n");

        // x is input; result is output of the optimized functions
        double *x = allocate(size, sizeof(double));
        double result_ref;
        double result;

        srandom(2);
        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0 * random() / __LONG_MAX__;
        }

        // For debugging purposes
        // for (size_t i = 0; i < size; i++) {
        //     printf("Input at index %d is %f\n", i, x[i]);
        // }

        BENCH(max_baseline, x, size, &result_ref);
        // printf("Result is: %f\n", result_ref);
        
        BENCH(max_ssr, x, size, &result);
        VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d\n", result_ref, result);
        // printf("Result is: %f\n", result);
        result = -1;

        BENCH(max_ssr_frep, x, size, &result);
        VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d\n", result_ref, result);
        // printf("Result is: %f\n", result);
    }

    return 0;
}

