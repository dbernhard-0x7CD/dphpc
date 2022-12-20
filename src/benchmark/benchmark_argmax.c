#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "argmax.h"
#include "benchmark.h"

float *x;
int result, result_ref;

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_argmax\n");

        // x is input; result is output of the optimized functions
        x = allocate(size, sizeof(float));

        srandom(2);
        for (size_t i = 0; core_idx == 0 && i < size; i++) {
            x[i] = 1.0 * size * (1.0 * random() / __LONG_MAX__);
        }

        // For debugging purposes
        // for (size_t i = 0; i < size; i++) {
        //     printf("Input at index %d is %f\n", i, x[i]);
        // }

        BENCH_VO(argmax_baseline, x, size, &result_ref);
        
        BENCH_VO(argmax_ssr, x, size, &result);
        VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d (ref: %f; actual: %f)\n", result_ref, result, x[result_ref], x[result]);
        result = -1;

        // BENCH_VO(argmax_ssr_frep, x, size, &result);
        // VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d\n", result_ref, result);
        // This is expected as no FREP implementation exists (for now)
    }

    for (size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2) {
        argmax_baseline(x, size, &result_ref);

        BENCH_VO_PARALLEL(argmax_parallel, x, size, &result);
        if (core_idx == 0) {
            VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d (ref: %f; actual: %f)\n", result_ref, result, x[result_ref], x[result]);
            result = -1;
        }

        BENCH_VO_PARALLEL(argmax_ssr_parallel, x, size, &result);
        if (core_idx == 0) {
            VERIFY_INT(result, result_ref, "Mismatch: expected %d but got %d (ref: %f; actual: %f)\n", result_ref, result, x[result_ref], x[result]);
            result = -1;
        }
    }
    return 0;
}

