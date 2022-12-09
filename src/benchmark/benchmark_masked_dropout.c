#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "masked_dropout.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    printf("Running benchmark_masked_dropout\n");

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){

        // x is input; result is output of the optimized functions
        float* x = allocate(size, sizeof(float));
        float* mask = allocate(size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        const float ratio = 0.5; // probability of dropout

        srandom(2);
        for (size_t i = 0; i < size; i++) {
            x[i] = 1.0 * random() / __LONG_MAX__;
        }

        for (size_t i = 0; i < size; i++) {
            if (1.0 * rand() / RAND_MAX <= ratio){
                mask[i] = 0;
            } else {
                mask[i] = 1;
            }
        }

        // For debugging purposes
        // for (size_t i = 0; i < size; i++) {
        //     printf("Input at index %d is %f\n", i, x[i]);
        // }

        BENCH(masked_dropout_baseline, x, mask, size, ratio, result_ref);


        BENCH(masked_dropout_ssr, x, mask, size, ratio, result);

        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        // TODO: check how to write and read in a register with frep
        BENCH(masked_dropout_ssr_frep, x, mask, size, ratio, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

    }

    return 0;
}