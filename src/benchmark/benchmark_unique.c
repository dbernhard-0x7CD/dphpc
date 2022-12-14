#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "benchmark.h"

__attribute__((noinline))
int unique_baseline(float* arr, const size_t n, float* result);
__attribute__((noinline))
int unique_ssr(float* arr, const size_t n, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){

        // Initialize the input data
        float* x = allocate(size, sizeof(float));
        float* result_ref = allocate(size/2, sizeof(float));
        float* result = allocate(size/2, sizeof(float));

        for(size_t i = 0; i < size; i++) {
            x[i] = 1.0 * (i%(size/2)); // add every element twice
        }

        float* x_for_ssr = allocate(size + (size*(size-1)/2), sizeof(float));

        size_t index = 0;
        for(size_t i = 0; i < size; i++) {
            x_for_ssr[index++] = x[i];
            for(size_t j = i+1; j < size; j++) {
                x_for_ssr[index++] = x[j];
            }
        }

        BENCH_VO(unique_baseline, x, size, result_ref);

        BENCH_VO(unique_ssr, x_for_ssr, size, result);

        verify_vector(result, result_ref, size/2);

    }

    return 0;
}

