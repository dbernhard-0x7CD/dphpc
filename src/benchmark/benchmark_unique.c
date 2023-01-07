#include <snrt.h>
#include "printf.h"
#include <stdlib.h>

#include "benchmark.h"
#include "lmq.h"

__attribute__((noinline)) int unique_baseline(float* arr, const size_t n, float* result);
__attribute__((noinline)) int unique_ssr(float* arr, const size_t n, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for (size_t size = LMQ_START_SIZE; core_idx == 0 && size <= LMQ_SIZE; size *= 2) {
        // Initialize the input data
        float* x = allocate(size, sizeof(float));

        for (size_t i = 0; i < size; i++) {
            x[i] = random() % (size / 2);  // add every element multiple times
        }

        // Count number of unique elements (so we know the size of the result):
        /*size_t n_unique = 0;
        for(size_t i = 0; i < size; i++) {
            int unique = 1;
            for(size_t j = i+1; j < size; j++) {
                if(x[i] == x[j]) {
                    unique = 0;
                }
            }
            n_unique += unique;
        }*/
        // NO LONGER NEEDED


        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        // Prepare x for ssr:
        float* x_for_ssr = allocate(size + (size * (size - 1) / 2), sizeof(float));

        size_t index = 0;
        for (size_t i = 0; i < size; i++) {
            x_for_ssr[index++] = x[i];
            for (size_t j = i + 1; j < size; j++) {
                x_for_ssr[index++] = x[j];
            }
        }

        BENCH_VO(unique_baseline, x, size, result_ref);

        BENCH_VO(unique_ssr, x_for_ssr, size, result);

        verify_vector(result, result_ref, size);
    }

    return 0;
}
