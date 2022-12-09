#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "div.h"
#include "benchmark.h"


int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    if (core_idx != 0) return 1;

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){


        // Initialize the input data
        float* x = allocate(size, sizeof(float));
        float* y = allocate(size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        for (int i = 0; i < size; i++) {
            x[i] = (float)i;
            y[i] = (float)size - i + 1;
        }
        
        BENCH_VO(div_baseline, x, y, size, result_ref);

        BENCH_VO(div_ssr, x, y, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(div_ssr_frep, x, y, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }
 
    return 0;
}

