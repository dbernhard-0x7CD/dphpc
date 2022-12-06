#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "benchmark.h"


int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=32;size<=LMQ_SIZE;size*=2){

        
        // only run on 1 core
        if (core_idx != 0) return 1;

        // Initialize the input data
        int* x = allocate(size, sizeof(int));
        int* y = allocate(size, sizeof(int));
        int* result_ref = allocate(size, sizeof(int));
        int* result = allocate(size, sizeof(int));

        for (int i = 0; i < size; i++) {
            x[i] = (int)i;
            y[i] = (int)i;
        }
        
        BENCH_VO(and_baseline, x, y, size, result_ref);

        BENCH_VO(and_ssr, x, y, size, result);
        verify_vector_int(result, result_ref, size);
        clear_vector_int(result, size);

        BENCH_VO(and_ssr_frep, x, y, size, result);
        verify_vector_int(result, result_ref, size);
        clear_vector_int(result, size);
    }
 
    return 0;
}

