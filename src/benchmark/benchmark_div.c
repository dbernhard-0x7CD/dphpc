#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "div.h"
#include "benchmark.h"


int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        // Initialize the input data
        double* x = allocate(size, sizeof(double));
        double* y = allocate(size, sizeof(double));
        double* result_ref = allocate(size, sizeof(double));
        double* result = allocate(size, sizeof(double));

        for (int i = 0; i < size; i++) {
            x[i] = (double)i;
            y[i] = (double)size - i + 1;
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

