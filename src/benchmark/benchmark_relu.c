#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "relu.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        double* x = allocate(size, sizeof(double));
        double* result_ref = allocate(size, sizeof(double));
        double* result = allocate(size, sizeof(double));

        for (size_t i = 0; i < size; i++) {
            x[i] = (double)i - (double)size / 2;
        }

        double alpha = 0.1;

        BENCH_VO(leakyrelu_baseline, x, size, alpha, result_ref);


        BENCH_VO(leakyrelu_ssr, x, size, alpha, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }
 
    return 0;
}

