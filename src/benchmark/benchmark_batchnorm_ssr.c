#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int batchnorm_baseline(float *a, const size_t n, float* result);
__attribute__((noinline))
int batchnorm_ssr(float *a, const size_t n, float* result);
__attribute__((noinline))
int batchnorm_ssr_frep(float *a, const size_t n, float* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        // Initialize the input data
        float* x = allocate(size, sizeof(float));
        float* result_ref = allocate(size, sizeof(float));
        float* result = allocate(size, sizeof(float));

        for (size_t i = 0; i < size; i++) {
            x[i] = (float)i;
        }
        
        BENCH_VO(batchnorm_baseline, x, size, result_ref);

        // The tests are split in two binaries as if they run together the later one writes out wrong values (for some reason)

        BENCH_VO(batchnorm_ssr, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}

