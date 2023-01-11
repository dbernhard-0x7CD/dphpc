#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int batchnorm_baseline(double *a, const size_t n, double* result);
__attribute__((noinline))
int batchnorm_ssr(double *a, const size_t n, double* result);
__attribute__((noinline))
int batchnorm_ssr_frep(double *a, const size_t n, double* result);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        // Initialize the input data
        double* x = allocate(size, sizeof(double));
        double* result_ref = allocate(size, sizeof(double));
        double* result = allocate(size, sizeof(double));

        for (size_t i = 0; i < size; i++) {
            x[i] = (double)i;
        }
        
        BENCH_VO(batchnorm_baseline, x, size, result_ref);

        // The tests are split in two binaries as if they run together the later one writes out wrong values (for some reason)

        BENCH_VO(batchnorm_ssr, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);

        BENCH_VO(batchnorm_ssr_frep, x, size, result);
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
    }

    return 0;
}

