#include <snrt.h>
#include "printf.h"
#include <stdlib.h>

#include "benchmark.h"
#include "lmq.h"

__attribute__((noinline)) int unique_baseline(double* arr, const size_t n, double* result);
__attribute__((noinline)) int unique_ssr(double* arr, const size_t n, double* result);
__attribute__((noinline)) int unique_parallel(double* arr, const size_t n, double* result);

double *x, *result, *result_ref;

int main() {

    uint32_t core_idx = snrt_global_core_idx();
    uint32_t core_num = snrt_cluster_core_num()-1; // -1 as there is one DM core 

    printf("Running benchmark_unique\n");

    for (size_t size = LMQ_START_SIZE; core_idx == 0 && size <= LMQ_SIZE; size *= 2) {

        // Initialize the input data
        x = allocate(size, sizeof(double));
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


        result = allocate(size, sizeof(double));
        result_ref = allocate(size, sizeof(double));

        // Prepare x for ssr:
        double* x_for_ssr = allocate(size + (size * (size - 1) / 2), sizeof(double));
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
        clear_vector(result, size);
        clear_vector(result_ref, size);
    }


    snrt_cluster_hw_barrier();
    
    for (size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2) {
        
        if(core_idx == 0) {
            
            /* Since the function generates different results based on size
             * (even with the same input), we must ensure that it doesn't 
             * get overridden before we verify below, thus we always want to 
             * run the baseline by core 0:
             */
            unique_baseline(x, size, result_ref);

        }

        snrt_cluster_hw_barrier();
        
        BENCH_VO_PARALLEL(unique_parallel, x, size, result);
        
        if(core_idx == 0) {

            verify_vector(result, result_ref, size);
            clear_vector(result, size);

        }
    }

    return 0;
}