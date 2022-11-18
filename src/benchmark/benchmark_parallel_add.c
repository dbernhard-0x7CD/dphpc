#include <snrt.h>
#include "printf.h"
#include "perf_cnt.h"

#include "lmq.c"
#include "parallel_add.h"
#include "benchmark.h"


int main() {
    uint32_t core_idx = snrt_global_core_idx();

    uint32_t cycles, dma_busy;


    // Not completly sure if we have to do it like this ...
    float *ptr = (float *)snrt_cluster_memory().start;

    float *x = ptr;
    ptr += size;
    float *y = ptr;
    ptr += size;
    float *result = ptr;
    ptr += size;

    uint32_t max_cores = 5;
    uint32_t elements_per_core = size / max_cores;
    float* result_ref = allocate(size, sizeof(float));;

    // Do we actually need to do this?
    if (core_idx == 0) {
        printf("Global core number: %i \n", snrt_global_core_num());
        // snrt_dma_txid_t test_cores = snrt_dma_start_1d(max_cores, cores, sizeof(uint32_t));
        // snrt_dma_txid_t test_cores = snrt_dma_start_1d(max_cores, elements_pc, sizeof(uint32_t));

        printf("Using %i cores, each computing %i elements\n", elements_per_core);

        // Not completly sure if we need do this here...
        // snrt_dma_start_tracking();
        // test = snrt_dma_start_1d();

        float* xx = allocate(size, sizeof(float));
        float* yy = allocate(size, sizeof(float));

        for (size_t i = 0; i < size; i++) {
            xx[i] = (float)i;
            yy[i] = (float)i;
        }

        BENCH_VO(parallel_add_baseline, x, y, size, result_ref);

        snrt_reset_perf_counter(SNRT_PERF_CNT0);
        snrt_reset_perf_counter(SNRT_PERF_CNT1);
        snrt_start_perf_counter(SNRT_PERF_CNT0, SNRT_PERF_CNT_CYCLES, 0);
        snrt_start_perf_counter(SNRT_PERF_CNT1, SNRT_PERF_CNT_DMA_BUSY, 0);


        // Writig xx (src) into the DMA (direct memory access) array of x
        // I.e. share the input of x to all cores
        snrt_dma_txid_t test_x = snrt_dma_start_1d(x, xx, sizeof(float) * size);
        snrt_dma_txid_t test_y= snrt_dma_start_1d(y, yy, sizeof(float) * size);
        for (size_t i = 0; i < size; i++) {
            printf("%i ", (int)x[i]);
        }
        printf("\n");

        for (size_t i = 0; i < size; i++) {
            printf("%i ", (int)y[i]);
        }
        printf("\n");

        for (size_t i = 0; i < size; i++) {
            printf("%i ", (int) result_ref[i]);
        }
        printf("\n");
        snrt_dma_wait_all();
    }

    snrt_global_barrier();

    
    // For testing purposes
    if (core_idx < max_cores){
        uint32_t offset = core_idx * elements_per_core;
        float *local_result = allocate(elements_per_core, sizeof(float));
        // printf("Core %i with %i elements to compute and offset %i. First element %f\n", core_idx, elements_per_core, offset, x[offset]);
        parallel_add_ssr(x + offset, y + offset, elements_per_core, local_result);

        snrt_dma_txid_t test_restult = snrt_dma_start_1d(result + offset, local_result, sizeof(float) * elements_per_core);
        snrt_dma_wait_all();

        if (core_idx == 1){
            for (size_t i = 0; i < size; i++) {
                printf("%i ", (int) x[i]);
            }
            printf("\n");

            for (size_t i = 0; i < size; i++) {
                printf("%i ", (int) y[i]);
            }
            printf("\n");

            for (size_t i = 0; i < size; i++) {
                printf("%i ", (int) result[i]);
            }
            printf("\n");
        }
        // printf("Core %i finished\n", core_idx);
    } else {
        printf("Core %i is idle\n", core_idx);
    }

    snrt_global_barrier();
    if (core_idx == 0) {
        printf("Comparing in core %i\n", core_idx);
        for (size_t i = 0; i < size; i++) {
            printf("%i ", (int) result_ref[i]);
        }
        printf("\n");
        verify_vector(result, result_ref, size);
        clear_vector(result, size);
        printf("Finished in core %i\n", core_idx);
    }
    snrt_global_barrier();
    
    // BENCH_VO(add_ssr, x, y, size, result);
    // verify_vector(result, result_ref, size);
    // clear_vector(result, size);

    // BENCH_VO(add_ssr_frep, x, y, size, result);
    // verify_vector(result, result_ref, size);
    // clear_vector(result, size);

    if (snrt_global_core_idx() == 0) {
        snrt_stop_perf_counter(SNRT_PERF_CNT0);
        snrt_stop_perf_counter(SNRT_PERF_CNT1);

        cycles = snrt_get_perf_counter(SNRT_PERF_CNT0);
        dma_busy = snrt_get_perf_counter(SNRT_PERF_CNT1);
        printf("perf: %d/%d dma/total\n", dma_busy, cycles);
    }

    snrt_global_barrier();

 
    return 0;
}

