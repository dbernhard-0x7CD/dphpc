#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "benchmark.h"
#include "gemm.h"

int print_gemm_pattern(const double* a, size_t m, size_t n, size_t k, double* result, size_t result_len);
int print_other_gemm_pattern(const double* a, size_t m, size_t n, size_t k, double* result, size_t result_len);

double *x, *y, *result_ref, *result;

int main() {
    uint32_t core_idx = snrt_cluster_core_idx();
    uint32_t core_num = snrt_cluster_core_num() - 1; // -1 as there is one DM core

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2) {
        uint32_t sqrt = sqrt_approx(size);
        size_t M = sqrt / 2;
        size_t N = sqrt * 2;
        size_t K = sqrt / 2;
                            // sqrt / 2 * sqrt * 2 --> size
        x = allocate(M * N, sizeof(double));
                            // sqrt * 2 * sqrt / 2 --> size
        y = allocate(N * K, sizeof(double));
        result_ref = allocate(M * K, sizeof(double));
        result = allocate(M * K, sizeof(double));

        for (size_t i = 0; i < M * N; i++) {
            x[i] = (double)i;
        }

        for (size_t i = 0; i < N * K; i++) {
            y[i] = (double)i;
        }

        BENCH_VO(gemm_baseline, x, y, M, N, K, result_ref);
        
        BENCH_VO(gemm_ssr, x, y, M, N, K, result);
        verify_vector(result, result_ref, M * K);
        clear_vector(result, M * K);

        BENCH_VO(gemm_ssr_frep, x, y, M, N, K, result);
        verify_vector(result, result_ref, M * K);
        clear_vector(result, M * K);
    }
 
    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2) {
        uint32_t sqrt = sqrt_approx(size);
        size_t M = sqrt / 2;
        size_t N = sqrt * 2;
        size_t K = sqrt / 2;

        if (core_idx == 0) {
            for (size_t i = 0; i < M * N; i++) {
                x[i] = (double)i;
            }

            for (size_t i = 0; i < N * K; i++) {
                y[i] = (double)i;
            }
            gemm_baseline(x, y, M, N, K, result_ref);
        }
        snrt_cluster_hw_barrier();

        BENCH_VO_PARALLEL(gemm_parallel, x, y, M, N, K, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, M * K);
            clear_vector(result, M * K);
        }
        
        // if (core_idx == 0) {
        //     printf("A:\n");
        //     print_matrix(x, M, N);
        //     
        //     printf("B:\n");
        //     print_matrix(y, N, K);
        // }

        BENCH_VO_PARALLEL(gemm_ssr_parallel, x, y, M, N, K, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, M * K);
            clear_vector(result, M * K);
        }

        BENCH_VO_PARALLEL(gemm_ssr_frep_parallel, x, y, M, N, K, result);
        if (core_idx == 0) {
            verify_vector(result, result_ref, M * K);
            clear_vector(result, M * K);
        }
    }

    // Benchmark OMP
    __snrt_omp_bootstrap(core_idx);

    for(size_t size=LMQ_START_SIZE;size<=LMQ_SIZE;size*=2){
        uint32_t sqrt = sqrt_approx(size);
        size_t M = sqrt / 2;
        size_t N = sqrt * 2;
        size_t K = sqrt / 2;

        if (core_idx == 0) {
            for (size_t i = 0; i < M * N; i++) {
                x[i] = (double)i;
            }

            for (size_t i = 0; i < N * K; i++) {
                y[i] = (double)i;
            }
            gemm_baseline(x, y, M, N, K, result_ref);
        }

        BENCH_VO_OMP(gemm_omp, x, y, M, N, K, result);
        verify_vector(result, result_ref, M * K);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, M * K);
        
        BENCH_VO_OMP(gemm_ssr_omp, x, y, M, N, K, result);
        verify_vector(result, result_ref, M * K);
        // for(unsigned i = 0; i < size; i++) {
        //     printf("Value of result at %d is %f\n", i, result[i]);
        // }
        clear_vector(result, M * K);

        BENCH_VO_OMP(gemm_ssr_frep_omp, x, y, M, N, K, result);
        verify_vector(result, result_ref, M * K);
        clear_vector(result, M * K);
    }
    
    __snrt_omp_destroy(core_idx);

    return 0;
}
