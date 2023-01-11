#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "add.h"
#include "benchmark.h"

__attribute__((noinline))
int maxpool2d_baseline(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);
__attribute__((noinline))
int maxpool2d_ssr(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);
__attribute__((noinline))
int maxpool2d_ssr_frep(double *a, size_t n0, size_t n1, size_t f0, size_t f1, size_t s0, size_t s1, double* result);

size_t pool_output_size(size_t n, size_t filter_size, size_t stride);

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    if (core_idx != 0) {
        return 0;
    }

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        size_t f0 = 5;
        size_t f1 = 4;
        size_t s0 = 3;
        size_t s1 = 2;

        size_t outn0 = sqrt_approx(size);
        size_t outn1 = sqrt_approx(size);

        size_t n0 = (outn0 - 1) * s0 + f0;
        size_t n1 = (outn1 - 1) * s1 + f1;

        double* x = allocate(n0 * n1, sizeof(double));
        double* result_ref = allocate(outn0 * outn1, sizeof(double));
        double* result = allocate(outn0 * outn1, sizeof(double));

        for (size_t i = 0; i < n0 * n1; i++) {
            x[i] = (double)i;
        }

        BENCH_VO(maxpool2d_baseline, x, n0, n1, f0, f1, s0, s1, result_ref);

        BENCH_VO(maxpool2d_ssr, x, n0, n1, f0, f1, s0, s1, result);
        verify_vector(result, result_ref, outn0 * outn1);
        clear_vector(result, outn0 * outn1);

        BENCH_VO(maxpool2d_ssr_frep, x, n0, n1, f0, f1, s0, s1, result);
        verify_vector(result, result_ref, outn0 * outn1);
        clear_vector(result, outn0 * outn1);
    }
}
