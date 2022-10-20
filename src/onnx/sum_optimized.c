#include "printf.h"

#include "lmq.h"
#include "sum.h"

/*
 * Naive implementation of sum. Sums n elements starting at arr.
 */
float sum_optimized(float *arr, const size_t n) {

    register volatile float ft0 asm("ft0");
    asm volatile("" : "=f"(ft0));

    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*arr));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, arr);

    snrt_ssr_enable();

    register float s = 0;
    for (size_t i = 0; i < n; i++) {
        asm volatile(
            "fadd.s %[s], ft0, %[s] \n"
            : [s] "+f"(s) :: "ft0"
        );
    }

    snrt_ssr_disable();
    asm volatile("" :: "f"(ft0));

    return s;
}

// void gemm_seq_ssr(uint32_t N, uint32_t M, uint32_t K, double *A, uint32_t ldA,
//                   double *B, uint32_t ldB, double *C, uint32_t ldC) {
//     // Start of SSR region.
//     register volatile double ft0 asm("ft0");
//     register volatile double ft1 asm("ft1");
//     asm volatile("" : "=f"(ft0), "=f"(ft1));

//     snrt_ssr_loop_3d(SNRT_SSR_DM0, K, M / 4, N, 8, 0 * 4, 8 * ldA);
//     snrt_ssr_repeat(SNRT_SSR_DM0, 4);  // repeat value 4 times
//     snrt_ssr_loop_4d(SNRT_SSR_DM1, 4, K, M / 4, N, 8, 8 * ldB, 8 * 4, 0);
//     snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_3D, A);
//     snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_4D, B);
//     snrt_ssr_enable();

//     for (uint32_t n = 0; n < N; n++) {
//         for (uint32_t m = 0; m < M; m += 4) {
//             register double c0 = C[n * ldC + m + 0];
//             register double c1 = C[n * ldC + m + 1];
//             register double c2 = C[n * ldC + m + 2];
//             register double c3 = C[n * ldC + m + 3];
//             for (uint32_t k = 0; k < K; k++) {
//                 asm volatile(
//                     "fmadd.d %[c0], ft0, ft1, %[c0] \n"
//                     "fmadd.d %[c1], ft0, ft1, %[c1] \n"
//                     "fmadd.d %[c2], ft0, ft1, %[c2] \n"
//                     "fmadd.d %[c3], ft0, ft1, %[c3] \n"
//                     : [ c0 ] "+f"(c0), [ c1 ] "+f"(c1), [ c2 ] "+f"(c2),
//                       [ c3 ] "+f"(c3)::"ft0", "ft1",
//                       "ft2");  // clobber ft0..ft2 for 3 SSR streamers
//             }
//             C[n * ldC + m + 0] = c0;
//             C[n * ldC + m + 1] = c1;
//             C[n * ldC + m + 2] = c2;
//             C[n * ldC + m + 3] = c3;
//         }
//     }

//     // End of SSR region.
//     snrt_ssr_disable();
//     asm volatile("" ::"f"(ft0), "f"(ft1));
// }
