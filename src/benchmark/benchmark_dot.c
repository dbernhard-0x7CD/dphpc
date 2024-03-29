#include <snrt.h>
#include "printf.h"
#include "stdlib.h"

#include "lmq.h"
#include "dot.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        printf("Running benchmark_dot\n");

        // x,y,xd,yd is input
        double* x = allocate(size, sizeof(double));
        double* y = allocate(size, sizeof(double));

        double* xd = allocate(size, sizeof(double));
        double* yd = allocate(size, sizeof(double));
        
        double result = 0.0;
        double result_ref = 0.0;

        double resultd = 0.0;
        double result_refd = 0.0;

        srandom(2);
        for (size_t i = 0; i < size; i++) {
            // x[i] = 1.0 * random() / __LONG_MAX__;
            x[i] = (double)i + 1.0;
            y[i] = (double)i + 1.0;
            xd[i] = (double)i + 1.0;
            yd[i] = (double)i + 1.0;
        }

        BENCH_VO(dot_baseline, x, y, size, &result_ref);
        // for (size_t i = 0; i < size; i++) {
        //     printf("Result at index %d is %f\n", i, result_ref[i]);
        // }
        printf("result_ref: %f\n", result_ref);

        BENCH_VO(ssr_dvec_dvec_dotp, xd, yd, size, &resultd);
        VERIFY_INT(result_ref, resultd, "Mismatch: expected %f but got %lf\n", result_ref, resultd);
        resultd = 0.0;

        BENCH_VO(ssr_dvec_dvec_dotpf, x, y, size, &result);
        VERIFY_INT(result_ref, result, "Mismatch: expected %f but got %f\n", result_ref, result);
        result = 0.0;

        BENCH_VO(dot_ssr, x, y, size, &result);
        VERIFY_INT(result_ref, result, "Mismatch: expected %f but got %f\n", result_ref, result);
        result = 0.0;

        BENCH_VO(dot_ssr_frep, x, y, size, &result);
        VERIFY_INT(result_ref, result, "Mismatch: expected %f but got %f\n", result_ref, result);
        result = 0.0;

    }

    return 0;
}

