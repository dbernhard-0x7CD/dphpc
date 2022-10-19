
#include "printf.h"

#include "lmq.h"
#include "sum.h"

/*
 * Compiler optimized version of sum. Sums n elements starting at arr.
 */
float sum_baseline_O3(float *arr, const size_t n) {
    float s = 0;

    for (int i = 0; i < n; i++) {
        s += arr[i];
    }

    return s;
}
