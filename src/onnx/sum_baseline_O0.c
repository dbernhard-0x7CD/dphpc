
#include "printf.h"

#include "lmq.h"
#include "sum.h"

/*
 * Naive implementation of sum. Sums n elements starting at arr.
 */
float sum_baseline(float *arr, const size_t n) {
    float s = 0;

    for (int i = 0; i < n; i++) {
        s += arr[i];
    }

    return s;
}
