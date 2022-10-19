#include "printf.h"

#include "lmq.h"

/*
 * Naive implementation of add. Adds a and b element wise into result.
 */
int add_baseline(const float *a, const float* b, const size_t n, float* result) {
    for (int i = 0; i < n; i++) {
        result[i] = a[i] + b[i];
    }

    return 0;
}
