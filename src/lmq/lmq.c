#include "lmq.h"
#include <printf.h>

#include <snrt.h>

void* cur_memory = NULL;

void* allocate(const size_t n, const size_t element_size) {
    if (cur_memory == NULL) {
        cur_memory = (void*) snrt_global_memory().start;
    }
    void* now = cur_memory;

    // This is to have some spacing as SSR sometimes writes one more
    // element to the stream which may be outide an array.
    cur_memory += (n*element_size + element_size);

    return now;
}

/*
 * Prints a matrix which is in the form [rows x columns] and row major inside arr.
 */
void print_matrix(const double* arr, const size_t rows, const size_t cols) {
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            printf("%0.02f,\t", arr[i * cols + j]);
        }
        printf("\n");
    }
}

/*
 * Calculates an approximation of the square root of a.
 * Needed as the fsqrt instruction is not implemented on the snitch. 
 */
double sqrt_approx(double a) {
    double x = 1.f;
    for (int i = 0; i < 5; ++i) {
        x = 0.5f * (x + a / x);
    }
    return x;
}
