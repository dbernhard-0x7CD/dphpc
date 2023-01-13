#include <stddef.h>
#include <x86intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <omp.h>


const size_t blocksize = 32;

size_t min(size_t a, size_t b) {
    if (a < b) return a;
    return b;
}
__attribute__((noinline))
int gemm_baseline(double* __restrict__ a, double* __restrict__ b, const size_t w, const size_t h, double* __restrict__ result) {
    for (size_t i = 0; i < h; ++i) {
        for (size_t j = 0; j < w; ++j) {
            double acc = 0.0;
            for (size_t k = 0; k < h; ++k) {
                acc += a[i * w + k] * b[k * w + j];
            }
            result[i * w + j] = acc; // result_{i, j} = acc
        }
    }
    return 0;
}

/* Very basic. 16ms */
__attribute__((noinline))
int gemm_omp(double* __restrict__ a, double* __restrict__ b, const size_t w, const size_t h, double* __restrict__ result) {
#pragma omp parallel for
    for (size_t i = 0; i < h; ++i) {
        for (size_t j = 0; j < w; ++j) {
            double acc = 0;
            for (size_t k = 0; k < h; ++k) {
                acc += a[i * w + k] * b[k * w + j];
            }
            result[i * w + j] = acc; // result_{i, j} = acc
        }
    }

    return 0;
}

// 11ms
__attribute__((noinline))
int gemm_omp_opt(double* __restrict__ a, double* __restrict__ b, const size_t w, const size_t h, double* __restrict__ result) {
#pragma omp parallel for
    for (size_t i = 0; i < h; ++i) {
        for (size_t k = 0; k < h; ++k) {
            double val = a[i * w + k];
            for (size_t j = 0; j < w; ++j) {
                result[i * w + j] += val * b[k * w + j];
            }
        }
    }

    return 0;
}

/*
 * Optimizations: Blocking and good access pattern.
 */
__attribute__((noinline))
int gemm_omp_opt_blocking(double* __restrict__ a, double* __restrict__ b, const size_t w, const size_t h, double* __restrict__ result) {
    for (size_t iB = 0; iB < h; iB += blocksize) {
        for (size_t jB = 0; jB < w; jB += blocksize) {
            for (size_t kB = 0; kB < h; kB += blocksize) {
            #pragma omp parallel for
                for (size_t i = iB; i < min(iB + blocksize, h); ++i) {
                    for (size_t k = kB; k < min(h, kB + blocksize); ++k) {
                        double val = a[i * w + k];
                        for (size_t j = jB; j < min(jB + blocksize, w); ++j) {
                            result[i * w + j] += val * b[k * w + j];
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * x2 must be after x1. Returns the difference in microseconds.
 */
long diff_in_us(struct timespec x1, struct timespec x2) {

    if (x1.tv_sec == x2.tv_sec) { return (x2.tv_nsec - x1.tv_nsec) / 1000; };

     return (x2.tv_sec - x1.tv_sec) * 1000000 + 1000000 - (x1.tv_nsec / 1000) + (x2.tv_nsec / 1000);
}

void print_matrix(double* matrix, size_t w, size_t h) {
    for (size_t i = 0; i < h; i++) {
        for (size_t j = 0; j < w; j++) {
            printf("%f\t", matrix[i * w + j]);
        }
        printf("\n");
    }
}

int verify(double* a, double* b, size_t w, size_t h) {
    for (size_t i = 0; i < h; i++) {
        for (size_t j = 0; j < w; j++) {
            if ((fabs(a[i * w + j] - b[i * w + j])) > 0.1 * fabs(a[i * w + j])) {
                printf("mismatch at %ld %ld\n", i, j);
                return 1;
            }
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    printf("Starting measurement\n");

    struct timespec start, end;
    
    double *x, *y, *result, *result_ref;
    size_t size = 10 * pow(2.0, 12);
    // size_t size = 9;
    size_t runs = 5;

    size_t h = (int)sqrt(size);
    size_t w = (int)sqrt(size);

    x = (double *) malloc(h * w * sizeof(double));
    y = (double *) malloc(h * w * sizeof(double));
    result = (double *) malloc(h * w * sizeof(double));
    result_ref = (double *) malloc(h * w * sizeof(double));
    
    for (size_t i = 0; i < h; i++) {
        for (size_t j = 0; j < w; j++) {
            x[i * w + j] = i * w + j + 1.0;
            y[i * w + j] = i * w + j + 1.0;
        }
    }
    // Debugging statements
    // print_matrix(x, w, h);
    // print_matrix(y, w, h);
    // printf("\n");
    gemm_baseline(x, y, w, h, result_ref);
    
    for (size_t i = 0; i < runs; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);

        // The following was used for single core
        // gemm_baseline(x, y, w, h, result);

        // The following was used for multi-core
        gemm_omp_opt_blocking(x, y, w, h, result);

        clock_gettime(CLOCK_MONOTONIC, &end);

        long us_duration = diff_in_us(start, end);
        printf("Took %ld us \n", us_duration);
    }

    if (0 == verify(result, result_ref, w, h)) {
        printf("VERIFIED\n");
    }

//    print_matrix(result, w, h);
//    print_matrix(result_ref, w, h);

    return 0;
}
