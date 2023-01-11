
#ifndef LMQ_COPY_H
#define LMQ_COPY_H

#include <snrt.h>

/*
 * Naive implementation of copy. Copies n elements starting at source to target
 */
int copy_snitch(double* source, const size_t n, double* target);

int copy_baseline(double* source, const size_t n, double* target);
int copy_ssr(double* source, const size_t n, double* target);
int copy_ssr_frep(double* source, const size_t n, double* target);

int copy_parallel(double* source, const size_t n, double* target);
int copy_ssr_parallel(double* source, const size_t n, double* target);
int copy_ssr_frep_parallel(double* source, const size_t n, double* target);

int copy_omp(double* source, const size_t n, double* target);
int copy_ssr_omp(double* source, const size_t n, double* target);
int copy_ssr_frep_omp(double* source, const size_t n, double* target);

#endif
