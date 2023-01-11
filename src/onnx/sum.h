
#ifndef LMQ_SUM_H
#define LMQ_SUM_H

#include <snrt.h>

int sum_baseline(double *arr, const size_t n, double* result);
int sum_ssr(double *arr, const size_t n, double* result);
int sum_ssr_frep(double *arr, const size_t n, double* result);

int sum_parallel(double *arr, const size_t n, double* result);
int sum_ssr_parallel(double *arr, const size_t n, double* result);
int sum_ssr_frep_parallel(double *arr, const size_t n, double* result);

// int sum_omp_fail(double *arr, const size_t n, double* result);
int sum_omp(double *arr, const size_t n, double* result);
int sum_ssr_omp(double *arr, const size_t n, double* result);
int sum_ssr_frep_omp(double *arr, const size_t n, double* result);

#endif
