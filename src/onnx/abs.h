#ifndef LMQ_ABS_H
#define LMQ_ABS_H

#include <snrt.h>

int fabs_baseline(double *arr, const size_t n, double *result);
int fabs_ssr(double *arr, const size_t n, double *result);
int fabs_ssr_frep(double *arr, const size_t n, double *result);

int fabs_parallel(double *arr, const size_t n, double *result);
int fabs_ssr_parallel(double *arr, const size_t n, double *result);
int fabs_ssr_frep_parallel(double *arr, const size_t n, double *result);

int fabs_omp(double *arr, const size_t n, double *result);
int fabs_ssr_omp(double *arr, const size_t n, double *result);
int fabs_ssr_frep_omp(double *arr, const size_t n, double *result);

#endif
