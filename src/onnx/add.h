
#ifndef LMQ_ADD_H
#define LMQ_ADD_H

#include <snrt.h>

int add_baseline(double* a, double* b, const size_t n, double* result);
int add_ssr(double *a, double *b, const size_t n, double *result);
int add_ssr_frep(double *a, double *b, const size_t n, double *result);

int add_parallel(double *a, double *b, const size_t n, double *result);
int add_ssr_parallel(double *a, double *b, const size_t n, double *result);
int add_ssr_frep_parallel(double *a, double *b, const size_t n, double *result);

int add_omp(double *a, double *b, const size_t n, double *result);
int add_ssr_omp(double *a, double *b, const size_t n, double *result);
int add_ssr_frep_omp(double *a, double *b, const size_t n, double *result);

#endif
