#ifndef LMQ_DROPOUT_H
#define LMQ_DROPOUT_H

#include <snrt.h>
#include <stdlib.h>
#include <float.h>

#include "printf.h"

#include <math.h>

int dropout_baseline(const double* arr, const size_t n, const double ratio, double* result);
int dropout_baseline_test(const double* arr, const size_t n, const double ratio, double* result);
int dropout_ssr(const double* arr, const size_t n, const double ratio, double* result);
int dropout_ssr_test(const double* arr, const size_t n, const double ratio, double* result);
int dropout_ssr_frep(const double* arr, const size_t n, const double ratio, double* result);

#endif