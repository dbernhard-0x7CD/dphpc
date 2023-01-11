#ifndef LMQ_MASKED_DROPOUT_H
#define LMQ_MASKED_DROPOUT_H

#include <snrt.h>
#include <stdlib.h>

#include <math.h>

int masked_dropout_baseline(const double* arr, const double* mask, const size_t n, const double ratio, double* result);
int masked_dropout_ssr(const double* arr, const double* mask, const size_t n, const double ratio, double* result);
int masked_dropout_ssr_frep(const double* arr, const double* mask, const size_t n, const double ratio, double* result);

#endif