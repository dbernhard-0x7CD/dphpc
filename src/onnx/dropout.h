#ifndef LMQ_DROPOUT_H
#define LMQ_DROPOUT_H

#include <snrt.h>
#include <stdlib.h>
#include <float.h>

#include "printf.h"

#include <math.h>

int dropout_baseline(const float* arr, const size_t n, const float ratio, float* result);
int dropout_baseline_test(const float* arr, const size_t n, const float ratio, float* result);
int dropout_ssr(const float* arr, const size_t n, const float ratio, float* result);
int dropout_ssr_test(const float* arr, const size_t n, const float ratio, float* result);
int dropout_ssr_frep(const float* arr, const size_t n, const float ratio, float* result);

#endif