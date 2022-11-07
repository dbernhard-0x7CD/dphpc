#ifndef LMQ_MASKED_DROPOUT_H
#define LMQ_MASKED_DROPOUT_H

#include <snrt.h>
#include <stdlib.h>

#include <math.h>

int masked_dropout_baseline(const float* arr, const float* mask, const size_t n, const float ratio, float* result);
int masked_dropout_ssr(const float* arr, const float* mask, const size_t n, const float ratio, float* result);
int masked_dropout_ssr_frep(const float* arr, const float* mask, const size_t n, const float ratio, float* result);

#endif