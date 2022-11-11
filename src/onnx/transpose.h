
#ifndef LMQ_TRANSPOSE_H
#define LMQ_TRANSPOSE_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of transpose.
 * arr is in row major format and has dimensions (r, s)
 */
int transpose_baseline(const float* arr, const size_t r, const size_t s, float* result);

int transpose_ssr(const float* arr, const size_t r, const size_t s, float* result);

int transpose_ssr_frep(const float* arr, const size_t r, const size_t s, float* result);

#endif
