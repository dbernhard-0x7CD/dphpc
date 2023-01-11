
#ifndef LMQ_DIV_H
#define LMQ_DIV_H

#include <snrt.h>

double div_baseline(double *x, double *y, const size_t n, double *result);
double div_ssr(double *x, double *y, const size_t n, double *result);
double div_ssr_frep(double *x, double *y, const size_t n, double *result);

#endif
