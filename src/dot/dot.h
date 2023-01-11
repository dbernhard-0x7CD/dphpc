
#ifndef LMQ_DOT_H
#define LMQ_DOT_H

#include <snrt.h>

#include <math.h>

/*
 * Naive implementation of dotproduct.
 * Writes the result back into the respective pointer.
 */
int dot_baseline(const double* a,
                 const double* b,
                 const size_t n,
                 double* result);

int dot_ssr(const double* a,
            const double* b,
            const size_t n,
            double* result);

int dot_ssr_frep(const double* a,
                 const double* b,
                 const size_t n,
                 double* result);

int ssr_dvec_dvec_dotp(const double* const vals_a,
                       const double* const vals_b,
                       const size_t len,
                       double* const res);

int ssr_dvec_dvec_dotpf(const double* const vals_a,
                        const double* const vals_b,
                        const size_t len,
                        double* const res);

#endif
