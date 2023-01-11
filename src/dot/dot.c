
#include <dot.h>
#include <snrt.h>

#include <float.h>
#include <math.h>

/*
 * Naive implementation of dot product.
 * Calculates the dotproduct of a and b (each containing n elements).
 * Writes back the result to the result pointer.
 */
__attribute__((noinline))
int dot_baseline(const double* a,
                 const double* b,
                 const size_t n,
                 double* result) {
    double sum = 0.0;

    for (size_t i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }

    *result = sum;

    return 0;
}

__attribute__((noinline))
int dot_ssr(const double* a,
            const double* b,
            const size_t n,
            double* result) {
    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    // stream arr into ft1
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    volatile register double out;

    snrt_ssr_enable();

    asm volatile(
        "addi a0, zero, 0\n"  // a0 <- 0; a0 is the index
        "fcvt.d.w ft3, zero\n"
        "1:\n"
        "addi a0, a0, 1\n"
        "fmadd.d ft3, ft1, ft0, ft3\n"
        "3:"
        "blt a0, %[n], 1b\n"
        "fmv.d %[out], ft3\n"
        : [out] "=f"(out)
        : [n] "r"(n)
        : "ft0", "ft1", "ft2", "ft3", "a0");

    snrt_fpu_fence();
    snrt_ssr_disable();

    *result = out;

    return 0;
}

__attribute__((noinline))
int dot_ssr_frep(const double* a,
                 const double* b,
                 const size_t n,
                 double* result) {
    // stream arr into ft0
    snrt_ssr_loop_1d(SNRT_SSR_DM0, n, sizeof(*a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, a);

    // stream arr into ft1
    snrt_ssr_loop_1d(SNRT_SSR_DM1, n, sizeof(*b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, b);

    volatile register double out;

    snrt_ssr_enable();

    asm volatile(
        "fcvt.d.w ft3, zero\n"
        "frep.o %[n], 1, 0, 0\n"
        "fmadd.d ft3, ft1, ft0, ft3\n"
        "fmv.d %[out], ft3\n"
        : [out] "=f"(out)
        : [n] "r"(n - 1)
        : "ft0", "ft1", "ft3");

    snrt_fpu_fence();
    snrt_ssr_disable();

    *result = out;

    return 0;
}

__attribute__((noinline))
int ssr_dvec_dvec_dotpf(const double* const vals_a,
                        const double* const vals_b,
                        const size_t len,
                        double* const res) {
    if (len == 0)
        return -1;

    snrt_ssr_loop_1d(SNRT_SSR_DM0, len, sizeof(*vals_a));
    snrt_ssr_repeat(SNRT_SSR_DM0, 1);
    snrt_ssr_read(SNRT_SSR_DM0, SNRT_SSR_1D, vals_a);

    snrt_ssr_loop_1d(SNRT_SSR_DM1, len, sizeof(*vals_b));
    snrt_ssr_repeat(SNRT_SSR_DM1, 1);
    snrt_ssr_read(SNRT_SSR_DM1, SNRT_SSR_1D, vals_b);

    snrt_ssr_enable();

    asm volatile(
        // Setup zero register
        "fcvt.d.w   ft3, zero           \n"

        // Init target registers
        "fmv.d      ft4, ft3            \n"
        "fmv.d      ft5, ft3            \n"
        "fmv.d      ft6, ft3            \n"
        "fmv.d      ft7, ft3            \n"
        "fmv.d      fs0, ft3            \n"

        // Computation
        "frep.o %[ldec], 1, 0b101, 0b1001   \n"
        "fmadd.d    ft3, ft1, ft0, ft3  \n"

        // Reduction
        "fadd.d     ft9, ft6, ft7       \n"
        "fadd.d     ft6, ft4, ft5       \n"
        "fadd.d     ft7, fs0, ft3       \n"
        "fadd.d     ft4, ft6, ft7       \n"
        "fadd.d     ft8, ft4, ft9       \n"
        // Writeback
        "fsd        ft8, 0(%[res])      \n"
        "bne t0,    zero, 9f            \n9:" ::[res] "r"(res),
        [c8] "r"(8), [vala] "r"(vals_a), [valb] "r"(vals_b), [ldec] "r"(len)
        : "memory", "t0", "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "ft8", "ft9",
          "fs0");

    snrt_fpu_fence();
    snrt_ssr_disable();

    return 0;
}

// NOTICE: This is adapted from the snitch project
// Simple 1D dot product using SSRs
__attribute__((noinline))
int ssr_dvec_dvec_dotp(const double* const vals_a,
                       const double* const vals_b,
                       const size_t len,
                       double* const res) {
    if (len == 0)
        return -1;

    asm volatile(
        // Setup zero register
        "fcvt.d.w   ft3, zero           \n"
        // SSR setup
        "scfgwi %[ldec], 0 |  2<<5      \n"  // bounds_0[0]
        "scfgwi %[ldec], 1 |  2<<5      \n"  // bounds_0[1]
        "scfgwi %[c8],   0 |  6<<5      \n"  // stride_0[0]
        "scfgwi %[c8],   1 |  6<<5      \n"  // stride_0[1]
        "scfgwi %[vala], 0 | 24<<5      \n"  // rptr_0[0]
        "scfgwi %[valb], 1 | 24<<5      \n"  // rptr_0[1]
        // Enable SSRs
        "csrsi      0x7C0, 1            \n"
        // Init target registers
        "fmv.d      ft4, ft3            \n"
        "fmv.d      ft5, ft3            \n"
        "fmv.d      ft6, ft3            \n"
        "fmv.d      ft7, ft3            \n"
        "fmv.d      fs0, ft3            \n"
        // Computation
        "frep.o %[ldec], 1, 0b101, 0b1001   \n"
        "fmadd.d    ft3, ft1, ft0, ft3  \n"
        // Reduction
        "fadd.d     ft9, ft6, ft7       \n"
        "fadd.d     ft6, ft4, ft5       \n"
        "fadd.d     ft7, fs0, ft3       \n"
        "fadd.d     ft4, ft6, ft7       \n"
        "fadd.d     ft8, ft4, ft9       \n"
        // Writeback
        "fsd        ft8, 0(%[res])      \n"
        // Fence, disable SSRs
        "fmv.x.w    t0, fa0             \n"
        "csrci      0x7C0, 1            \n"
        "bne t0,    zero, 9f            \n9:" ::[res] "r"(res),
        [c8] "r"(8), [vala] "r"(vals_a), [valb] "r"(vals_b), [ldec] "r"(len)
        : "memory", "t0", "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "ft8", "ft9",
          "fs0");

    return 0;
}
