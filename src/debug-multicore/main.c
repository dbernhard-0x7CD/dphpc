#include "printf.h"

#include "snrt.h"

int main() {
    uint32_t core_num = snrt_global_core_num();
    uint32_t core_idx = snrt_global_core_idx();

    // This terminates all other cores early. This decreased the simulation time.
    // if (core_idx != 0) return 0;

    size_t start = read_csr(mcycle);

    int x = core_idx;
    for (int i = 0; i < 100; i++) {
        x++;
    }

    size_t end = read_csr(mcycle);

    if (core_idx == 0) {
        printf("took %d cycles and result: %d\n", end - start, x);
    } else {
        printf("Hello from the snitch core %d. Took %d cycles. result: %d\n", core_idx, end - start, x);
    }

    return 0;
}