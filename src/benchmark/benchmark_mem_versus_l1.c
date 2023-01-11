#include <snrt.h>
#include "printf.h"

#include "lmq.h"
#include "benchmark.h"

int main() {
    uint32_t core_idx = snrt_global_core_idx();

    // only run on 1 core
    for(size_t size=LMQ_START_SIZE; core_idx == 0 && size<=LMQ_SIZE;size*=2){
        // memory
        double* memory_x = allocate(size, sizeof(double));
        double* memory_target = allocate(size, sizeof(double));
        double* l1_x = snrt_l1alloc(size * sizeof(double));
        double* l1_target = snrt_l1alloc(size * sizeof(double));
        
        for (int i = 0; i < size; i++) {
            memory_x[i] = (double)i - 20.0;
            l1_x[i] = (double)i - 20.0;
        }
        
        // copy mem -> mem
        size_t _start_ = read_csr(mcycle);
        for (size_t i = 0; i < size; i++) {
            memory_target[i] = memory_x[i];
        }
        size_t _end_ = read_csr(mcycle);

        printf("copy_memory_to_memory, size: %d: %lu cycles\n", size, _end_ - _start_);

        size_t start_l1 = read_csr(mcycle);
        for (size_t i = 0; i < size; i++) {
            l1_target[i] = l1_x[i];
        }
        size_t end_l1  = read_csr(mcycle);
        
        printf("copy_l1_to_l1, size: %d: %lu cycles\n", size, end_l1 - start_l1);

        verify_vector(memory_target, memory_x, size);
        verify_vector(memory_target, l1_target, size);
    }
 
    return 0;
}