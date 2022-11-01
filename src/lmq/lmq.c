#include "lmq.h"

#include <snrt.h>

void* cur_memory = NULL;

void* allocate(const size_t n) {
    if (cur_memory == NULL) {
        cur_memory = (void*) snrt_global_memory().start;
    }
    void* now = cur_memory;

    cur_memory += n;

    return now;
}