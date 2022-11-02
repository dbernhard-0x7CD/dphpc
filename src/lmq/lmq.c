#include "lmq.h"
#include <printf.h>

#include <snrt.h>

void* cur_memory = NULL;

void* allocate(const size_t n, const size_t element_size) {
    if (cur_memory == NULL) {
        cur_memory = (void*) snrt_global_memory().start;
    }
    void* now = cur_memory;

    // This is to have some spacing as SSR sometimes writes one more
    // element to the stream which may be outide an array.
    cur_memory += (n*element_size + element_size);

    return now;
}