#ifndef NTOS_FAILURE_RECEIPTS_H
#define NTOS_FAILURE_RECEIPTS_H

#define FAILURE_ID_FORMAT "file=0x%08x%08x generation=0x%08x%08x"
#define FAILURE_ID_ARGS(file, generation) \
    (uint32_t)((uintptr_t)(file) >> 32), (uint32_t)(uintptr_t)(file), \
    (uint32_t)((uint64_t)(generation) >> 32), (uint32_t)(generation)

#endif
