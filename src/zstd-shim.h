#include <stddef.h>
#include <stdint.h>

static void* ZSTD_malloc(size_t size) {
    return NULL;
}

static void* ZSTD_calloc(size_t nmemb, size_t size) {
    return NULL;
}

static void ZSTD_free(void* ptr) {
}

#ifdef _MSC_VER
static uint64_t _byteswap_uint64(uint64_t val) {
    return ((val << 56) & 0xff00000000000000ULL) |
        ((val << 40) & 0x00ff000000000000ULL) |
        ((val << 24) & 0x0000ff0000000000ULL) |
        ((val << 8)  & 0x000000ff00000000ULL) |
        ((val >> 8)  & 0x00000000ff000000ULL) |
        ((val >> 24) & 0x0000000000ff0000ULL) |
        ((val >> 40) & 0x000000000000ff00ULL) |
        ((val >> 56) & 0x00000000000000ffULL);
}

static unsigned long _byteswap_ulong(unsigned long val) {
    return ((val << 24) & 0xff000000) |
           ((val <<  8) & 0x00ff0000) |
           ((val >>  8) & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}
#endif
