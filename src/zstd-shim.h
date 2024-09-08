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

#include <crt/intrin.h>

#pragma intrinsic(_byteswap_uint64)
#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(_rotl)
#pragma intrinsic(_rotl64)

#endif
