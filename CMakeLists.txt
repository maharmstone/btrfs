cmake_minimum_required(VERSION 3.13)

project(btrfs)

set(ZSTD_SRC_FILES src/zstd/entropy_common.c
    src/zstd/error_private.c
    src/zstd/fse_compress.c
    src/zstd/fse_decompress.c
    src/zstd/hist.c
    src/zstd/huf_compress.c
    src/zstd/huf_decompress.c
    src/zstd/zstd_common.c
    src/zstd/zstd_compress.c
    src/zstd/zstd_decompress.c
    src/zstd/zstd_double_fast.c
    src/zstd/zstd_fast.c
    src/zstd/zstd_lazy.c
    src/zstd/zstd_ldm.c
    src/zstd/zstd_opt.c)

set(ZLIB_SRC_FILES src/zlib/adler32.c
    src/zlib/deflate.c
    src/zlib/inffast.c
    src/zlib/inflate.c
    src/zlib/inftrees.c
    src/zlib/trees.c
    src/zlib/zutil.c)

set(SRC_FILES src/balance.c
    src/blake2b-ref.c
    src/boot.c
    src/btrfs.c
    src/cache.c
    src/calcthread.c
    src/compress.c
    src/crc32c.c
    src/create.c
    src/devctrl.c
    src/dirctrl.c
    src/extent-tree.c
    src/fastio.c
    src/fileinfo.c
    src/flushthread.c
    src/free-space.c
    src/fsctl.c
    src/fsrtl.c
    src/galois.c
    src/pnp.c
    src/read.c
    src/registry.c
    src/reparse.c
    src/scrub.c
    src/search.c
    src/security.c
    src/send.c
    src/sha256.c
    src/treefuncs.c
    src/volume.c
    src/worker-thread.c
    src/write.c
    src/xxhash.c
    src/btrfs.rc
    ${ZSTD_SRC_FILES}
    ${ZLIB_SRC_FILES})

if(MSVC)
    enable_language(ASM_MASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-amd64-masm.asm)
else()
    enable_language(ASM)
    set(SRC_FILES ${SRC_FILES} src/crc32c-gas.S)
endif()

add_library(btrfs SHARED ${SRC_FILES})

if(MSVC)
    include_directories("$ENV{WindowsSdkDir}Include\\$ENV{WindowsSDKLibVersion}km")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    include_directories("${CMAKE_FIND_ROOT_PATH}/usr/include/ddk")
endif()

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "AMD64" OR ${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    add_definitions(-D_AMD64_)
endif()

target_compile_definitions(btrfs PUBLIC _KERNEL_MODE WIN9X_COMPAT_SPINLOCK)

if(MSVC)
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\x64\\ntoskrnl.lib")
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\x64\\hal.lib")
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\x64\\BufferOverflowK.lib")
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\x64\\rtlver.lib")
    target_link_options(btrfs PUBLIC /SUBSYSTEM:NATIVE /NODEFAULTLIB /MANIFEST:NO /Driver /ENTRY:DriverEntry)

    # strip out flags for MSVC's runtime checks
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
else()
    target_link_libraries(btrfs ntoskrnl hal gcc)
    target_link_options(btrfs PUBLIC -nostdlib -Wl,--entry,DriverEntry -Wl,--subsystem,native -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--exclude-all-symbols)
endif()

set_target_properties(btrfs PROPERTIES PREFIX "")
set_target_properties(btrfs PROPERTIES SUFFIX ".sys")

# FIXME - get working with x86
# FIXME - arm and aarch64
# FIXME - get working with shellext etc.
# FIXME - get version automatically put in RC file
