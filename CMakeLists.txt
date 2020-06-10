cmake_minimum_required(VERSION 3.15)

project(btrfs)

# btrfs.sys

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
    if(MSVC_C_ARCHITECTURE_ID STREQUAL "X86") # cmake bug 15170
        set(CMAKE_SYSTEM_PROCESSOR "x86")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARMV7")
        set(CMAKE_SYSTEM_PROCESSOR "arm")
    endif()
endif()

if(MSVC)
    enable_language(ASM_MASM)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        set(SRC_FILES ${SRC_FILES} src/crc32c-amd64-masm.asm)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        set(SRC_FILES ${SRC_FILES} src/crc32c-x86-masm.asm)
    endif()
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

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions(-D_AMD64_)
    set(MS_ARCH "x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    add_definitions(-D_X86_)
    set(MS_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    add_definitions(-D_ARM_)
    set(MS_ARCH "arm")
endif()

target_compile_definitions(btrfs PUBLIC _KERNEL_MODE WIN9X_COMPAT_SPINLOCK)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_compile_options(btrfs PUBLIC /Gz) # stdcall
    endif()

    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\ntoskrnl.lib")
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\hal.lib")

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\bufferoverflowfastfailk.lib")
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}um\\${MS_ARCH}\\armrt.lib")
    else()
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\BufferOverflowK.lib")
    endif()

    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\rtlver.lib")
    target_link_options(btrfs PUBLIC /SUBSYSTEM:NATIVE /NODEFAULTLIB /MANIFEST:NO /Driver /ENTRY:DriverEntry)

    # strip out flags for MSVC's runtime checks
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
else()
    target_compile_options(btrfs PUBLIC -msse4.2)

    target_link_libraries(btrfs ntoskrnl hal gcc)
    target_link_options(btrfs PUBLIC -nostdlib -Wl,--subsystem,native -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--exclude-all-symbols)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_link_options(btrfs PUBLIC -Wl,--entry,_DriverEntry@8)
    else()
        target_link_options(btrfs PUBLIC -Wl,--entry,DriverEntry)
    endif()
endif()

set_target_properties(btrfs PROPERTIES PREFIX "")
set_target_properties(btrfs PROPERTIES SUFFIX ".sys")

# FIXME - aarch64
# FIXME - get version automatically put in RC file

# --------------------------------------

# shellbtrfs.dll

set(SHELLEXT_SRC_FILES src/shellext/balance.cpp
    src/shellext/contextmenu.cpp
    src/shellext/devices.cpp
    src/shellext/factory.cpp
    src/shellext/iconoverlay.cpp
    src/shellext/main.cpp
    src/shellext/mountmgr.cpp
    src/shellext/propsheet.cpp
    src/shellext/recv.cpp
    src/shellext/scrub.cpp
    src/shellext/send.cpp
    src/shellext/volpropsheet.cpp
    src/shellext/shellbtrfs.rc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_library(shellbtrfs SHARED ${SHELLEXT_SRC_FILES})

if(NOT MSVC)
    target_compile_options(shellbtrfs PUBLIC -msse4.2)
else()
    target_compile_options(shellbtrfs PUBLIC /EHsc)
endif()

target_link_libraries(shellbtrfs comctl32 ntdll setupapi uxtheme shlwapi windowscodecs gdi32 advapi32 shell32 ole32)

set_target_properties(shellbtrfs PROPERTIES PREFIX "")

if(MSVC)
    set_property(TARGET shellbtrfs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --------------------------------------

# ubtrfs.dll

set(UBTRFS_SRC_FILES src/ubtrfs/ubtrfs.c
    src/crc32c.c
    src/xxhash.c
    src/sha256.c
    src/blake2b-ref.c
    src/ubtrfs/ubtrfs.rc)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        set(UBTRFS_SRC_FILES ${UBTRFS_SRC_FILES} src/crc32c-amd64-masm.asm)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        set(UBTRFS_SRC_FILES ${UBTRFS_SRC_FILES} src/crc32c-x86-masm.asm)
    endif()
else()
    set(UBTRFS_SRC_FILES ${UBTRFS_SRC_FILES} src/crc32c-gas.S)
endif()

add_library(ubtrfs SHARED ${UBTRFS_SRC_FILES})

if(MSVC)
    set_property(TARGET ubtrfs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_compile_definitions(ubtrfs PUBLIC _USRDLL)
target_link_libraries(ubtrfs ntdll advapi32)

if(MSVC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    target_compile_options(ubtrfs PUBLIC /Gz) # stdcall
endif()

set_target_properties(ubtrfs PROPERTIES PREFIX "")

# --------------------------------------

# mkbtrfs.exe

set(MKBTRFS_SRC_FILES src/mkbtrfs/mkbtrfs.c
    src/mkbtrfs/mkbtrfs.rc)

add_executable(mkbtrfs ${MKBTRFS_SRC_FILES})

if(MSVC)
    set_property(TARGET mkbtrfs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
