cmake_minimum_required(VERSION 3.15)

project(btrfs VERSION 1.7.7)

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
    src/zstd/zstd_compress_literals.c
    src/zstd/zstd_compress_sequences.c
    src/zstd/zstd_compress_superblock.c
    src/zstd/zstd_ddict.c
    src/zstd/zstd_decompress.c
    src/zstd/zstd_decompress_block.c
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
    ${CMAKE_CURRENT_BINARY_DIR}/btrfs.rc
    ${ZSTD_SRC_FILES}
    ${ZLIB_SRC_FILES})

if(MSVC) # cmake bug 15170
    if(MSVC_C_ARCHITECTURE_ID STREQUAL "X86")
        set(CMAKE_SYSTEM_PROCESSOR "x86")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "x64")
        set(CMAKE_SYSTEM_PROCESSOR "x86_64")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARMV7")
        set(CMAKE_SYSTEM_PROCESSOR "arm")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARM64")
        set(CMAKE_SYSTEM_PROCESSOR "aarch64")
    endif()
endif()

# Work around bug in MSVC version of cmake - see https://gitlab.kitware.com/cmake/cmake/-/merge_requests/4257
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")

set(CMAKE_ASM_MASM_FLAGS "/Zd")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    if(MSVC)
        enable_language(ASM_MASM)
        set(SRC_FILES ${SRC_FILES}
            src/crc32c-masm.asm
            src/xor-masm.asm)
    else()
        enable_language(ASM)
        set(SRC_FILES ${SRC_FILES}
            src/crc32c-gas.S
            src/xor-gas.S)
    endif()
endif()

configure_file(src/btrfs.rc.in btrfs.rc)

add_library(btrfs SHARED ${SRC_FILES})

if(MSVC)
    include_directories("$ENV{WindowsSdkDir}Include\\$ENV{WindowsSDKLibVersion}km")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND WIN32)
    include_directories("${CMAKE_FIND_ROOT_PATH}/usr/include/ddk")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions(-D_AMD64_)
    set(MS_ARCH "x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    add_definitions(-D_X86_)
    set(MS_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    add_definitions(-D_ARM_)
    set(MS_ARCH "arm")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions(-D_ARM64_)
    set(MS_ARCH "arm64")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-D_DEBUG)
endif()

if(NOT MSVC)
    target_compile_options(btrfs PUBLIC -U__NO_INLINE__)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=0)
endif()

target_compile_definitions(btrfs PUBLIC _KERNEL_MODE WIN9X_COMPAT_SPINLOCK)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_compile_options(btrfs PUBLIC /Gz) # stdcall
    endif()

    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\ntoskrnl.lib")
    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\hal.lib")

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\bufferoverflowfastfailk.lib")
    else()
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\BufferOverflowK.lib")
    endif()

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}um\\${MS_ARCH}\\armrt.lib")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}um\\${MS_ARCH}\\arm64rt.lib")
    endif()

    target_link_libraries(btrfs "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\rtlver.lib")
    target_link_options(btrfs PUBLIC /SUBSYSTEM:NATIVE /NODEFAULTLIB /MANIFEST:NO /Driver /ENTRY:DriverEntry)

    # strip out flags for MSVC's runtime checks
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
else()
    target_compile_options(btrfs PUBLIC -Wall -Werror-implicit-function-declaration -Werror=cast-function-type -Werror=incompatible-pointer-types -Wno-expansion-to-defined -Wunused-parameter -Wold-style-declaration -Wtype-limits -Wextra)

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
    src/crc32c.c
    src/shellext/shellbtrfs.def
    ${CMAKE_CURRENT_BINARY_DIR}/shellbtrfs.rc)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    if(MSVC)
        enable_language(ASM_MASM)
        set(SHELLEXT_SRC_FILES ${SHELLEXT_SRC_FILES} src/crc32c-masm.asm)
    else()
        enable_language(ASM)
        set(SHELLEXT_SRC_FILES ${SHELLEXT_SRC_FILES} src/crc32c-gas.S)
    endif()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

configure_file(src/shellext/shellbtrfs.rc.in shellbtrfs.rc)

add_library(shellbtrfs SHARED ${SHELLEXT_SRC_FILES})

if(NOT MSVC)
    target_link_options(shellbtrfs PUBLIC -static -static-libgcc)
else()
    target_compile_options(shellbtrfs PUBLIC /EHsc)
    target_link_options(shellbtrfs PUBLIC /MANIFEST:NO)
endif()

target_link_libraries(shellbtrfs comctl32 ntdll setupapi uxtheme shlwapi windowscodecs gdi32 advapi32 shell32 ole32)

if(MSVC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    target_compile_options(shellbtrfs PUBLIC /Gz) # stdcall
endif()

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
    src/ubtrfs/ubtrfs.def
    ${CMAKE_CURRENT_BINARY_DIR}/ubtrfs.rc)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    if(MSVC)
        enable_language(ASM_MASM)
        set(UBTRFS_SRC_FILES ${UBTRFS_SRC_FILES} src/crc32c-masm.asm)
    else()
        enable_language(ASM)
        set(UBTRFS_SRC_FILES ${UBTRFS_SRC_FILES} src/crc32c-gas.S)
    endif()
endif()

configure_file(src/ubtrfs/ubtrfs.rc.in ubtrfs.rc)

add_library(ubtrfs SHARED ${UBTRFS_SRC_FILES})

if(MSVC)
    set_property(TARGET ubtrfs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_compile_definitions(ubtrfs PUBLIC _USRDLL)
target_link_libraries(ubtrfs ntdll advapi32)

if(MSVC AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    target_compile_options(ubtrfs PUBLIC /Gz) # stdcall
endif()

if(NOT MSVC)
    target_link_options(ubtrfs PUBLIC -static -static-libgcc -static-libstdc++)
endif()

set_target_properties(ubtrfs PROPERTIES PREFIX "")

# --------------------------------------

# mkbtrfs.exe

set(MKBTRFS_SRC_FILES src/mkbtrfs/mkbtrfs.c
    ${CMAKE_CURRENT_BINARY_DIR}/mkbtrfs.rc)

configure_file(src/mkbtrfs/mkbtrfs.rc.in mkbtrfs.rc)

add_executable(mkbtrfs ${MKBTRFS_SRC_FILES})

if(MSVC)
    set_property(TARGET mkbtrfs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_link_options(mkbtrfs PUBLIC -static -static-libgcc)
endif()

# --------------------------------------

# install

install(TARGETS btrfs DESTINATION bin)
install(TARGETS shellbtrfs DESTINATION bin)
install(TARGETS ubtrfs DESTINATION bin)
install(TARGETS mkbtrfs DESTINATION bin)
