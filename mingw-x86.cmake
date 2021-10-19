#
# To Cross-compile, use:
#  cmake -DCMAKE_TOOLCHAIN_FILE=../mingw.cmake ..
#
# the name of the target operating system
SET(CMAKE_SYSTEM_NAME Windows)

# which compilers to use for C and C++
SET(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
SET(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
SET(CMAKE_RC_COMPILER i686-w64-mingw32-windres)

SET(CMAKE_C_FLAGS "-m32")
SET(CMAKE_CXX_FLAGS "-m32")
SET(CMAKE_RC_FLAGS "-F pe-i386")
SET(CMAKE_ASM_FLAGS "-m32")

# here is the target environment located
SET(CMAKE_FIND_ROOT_PATH /usr/i686-w64-mingw32)

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_PREFIX_PATH /usr/i686-w64-mingw32/usr/lib/cmake)

set(CMAKE_SYSTEM_PROCESSOR x86)
