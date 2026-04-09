# Signet_io_uring — Header-only C++20 io_uring + kTLS WebSocket library
# Copyright 2026 Signet_io_uring Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

project(signet_io_uring
    VERSION 0.1.0
    DESCRIPTION "Header-only C++20 io_uring + kTLS WebSocket library for Linux"
    HOMEPAGE_URL "https://github.com/Johnson-Ogundeji/signet_io_uring"
    LANGUAGES CXX
)

# C++20 required
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(SIGNET_BUILD_TESTS "Build test suite" ON)
option(SIGNET_BUILD_BENCHMARKS "Build benchmarks" OFF)
option(SIGNET_BUILD_EXAMPLES "Build examples" ON)
option(SIGNET_ENABLE_METRICS "Enable runtime metrics collection" OFF)
option(SIGNET_ENABLE_SIMD "Enable SIMD optimizations" ON)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED liburing)

find_package(OpenSSL REQUIRED)

# tl-expected (header-only) — try system first, fetch as fallback
find_path(TL_EXPECTED_INCLUDE_DIR tl/expected.hpp
    HINTS /usr/include
          /usr/local/include
)

if(NOT TL_EXPECTED_INCLUDE_DIR)
    include(FetchContent)
    FetchContent_Declare(
        tl_expected
        GIT_REPOSITORY https://github.com/TartanLlama/expected.git
        GIT_TAG v1.1.0
    )
    # Don't build tl_expected's own test suite — it carries warnings
    # that fail under our -Werror sanity build, and we only consume
    # the headers anyway.
    set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(EXPECTED_BUILD_PACKAGE OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(tl_expected)
    set(TL_EXPECTED_INCLUDE_DIR ${tl_expected_SOURCE_DIR}/include)
endif()

# Create interface library (header-only)
# Target name is `signet_io_uring`; legacy alias `signet::signet` is preserved
# so existing code using the older include namespace continues to compile.
add_library(signet_io_uring INTERFACE)
add_library(signet_io_uring::signet_io_uring ALIAS signet_io_uring)
add_library(signet::signet ALIAS signet_io_uring)  # legacy alias

target_include_directories(signet_io_uring INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${TL_EXPECTED_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(signet_io_uring INTERFACE
    ${LIBURING_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_features(signet_io_uring INTERFACE cxx_std_20)

# Compiler warnings
target_compile_options(signet_io_uring INTERFACE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
)

# SIMD flags
if(SIGNET_ENABLE_SIMD)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(-mavx2 HAS_AVX2)
    check_cxx_compiler_flag(-msse4.2 HAS_SSE42)

    if(HAS_AVX2)
        target_compile_options(signet_io_uring INTERFACE
            $<$<CXX_COMPILER_ID:GNU>:-mavx2>
            $<$<CXX_COMPILER_ID:Clang>:-mavx2>
        )
    elseif(HAS_SSE42)
        target_compile_options(signet_io_uring INTERFACE
            $<$<CXX_COMPILER_ID:GNU>:-msse4.2>
            $<$<CXX_COMPILER_ID:Clang>:-msse4.2>
        )
    endif()
endif()

# Metrics definition
if(SIGNET_ENABLE_METRICS)
    target_compile_definitions(signet_io_uring INTERFACE SIGNET_ENABLE_METRICS)
endif()

# Tests
if(SIGNET_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Benchmarks
if(SIGNET_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# Examples
if(SIGNET_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS signet_io_uring
    EXPORT signet_io_uringTargets
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/signet
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT signet_io_uringTargets
    FILE signet_io_uringTargets.cmake
    NAMESPACE signet_io_uring::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/signet_io_uring
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/signet_io_uringConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/signet_io_uringConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/signet_io_uring
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/signet_io_uringConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/signet_io_uringConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/signet_io_uringConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/signet_io_uring
)

# Summary
message(STATUS "")
message(STATUS "Signet_io_uring v${PROJECT_VERSION} configuration:")
message(STATUS "  Build tests:      ${SIGNET_BUILD_TESTS}")
message(STATUS "  Build benchmarks: ${SIGNET_BUILD_BENCHMARKS}")
message(STATUS "  Build examples:   ${SIGNET_BUILD_EXAMPLES}")
message(STATUS "  Enable metrics:   ${SIGNET_ENABLE_METRICS}")
message(STATUS "  Enable SIMD:      ${SIGNET_ENABLE_SIMD}")
message(STATUS "")
