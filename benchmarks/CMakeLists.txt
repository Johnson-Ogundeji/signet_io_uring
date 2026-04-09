# Signet_io_uring — Benchmarks
# Copyright 2026 Signet_io_uring Authors
# SPDX-License-Identifier: Apache-2.0

find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.8.3
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(benchmark)
endif()

find_package(ZLIB REQUIRED)

# WebSocket benchmarks
add_executable(signet_ws_bench
    bench_ws.cpp
)

target_link_libraries(signet_ws_bench PRIVATE
    signet::signet
    benchmark::benchmark
    benchmark::benchmark_main
    ZLIB::ZLIB
    pthread
)

target_compile_definitions(signet_ws_bench PRIVATE SIGNET_ENABLE_METRICS)
target_compile_options(signet_ws_bench PRIVATE -O3 -march=native)
