# Signet_io_uring — Examples
# Copyright 2026 Signet_io_uring Authors
# SPDX-License-Identifier: Apache-2.0

# Basic benchmark example
add_executable(signet_basic_bench
    basic_benchmark.cpp
)

target_link_libraries(signet_basic_bench PRIVATE
    signet::signet
)

# Enable metrics for examples
target_compile_definitions(signet_basic_bench PRIVATE SIGNET_ENABLE_METRICS)
