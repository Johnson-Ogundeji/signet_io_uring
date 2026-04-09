# Signet_io_uring — Tests
# Copyright 2026 Signet_io_uring Authors
# SPDX-License-Identifier: Apache-2.0

# Find GTest
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Unit tests
add_executable(signet_tests
    # Core tests
    unit/test_clock.cpp
    unit/test_histogram.cpp
    unit/test_metrics.cpp
    unit/test_buffer_pool.cpp
    unit/test_ring.cpp
    # Network tests
    unit/test_address.cpp
    unit/test_resolver.cpp
    unit/test_socket.cpp
    # TLS tests
    unit/test_tls.cpp
    # WebSocket tests
    unit/test_ws.cpp
    unit/test_ws_edge_cases.cpp
    unit/test_ws_extensions.cpp
    unit/test_ws_client.cpp
)

find_package(ZLIB REQUIRED)

target_link_libraries(signet_tests PRIVATE
    signet::signet
    GTest::gtest_main
    ZLIB::ZLIB
    pthread
)

# Enable metrics for tests
target_compile_definitions(signet_tests PRIVATE SIGNET_ENABLE_METRICS)

include(GoogleTest)
gtest_discover_tests(signet_tests)

# ═══════════════════════════════════════════════════════════════════════════
# Autobahn Compliance Tests (optional)
# ═══════════════════════════════════════════════════════════════════════════

option(SIGNET_BUILD_AUTOBAHN "Build Autobahn compliance test client" OFF)

if(SIGNET_BUILD_AUTOBAHN)
    add_executable(signet_autobahn_client
        autobahn/autobahn_client.cpp
    )

    target_link_libraries(signet_autobahn_client PRIVATE
        signet::signet
        ZLIB::ZLIB
        pthread
    )

    target_compile_definitions(signet_autobahn_client PRIVATE SIGNET_ENABLE_METRICS)
endif()
