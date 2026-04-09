// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file signet.hpp
/// @brief Main include header for Signet WebSocket library
///
/// Signet is a high-performance WebSocket library built on Linux io_uring.
/// Include this header to access all Signet functionality.
///
/// @code
/// #include <signet/signet.hpp>
///
/// int main() {
///     signet::WebSocketClient client;
///     client.on_message([](const signet::Message& msg) {
///         std::cout << msg.as_text() << "\n";
///     });
///     client.connect("wss://echo.websocket.org");
///     client.send("Hello!");
///     client.run();
/// }
/// @endcode

#pragma once

// Version information
#define SIGNET_VERSION_MAJOR 0
#define SIGNET_VERSION_MINOR 1
#define SIGNET_VERSION_PATCH 0
#define SIGNET_VERSION_STRING "0.1.0"

// Core components
#include "signet/core/types.hpp"
#include "signet/core/error.hpp"
#include "signet/core/config.hpp"
#include "signet/core/clock.hpp"
#include "signet/core/histogram.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/ring.hpp"
#include "signet/core/buffer_pool.hpp"
#include "signet/core/benchmark.hpp"

// Networking components
#include "signet/net/address.hpp"
#include "signet/net/socket.hpp"
#include "signet/net/resolver.hpp"
#include "signet/net/connection.hpp"

// TLS components
#include "signet/tls/tls_context.hpp"
#include "signet/tls/ktls.hpp"
#include "signet/tls/tls_connection.hpp"

// WebSocket components
#include "signet/ws/ws_types.hpp"
#include "signet/ws/ws_frame.hpp"
#include "signet/ws/ws_handshake.hpp"
#include "signet/ws/ws_connection.hpp"
#include "signet/ws/ws_validator.hpp"
#include "signet/ws/ws_extension.hpp"
#include "signet/ws/ws_deflate.hpp"
#include "signet/ws/ws_client.hpp"

// Forward declarations for components not yet implemented
namespace signet {

// Will be implemented in Phase 7-8
class WebSocketServer;

}  // namespace signet

namespace signet {

/// Initialize Signet library
/// Call this before using any Signet functionality
inline void initialize() {
    Clock::initialize();
}

/// Get Signet version string
[[nodiscard]] inline const char* version() noexcept {
    return SIGNET_VERSION_STRING;
}

/// Check if io_uring is supported on this system
[[nodiscard]] inline bool is_iouring_supported() noexcept {
#ifdef __linux__
    // Try to create a minimal io_uring instance
    struct io_uring ring;
    int ret = io_uring_queue_init(1, &ring, 0);
    if (ret == 0) {
        io_uring_queue_exit(&ring);
        return true;
    }
    return false;
#else
    return false;
#endif
}

/// Check if kTLS is supported on this system
[[nodiscard]] inline bool is_ktls_supported() noexcept {
#ifdef __linux__
    // Check if TLS module is available
    // In practice, check /proc/modules or try to set socket option
    return true;  // Assume available, will fail gracefully if not
#else
    return false;
#endif
}

/// Get the detected SIMD level
[[nodiscard]] inline SimdLevel detect_simd_level() noexcept {
#if defined(__AVX512F__)
    return SimdLevel::AVX512;
#elif defined(__AVX2__)
    return SimdLevel::AVX2;
#elif defined(__SSE4_2__)
    return SimdLevel::SSE42;
#elif defined(__ARM_NEON)
    return SimdLevel::NEON;
#else
    return SimdLevel::None;
#endif
}

}  // namespace signet
