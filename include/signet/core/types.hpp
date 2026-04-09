// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace signet {

/// WebSocket frame opcodes per RFC 6455
enum class Opcode : uint8_t {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    // 0x3-0x7 reserved for future non-control frames
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA
    // 0xB-0xF reserved for future control frames
};

/// Check if opcode is a control frame
[[nodiscard]] constexpr bool is_control_frame(Opcode op) noexcept {
    return static_cast<uint8_t>(op) >= 0x8;
}

/// Check if opcode is a data frame
[[nodiscard]] constexpr bool is_data_frame(Opcode op) noexcept {
    return static_cast<uint8_t>(op) <= 0x2;
}

/// Check if opcode is valid
[[nodiscard]] constexpr bool is_valid_opcode(uint8_t op) noexcept {
    return op <= 0x2 || (op >= 0x8 && op <= 0xA);
}

/// WebSocket close status codes per RFC 6455 Section 7.4
enum class CloseCode : uint16_t {
    Normal           = 1000,  // Normal closure
    GoingAway        = 1001,  // Endpoint going away
    ProtocolError    = 1002,  // Protocol error
    UnsupportedData  = 1003,  // Unsupported data type
    NoStatus         = 1005,  // No status received (internal only)
    Abnormal         = 1006,  // Abnormal closure (internal only)
    InvalidPayload   = 1007,  // Invalid frame payload data
    PolicyViolation  = 1008,  // Policy violation
    MessageTooBig    = 1009,  // Message too big
    MissingExtension = 1010,  // Missing extension
    InternalError    = 1011,  // Internal server error
    TLSHandshake     = 1015   // TLS handshake failure (internal only)
};

/// Check if close code can be sent on wire
[[nodiscard]] constexpr bool is_valid_close_code(uint16_t code) noexcept {
    // 1000-1003, 1007-1011 are valid for wire
    // 1005, 1006, 1015 are internal only
    if (code < 1000) return false;
    if (code >= 1004 && code <= 1006) return false;
    if (code >= 1012 && code <= 1014) return false;
    if (code == 1015) return false;
    if (code >= 1016 && code <= 2999) return false;
    // 3000-3999: registered, 4000-4999: private use
    return code <= 4999;
}

/// WebSocket connection state
enum class ReadyState : uint8_t {
    Connecting = 0,  // Connection in progress
    Open       = 1,  // Connection established
    Closing    = 2,  // Close handshake in progress
    Closed     = 3   // Connection closed
};

/// Frame header structure
struct FrameHeader {
    bool fin = true;              // Final fragment
    bool rsv1 = false;            // Reserved (compression)
    bool rsv2 = false;            // Reserved
    bool rsv3 = false;            // Reserved
    Opcode opcode = Opcode::Text; // Frame type
    bool masked = false;          // Has masking key
    uint64_t payload_length = 0;  // Payload length
    std::array<uint8_t, 4> masking_key{};  // Masking key (if masked)
    size_t header_size = 0;       // Total header size in bytes
};

/// Calculate header size for a given payload length and mask flag
[[nodiscard]] constexpr size_t calculate_header_size(uint64_t payload_length, bool masked) noexcept {
    size_t size = 2;  // Minimum header

    if (payload_length <= 125) {
        // 7-bit length
    } else if (payload_length <= 65535) {
        size += 2;  // 16-bit length
    } else {
        size += 8;  // 64-bit length
    }

    if (masked) {
        size += 4;  // Masking key
    }

    return size;
}

/// Maximum size of a frame header
constexpr size_t kMaxHeaderSize = 14;  // 2 + 8 + 4

/// Maximum control frame payload
constexpr size_t kMaxControlPayload = 125;

/// Default buffer size
constexpr size_t kDefaultBufferSize = 16384;

/// Default buffer count in pool
constexpr size_t kDefaultBufferCount = 64;

/// Message representation (view into buffer, no ownership)
struct Message {
    Opcode opcode = Opcode::Text;
    std::span<const std::byte> data;
    bool compressed = false;

    /// Get payload as text (for text frames)
    [[nodiscard]] std::string_view as_text() const noexcept {
        return {reinterpret_cast<const char*>(data.data()), data.size()};
    }

    /// Get payload as binary
    [[nodiscard]] std::span<const std::byte> as_binary() const noexcept {
        return data;
    }

    /// Get payload size
    [[nodiscard]] size_t size() const noexcept {
        return data.size();
    }

    /// Check if message is empty
    [[nodiscard]] bool empty() const noexcept {
        return data.empty();
    }
};

/// Close information
struct CloseInfo {
    CloseCode code = CloseCode::Normal;
    std::string_view reason;
    bool was_clean = false;
};

/// Time duration aliases
using Milliseconds = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;
using Nanoseconds = std::chrono::nanoseconds;

/// Backend type for feature detection
enum class BackendType {
    IoUring,      // Native io_uring
    Epoll,        // epoll fallback
    Asio          // Boost.Asio/Beast
};

/// TLS mode
enum class TLSMode {
    None,         // No TLS (ws://)
    Userspace,    // OpenSSL userspace TLS
    Kernel        // kTLS kernel offload
};

/// SIMD capability level
enum class SimdLevel {
    None,         // Scalar only
    SSE42,        // SSE 4.2
    AVX2,         // AVX2
    AVX512,       // AVX-512
    NEON          // ARM NEON
};

/// Detect SIMD capability at runtime
[[nodiscard]] SimdLevel detect_simd_level() noexcept;

}  // namespace signet
