// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ws_frame.hpp
/// @brief High-performance WebSocket frame parser and builder (RFC 6455)
///
/// Design goals:
/// - Zero-copy parsing where possible
/// - Single-pass parsing (no backtracking)
/// - Minimal branching in hot path
/// - Cache-friendly memory access patterns
/// - Benchmarking-friendly (all operations measurable)

#pragma once

#include "signet/ws/ws_types.hpp"
#include "signet/core/metrics.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

namespace signet {

// ============================================================================
// Frame Parser
// ============================================================================

/// High-performance WebSocket frame parser
/// Parses frames incrementally without buffering
class WsFrameParser {
public:
    WsFrameParser() = default;

    /// Parse frame header from buffer
    /// @param data Input buffer
    /// @return Parse result
    [[nodiscard]] WsParseResult parse_header(std::span<const std::byte> data) noexcept {
        SIGNET_TIMER_SCOPE(metrics::kWsFrameParse);

        if (data.size() < ws_constants::kMinFrameHeaderSize) {
            return WsParseResult::NeedMoreData;
        }

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());

        // First byte: FIN, RSV1-3, opcode
        uint8_t byte0 = ptr[0];
        header_.fin = (byte0 & 0x80) != 0;
        header_.rsv1 = (byte0 & 0x40) != 0;
        header_.rsv2 = (byte0 & 0x20) != 0;
        header_.rsv3 = (byte0 & 0x10) != 0;
        uint8_t opcode = byte0 & 0x0F;

        // Validate opcode
        if (!is_valid_opcode(opcode)) {
            return WsParseResult::InvalidOpcode;
        }
        header_.opcode = static_cast<WsOpcode>(opcode);

        // Validate RSV bits (must be 0 unless extension negotiated)
        if (!allow_rsv_bits_ && (header_.rsv1 || header_.rsv2 || header_.rsv3)) {
            return WsParseResult::ReservedBitSet;
        }

        // Second byte: MASK flag and payload length
        uint8_t byte1 = ptr[1];
        header_.masked = (byte1 & 0x80) != 0;
        uint8_t len7 = byte1 & 0x7F;

        size_t header_size = 2;
        uint64_t payload_len = 0;

        if (len7 <= 125) {
            // Length fits in 7 bits
            payload_len = len7;
        } else if (len7 == 126) {
            // 16-bit length follows
            header_size = 4;
            if (data.size() < header_size) {
                return WsParseResult::NeedMoreData;
            }
            // Network byte order (big endian)
            payload_len = (static_cast<uint64_t>(ptr[2]) << 8) |
                          static_cast<uint64_t>(ptr[3]);
            // Must use minimal encoding
            if (payload_len < 126) {
                return WsParseResult::InvalidLength;
            }
        } else {  // len7 == 127
            // 64-bit length follows
            header_size = 10;
            if (data.size() < header_size) {
                return WsParseResult::NeedMoreData;
            }
            // Network byte order (big endian)
            payload_len = (static_cast<uint64_t>(ptr[2]) << 56) |
                          (static_cast<uint64_t>(ptr[3]) << 48) |
                          (static_cast<uint64_t>(ptr[4]) << 40) |
                          (static_cast<uint64_t>(ptr[5]) << 32) |
                          (static_cast<uint64_t>(ptr[6]) << 24) |
                          (static_cast<uint64_t>(ptr[7]) << 16) |
                          (static_cast<uint64_t>(ptr[8]) << 8) |
                          static_cast<uint64_t>(ptr[9]);
            // MSB must be 0 (per RFC 6455)
            if (payload_len >> 63) {
                return WsParseResult::InvalidLength;
            }
            // Must use minimal encoding
            if (payload_len <= 0xFFFF) {
                return WsParseResult::InvalidLength;
            }
        }

        // Read mask key if present
        if (header_.masked) {
            if (data.size() < header_size + 4) {
                return WsParseResult::NeedMoreData;
            }
            std::memcpy(header_.masking_key.data(), ptr + header_size, 4);
            header_size += 4;
        }

        header_.payload_length = payload_len;
        header_.header_size = header_size;

        // Validate control frame constraints
        if (is_control_frame(header_.opcode)) {
            if (payload_len > ws_constants::kMaxControlFramePayload) {
                return WsParseResult::ControlFrameTooBig;
            }
            if (!header_.fin) {
                return WsParseResult::ControlFrameFragmented;
            }
        }

        SIGNET_COUNTER_INC("ws.frames_parsed");
        return WsParseResult::Complete;
    }

    /// Get parsed header (valid after Complete result)
    [[nodiscard]] const WsFrameHeader& header() const noexcept { return header_; }

    /// Reset parser state
    void reset() noexcept {
        header_ = WsFrameHeader{};
        header_.opcode = Opcode::Continuation;  // Reset to "unset" state
        header_.fin = false;  // Reset to not final
    }

    /// Allow RSV bits (for extensions like permessage-deflate)
    void allow_rsv_bits(bool allow) noexcept { allow_rsv_bits_ = allow; }

private:
    WsFrameHeader header_;
    bool allow_rsv_bits_ = false;
};

// ============================================================================
// Frame Builder
// ============================================================================

/// High-performance WebSocket frame builder
/// Builds frames in-place without intermediate copies
class WsFrameBuilder {
public:
    WsFrameBuilder() = default;

    /// Build a complete frame header
    /// @param opcode Frame opcode
    /// @param payload_length Payload length
    /// @param fin Final fragment flag
    /// @param mask Apply masking (required for client->server)
    /// @param masking_key Masking key (used if mask=true)
    /// @param rsv1 RSV1 bit (for extensions)
    /// @return Header bytes
    [[nodiscard]] std::span<const std::byte> build_header(
        WsOpcode opcode,
        uint64_t payload_length,
        bool fin = true,
        bool mask = true,
        const std::array<uint8_t, 4>& masking_key = {},
        bool rsv1 = false
    ) noexcept {
        SIGNET_TIMER_SCOPE(metrics::kWsFrameBuild);

        uint8_t* ptr = header_buffer_;
        size_t offset = 0;

        // Byte 0: FIN, RSV, opcode
        uint8_t byte0 = static_cast<uint8_t>(opcode);
        if (fin) byte0 |= 0x80;
        if (rsv1) byte0 |= 0x40;
        ptr[offset++] = byte0;

        // Byte 1: MASK flag and length
        uint8_t byte1 = mask ? 0x80 : 0x00;

        if (payload_length <= 125) {
            byte1 |= static_cast<uint8_t>(payload_length);
            ptr[offset++] = byte1;
        } else if (payload_length <= 0xFFFF) {
            byte1 |= 126;
            ptr[offset++] = byte1;
            // 16-bit length in network order
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 8);
            ptr[offset++] = static_cast<uint8_t>(payload_length);
        } else {
            byte1 |= 127;
            ptr[offset++] = byte1;
            // 64-bit length in network order
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 56);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 48);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 40);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 32);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 24);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 16);
            ptr[offset++] = static_cast<uint8_t>(payload_length >> 8);
            ptr[offset++] = static_cast<uint8_t>(payload_length);
        }

        // Mask key (if masking)
        if (mask) {
            std::memcpy(ptr + offset, masking_key.data(), 4);
            offset += 4;
        }

        header_size_ = offset;
        SIGNET_COUNTER_INC("ws.frames_built");
        return {reinterpret_cast<std::byte*>(header_buffer_), header_size_};
    }

    /// Build a close frame payload
    /// @param code Close code
    /// @param reason Close reason (optional, max 123 bytes)
    /// @return Payload bytes (code + reason)
    [[nodiscard]] std::span<const std::byte> build_close_payload(
        WsCloseCode code,
        std::string_view reason = {}
    ) noexcept {
        uint8_t* ptr = close_payload_;
        size_t offset = 0;

        // 2-byte close code in network order
        uint16_t code_val = static_cast<uint16_t>(code);
        ptr[offset++] = static_cast<uint8_t>(code_val >> 8);
        ptr[offset++] = static_cast<uint8_t>(code_val);

        // Optional reason string (max 123 bytes to fit in control frame)
        size_t reason_len = std::min(reason.size(), size_t{123});
        if (reason_len > 0) {
            std::memcpy(ptr + offset, reason.data(), reason_len);
            offset += reason_len;
        }

        close_payload_size_ = offset;
        return {reinterpret_cast<std::byte*>(close_payload_), close_payload_size_};
    }

    /// Get last built header size
    [[nodiscard]] size_t header_size() const noexcept { return header_size_; }

    /// Build complete frame into output buffer
    /// @param output Output buffer (must be large enough)
    /// @param opcode Frame opcode
    /// @param payload Payload data
    /// @param mask Apply masking
    /// @param masking_key Masking key
    /// @param fin Final fragment
    /// @return Number of bytes written
    [[nodiscard]] size_t build_frame(
        std::span<std::byte> output,
        WsOpcode opcode,
        std::span<const std::byte> payload,
        bool mask = true,
        const std::array<uint8_t, 4>& masking_key = {},
        bool fin = true
    ) noexcept {
        auto header = build_header(opcode, payload.size(), fin, mask, masking_key);

        // SECURITY: Check for integer overflow before computing total size.
        // header.size() + payload.size() could wrap if payload is enormous,
        // producing a small total_size that bypasses the bounds check below
        // and corrupts memory in std::memcpy.
        if (payload.size() > std::numeric_limits<size_t>::max() - header.size()) {
            return 0;  // Overflow — refuse to build
        }
        size_t total_size = header.size() + payload.size();

        if (output.size() < total_size) {
            return 0;  // Buffer too small
        }

        // Copy header
        std::memcpy(output.data(), header.data(), header.size());

        // Copy payload (with masking if needed)
        if (mask && !payload.empty()) {
            apply_mask(
                reinterpret_cast<uint8_t*>(output.data() + header.size()),
                reinterpret_cast<const uint8_t*>(payload.data()),
                payload.size(),
                masking_key
            );
        } else if (!payload.empty()) {
            std::memcpy(output.data() + header.size(), payload.data(), payload.size());
        }

        return total_size;
    }

    /// Calculate required buffer size for a frame
    /// @return Required size, or 0 if payload_length would overflow size_t
    [[nodiscard]] static constexpr size_t frame_size(
        uint64_t payload_length,
        bool mask
    ) noexcept {
        size_t header_size = 2;  // Base header
        if (payload_length > 125) {
            header_size += (payload_length <= 0xFFFF) ? 2 : 8;
        }
        if (mask) {
            header_size += 4;
        }

        // SECURITY: Reject payloads that don't fit in size_t.
        // On 32-bit, payload_length (uint64) may exceed SIZE_MAX.
        // On 64-bit, addition could still wrap if payload is near SIZE_MAX.
        if (payload_length > std::numeric_limits<size_t>::max() - header_size) {
            return 0;  // Overflow — caller must treat as error
        }
        return header_size + static_cast<size_t>(payload_length);
    }

private:
    /// Apply XOR mask to data
    static void apply_mask(
        uint8_t* dest,
        const uint8_t* src,
        size_t len,
        const std::array<uint8_t, 4>& mask
    ) noexcept {
        SIGNET_TIMER_SCOPE(metrics::kWsMaskApply);

        // Process 8 bytes at a time for better performance
        size_t i = 0;

#if defined(__x86_64__) || defined(_M_X64)
        // Extend mask to 64-bit for vectorized operation
        if (len >= 8) {
            uint64_t mask64 = static_cast<uint64_t>(mask[0]) |
                             (static_cast<uint64_t>(mask[1]) << 8) |
                             (static_cast<uint64_t>(mask[2]) << 16) |
                             (static_cast<uint64_t>(mask[3]) << 24) |
                             (static_cast<uint64_t>(mask[0]) << 32) |
                             (static_cast<uint64_t>(mask[1]) << 40) |
                             (static_cast<uint64_t>(mask[2]) << 48) |
                             (static_cast<uint64_t>(mask[3]) << 56);

            for (; i + 8 <= len; i += 8) {
                uint64_t data;
                std::memcpy(&data, src + i, 8);
                data ^= mask64;
                std::memcpy(dest + i, &data, 8);
            }
        }
#endif

        // Process remaining bytes
        for (; i < len; ++i) {
            dest[i] = src[i] ^ mask[i & 3];
        }

        SIGNET_COUNTER_ADD("ws.bytes_masked", len);
    }

    uint8_t header_buffer_[ws_constants::kMaxFrameHeaderSize]{};
    size_t header_size_ = 0;
    uint8_t close_payload_[ws_constants::kMaxControlFramePayload]{};
    size_t close_payload_size_ = 0;
};

// ============================================================================
// Masking Utilities
// ============================================================================

/// Generate a random masking key
/// Uses fast PRNG suitable for masking (not cryptographic)
[[nodiscard]] inline std::array<uint8_t, 4> generate_masking_key() noexcept {
    // Simple LCG for fast mask generation (not for crypto!)
    static thread_local uint32_t state = 0x12345678;
    state = state * 1103515245 + 12345;

    std::array<uint8_t, 4> key;
    key[0] = static_cast<uint8_t>(state >> 24);
    key[1] = static_cast<uint8_t>(state >> 16);
    key[2] = static_cast<uint8_t>(state >> 8);
    key[3] = static_cast<uint8_t>(state);
    return key;
}

/// Apply mask in-place
inline void apply_mask_inplace(
    std::span<std::byte> data,
    const std::array<uint8_t, 4>& mask
) noexcept {
    SIGNET_TIMER_SCOPE(metrics::kWsMaskApply);

    uint8_t* ptr = reinterpret_cast<uint8_t*>(data.data());
    size_t len = data.size();
    size_t i = 0;

#if defined(__x86_64__) || defined(_M_X64)
    if (len >= 8) {
        uint64_t mask64 = static_cast<uint64_t>(mask[0]) |
                         (static_cast<uint64_t>(mask[1]) << 8) |
                         (static_cast<uint64_t>(mask[2]) << 16) |
                         (static_cast<uint64_t>(mask[3]) << 24) |
                         (static_cast<uint64_t>(mask[0]) << 32) |
                         (static_cast<uint64_t>(mask[1]) << 40) |
                         (static_cast<uint64_t>(mask[2]) << 48) |
                         (static_cast<uint64_t>(mask[3]) << 56);

        for (; i + 8 <= len; i += 8) {
            uint64_t* p64 = reinterpret_cast<uint64_t*>(ptr + i);
            *p64 ^= mask64;
        }
    }
#endif

    for (; i < len; ++i) {
        ptr[i] ^= mask[i & 3];
    }
}

/// Parse close frame payload
struct WsCloseInfo {
    WsCloseCode code = WsCloseCode::NoStatus;
    std::string_view reason;
    bool valid = false;
};

[[nodiscard]] inline WsCloseInfo parse_close_payload(std::span<const std::byte> payload) noexcept {
    WsCloseInfo info;

    if (payload.empty()) {
        // Empty payload is valid (no status code)
        info.valid = true;
        return info;
    }

    if (payload.size() < 2) {
        // Invalid: must have at least 2 bytes for close code
        return info;
    }

    // Extract close code (network byte order)
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(payload.data());
    uint16_t code = (static_cast<uint16_t>(ptr[0]) << 8) | static_cast<uint16_t>(ptr[1]);

    if (!is_valid_close_code(code)) {
        return info;
    }

    info.code = static_cast<WsCloseCode>(code);

    // Extract reason (if present)
    if (payload.size() > 2) {
        info.reason = std::string_view(
            reinterpret_cast<const char*>(payload.data() + 2),
            payload.size() - 2
        );
    }

    info.valid = true;
    return info;
}

}  // namespace signet
