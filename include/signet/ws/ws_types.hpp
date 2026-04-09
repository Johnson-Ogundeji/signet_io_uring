// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ws_types.hpp
/// @brief WebSocket types, extending core types for RFC 6455 compliance

#pragma once

#include "signet/core/types.hpp"

#include <array>
#include <string_view>

namespace signet {

// Re-export core types for convenience
// (Opcode, CloseCode, is_valid_opcode, is_valid_close_code, etc. come from types.hpp)

// ============================================================================
// Additional WebSocket Type Aliases for API compatibility
// ============================================================================

using WsOpcode = Opcode;
using WsCloseCode = CloseCode;
using WsState = ReadyState;

/// Get opcode name for debugging
[[nodiscard]] constexpr std::string_view opcode_name(Opcode opcode) noexcept {
    switch (opcode) {
        case Opcode::Continuation: return "Continuation";
        case Opcode::Text: return "Text";
        case Opcode::Binary: return "Binary";
        case Opcode::Close: return "Close";
        case Opcode::Ping: return "Ping";
        case Opcode::Pong: return "Pong";
        default: return "Unknown";
    }
}

/// Get close code description
[[nodiscard]] constexpr std::string_view close_code_description(CloseCode code) noexcept {
    switch (code) {
        case CloseCode::Normal: return "Normal closure";
        case CloseCode::GoingAway: return "Going away";
        case CloseCode::ProtocolError: return "Protocol error";
        case CloseCode::UnsupportedData: return "Unsupported data";
        case CloseCode::NoStatus: return "No status received";
        case CloseCode::Abnormal: return "Abnormal closure";
        case CloseCode::InvalidPayload: return "Invalid payload";
        case CloseCode::PolicyViolation: return "Policy violation";
        case CloseCode::MessageTooBig: return "Message too big";
        case CloseCode::MissingExtension: return "Missing extension";
        case CloseCode::InternalError: return "Internal error";
        case CloseCode::TLSHandshake: return "TLS handshake failure";
        default: return "Unknown";
    }
}

/// Get state name for debugging
[[nodiscard]] constexpr std::string_view state_name(ReadyState state) noexcept {
    switch (state) {
        case ReadyState::Connecting: return "Connecting";
        case ReadyState::Open: return "Open";
        case ReadyState::Closing: return "Closing";
        case ReadyState::Closed: return "Closed";
        default: return "Unknown";
    }
}

// ============================================================================
// Frame Parse Result
// ============================================================================

/// Frame parse result
enum class WsParseResult : uint8_t {
    Complete,           // Frame header fully parsed
    NeedMoreData,       // Need more data to parse header
    InvalidOpcode,      // Invalid opcode
    ReservedBitSet,     // RSV bit set without extension
    ControlFrameTooBig, // Control frame > 125 bytes
    ControlFrameFragmented, // Control frame with FIN=0
    InvalidLength,      // Invalid length encoding
};

/// Get parse result description
[[nodiscard]] constexpr std::string_view parse_result_description(WsParseResult result) noexcept {
    switch (result) {
        case WsParseResult::Complete: return "Complete";
        case WsParseResult::NeedMoreData: return "Need more data";
        case WsParseResult::InvalidOpcode: return "Invalid opcode";
        case WsParseResult::ReservedBitSet: return "Reserved bit set";
        case WsParseResult::ControlFrameTooBig: return "Control frame too big";
        case WsParseResult::ControlFrameFragmented: return "Control frame fragmented";
        case WsParseResult::InvalidLength: return "Invalid length";
        default: return "Unknown";
    }
}

// ============================================================================
// WebSocket Frame Header (extended from core FrameHeader)
// ============================================================================

/// Alias for the frame header from types.hpp
using WsFrameHeader = FrameHeader;

// ============================================================================
// WebSocket Constants
// ============================================================================

namespace ws_constants {

/// Maximum control frame payload size (RFC 6455)
constexpr size_t kMaxControlFramePayload = 125;

/// Maximum frame header size (1 byte flags + 1 byte length + 8 bytes extended length + 4 bytes mask)
constexpr size_t kMaxFrameHeaderSize = 14;

/// Minimum frame header size (1 byte flags + 1 byte length)
constexpr size_t kMinFrameHeaderSize = 2;

/// WebSocket GUID for handshake (RFC 6455 Section 1.3)
constexpr std::string_view kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// HTTP upgrade required headers
constexpr std::string_view kUpgradeHeader = "websocket";
constexpr std::string_view kConnectionHeader = "Upgrade";
constexpr std::string_view kWebSocketVersion = "13";

/// Default maximum message size (16MB)
constexpr size_t kDefaultMaxMessageSize = 16 * 1024 * 1024;

/// Default receive buffer size (64KB)
constexpr size_t kDefaultReceiveBufferSize = 64 * 1024;

/// Default send buffer size (64KB)
constexpr size_t kDefaultSendBufferSize = 64 * 1024;

}  // namespace ws_constants

// ============================================================================
// WebSocket Message Type
// ============================================================================

enum class WsMessageType : uint8_t {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
};

/// Convert opcode to message type
[[nodiscard]] constexpr WsMessageType opcode_to_message_type(Opcode opcode) noexcept {
    switch (opcode) {
        case Opcode::Text: return WsMessageType::Text;
        case Opcode::Binary: return WsMessageType::Binary;
        case Opcode::Ping: return WsMessageType::Ping;
        case Opcode::Pong: return WsMessageType::Pong;
        case Opcode::Close: return WsMessageType::Close;
        default: return WsMessageType::Binary;  // Continuation inherits from first frame
    }
}

/// Convert message type to opcode.
///
/// SECURITY (MEDIUM #36/#37): Explicit default case so any future addition to
/// WsMessageType produces a compile warning instead of silently mapping to
/// Binary. The fallback after the switch covers the case where the enum has
/// an out-of-range value (e.g. memory corruption / casted int).
[[nodiscard]] constexpr Opcode message_type_to_opcode(WsMessageType type) noexcept {
    switch (type) {
        case WsMessageType::Text: return Opcode::Text;
        case WsMessageType::Binary: return Opcode::Binary;
        case WsMessageType::Ping: return Opcode::Ping;
        case WsMessageType::Pong: return Opcode::Pong;
        case WsMessageType::Close: return Opcode::Close;
    }
    // Unreachable for valid enum values; defensive fallback for corrupted state.
    return Opcode::Binary;
}

}  // namespace signet
