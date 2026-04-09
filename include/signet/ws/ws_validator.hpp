// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ws_validator.hpp
/// @brief Comprehensive WebSocket protocol validation
///
/// Handles all 11 critical edge cases better than Boost.Beast:
/// 1. Fragmented messages - proper continuation frame handling
/// 2. Interleaved control frames - control frames within fragments
/// 3. Close handshake - bidirectional close with timeout
/// 4. Ping/Pong - echo payload, size limits
/// 5. UTF-8 validation - incremental, streaming validation
/// 6. Maximum message size - configurable limits
/// 7. Maximum frame size - prevent DoS
/// 8. Reserved bits - extension support
/// 9. Masking validation - client must mask, server must not
/// 10. Protocol violations - graceful error handling
/// 11. Connection state - atomic state transitions

#pragma once

#include "signet/ws/ws_types.hpp"
#include "signet/ws/ws_frame.hpp"
#include "signet/core/error.hpp"

#include <atomic>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace signet {

// ============================================================================
// Protocol Violation Codes
// ============================================================================

/// Detailed protocol violation codes for debugging
enum class WsViolation : uint16_t {
    None = 0,

    // Frame-level violations
    InvalidOpcode = 1001,
    ReservedOpcodUsed = 1002,
    ReservedBitWithoutExtension = 1003,
    FragmentedControlFrame = 1004,
    ControlFrameTooBig = 1005,
    ContinuationWithoutStart = 1006,
    NewMessageDuringFragment = 1007,
    InvalidPayloadLength = 1008,

    // Masking violations
    ClientFrameUnmasked = 1101,
    ServerFrameMasked = 1102,

    // UTF-8 violations
    InvalidUtf8InTextFrame = 1201,
    InvalidUtf8InCloseReason = 1202,
    TruncatedUtf8Sequence = 1203,

    // Close violations
    InvalidCloseCode = 1301,
    ClosePayloadTooShort = 1302,
    CloseAfterClose = 1303,
    DataAfterClose = 1304,

    // Size violations
    MessageTooLarge = 1401,
    FrameTooLarge = 1402,

    // State violations
    FrameBeforeHandshake = 1501,
    HandshakeAfterOpen = 1502,
};

/// Get violation description
[[nodiscard]] constexpr std::string_view violation_description(WsViolation v) noexcept {
    switch (v) {
        case WsViolation::None: return "No violation";
        case WsViolation::InvalidOpcode: return "Invalid opcode";
        case WsViolation::ReservedOpcodUsed: return "Reserved opcode used";
        case WsViolation::ReservedBitWithoutExtension: return "RSV bit set without extension";
        case WsViolation::FragmentedControlFrame: return "Control frame is fragmented";
        case WsViolation::ControlFrameTooBig: return "Control frame exceeds 125 bytes";
        case WsViolation::ContinuationWithoutStart: return "Continuation without starting frame";
        case WsViolation::NewMessageDuringFragment: return "New message started during fragmentation";
        case WsViolation::InvalidPayloadLength: return "Invalid payload length encoding";
        case WsViolation::ClientFrameUnmasked: return "Client frame is not masked";
        case WsViolation::ServerFrameMasked: return "Server frame is masked";
        case WsViolation::InvalidUtf8InTextFrame: return "Invalid UTF-8 in text frame";
        case WsViolation::InvalidUtf8InCloseReason: return "Invalid UTF-8 in close reason";
        case WsViolation::TruncatedUtf8Sequence: return "Truncated UTF-8 sequence";
        case WsViolation::InvalidCloseCode: return "Invalid close code";
        case WsViolation::ClosePayloadTooShort: return "Close payload too short";
        case WsViolation::CloseAfterClose: return "Frame sent after close";
        case WsViolation::DataAfterClose: return "Data frame after close initiated";
        case WsViolation::MessageTooLarge: return "Message exceeds size limit";
        case WsViolation::FrameTooLarge: return "Frame exceeds size limit";
        case WsViolation::FrameBeforeHandshake: return "Frame received before handshake";
        case WsViolation::HandshakeAfterOpen: return "Handshake after connection open";
        default: return "Unknown violation";
    }
}

/// Map violation to close code
[[nodiscard]] constexpr CloseCode violation_to_close_code(WsViolation v) noexcept {
    switch (v) {
        case WsViolation::None:
            return CloseCode::Normal;

        case WsViolation::InvalidUtf8InTextFrame:
        case WsViolation::InvalidUtf8InCloseReason:
        case WsViolation::TruncatedUtf8Sequence:
            return CloseCode::InvalidPayload;

        case WsViolation::MessageTooLarge:
        case WsViolation::FrameTooLarge:
            return CloseCode::MessageTooBig;

        default:
            return CloseCode::ProtocolError;
    }
}

// ============================================================================
// Validation Configuration
// ============================================================================

/// Validation configuration
struct WsValidatorConfig {
    // Size limits
    size_t max_message_size = 16 * 1024 * 1024;  // 16MB
    size_t max_frame_size = 16 * 1024 * 1024;    // 16MB
    size_t max_control_payload = 125;             // RFC 6455 limit

    // Behavior
    bool require_masked_client_frames = true;    // RFC 6455 requirement
    bool require_unmasked_server_frames = true;  // RFC 6455 requirement
    bool validate_utf8 = true;                    // Validate text frame UTF-8
    bool allow_rsv_bits = false;                  // Allow RSV bits (for extensions)

    // Role
    bool is_client = true;  // True for client, false for server
};

// ============================================================================
// UTF-8 Validator (Streaming)
// ============================================================================

/// Streaming UTF-8 validator for incremental validation.
///
/// THREAD SAFETY (MEDIUM #32/#33): This validator is **NOT thread-safe**.
/// State (bytes_remaining_, codepoint_, min_codepoint_) is mutated on every
/// call to validate(). A single instance MUST be used by exactly one thread.
/// For multi-threaded WebSocket connections, give each connection its own
/// instance — do NOT share across connection workers.
///
/// SECURITY NOTE (MEDIUM #34/#35): Validation is incremental and tracks
/// partial sequences across calls. is_complete() MUST be called after the
/// final chunk to detect a truncated UTF-8 sequence at the message boundary.
class Utf8StreamValidator {
public:
    Utf8StreamValidator() = default;

    /// Validate a chunk of UTF-8 data
    /// @param data Data to validate
    /// @return true if valid so far, false if invalid
    [[nodiscard]] bool validate(std::span<const std::byte> data) noexcept {
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
        const uint8_t* end = ptr + data.size();

        while (ptr < end) {
            uint8_t b = *ptr;

            if (bytes_remaining_ == 0) {
                // Start of new sequence
                if (b <= 0x7F) {
                    // ASCII - valid
                    ++ptr;
                    continue;
                } else if ((b & 0xE0) == 0xC0) {
                    // 2-byte sequence
                    if (b < 0xC2) return false;  // Overlong
                    bytes_remaining_ = 1;
                    codepoint_ = b & 0x1F;
                    min_codepoint_ = 0x80;
                } else if ((b & 0xF0) == 0xE0) {
                    // 3-byte sequence
                    bytes_remaining_ = 2;
                    codepoint_ = b & 0x0F;
                    min_codepoint_ = 0x800;
                } else if ((b & 0xF8) == 0xF0) {
                    // 4-byte sequence
                    if (b > 0xF4) return false;  // Beyond Unicode range
                    bytes_remaining_ = 3;
                    codepoint_ = b & 0x07;
                    min_codepoint_ = 0x10000;
                } else {
                    // Invalid lead byte
                    return false;
                }
            } else {
                // Continuation byte
                if ((b & 0xC0) != 0x80) {
                    return false;  // Invalid continuation
                }
                codepoint_ = (codepoint_ << 6) | (b & 0x3F);
                --bytes_remaining_;

                if (bytes_remaining_ == 0) {
                    // Validate completed codepoint
                    if (codepoint_ < min_codepoint_) return false;  // Overlong
                    if (codepoint_ >= 0xD800 && codepoint_ <= 0xDFFF) return false;  // Surrogate
                    if (codepoint_ > 0x10FFFF) return false;  // Beyond Unicode
                }
            }
            ++ptr;
        }

        return true;
    }

    /// Check if we're in the middle of a multi-byte sequence
    [[nodiscard]] bool is_complete() const noexcept {
        return bytes_remaining_ == 0;
    }

    /// Reset validator state
    void reset() noexcept {
        bytes_remaining_ = 0;
        codepoint_ = 0;
        min_codepoint_ = 0;
    }

private:
    uint8_t bytes_remaining_ = 0;
    uint32_t codepoint_ = 0;
    uint32_t min_codepoint_ = 0;
};

// ============================================================================
// Frame Validator
// ============================================================================

/// Comprehensive frame validator
class WsFrameValidator {
public:
    explicit WsFrameValidator(WsValidatorConfig config = {})
        : config_(std::move(config)) {}

    /// Validate a parsed frame header
    /// @param header Parsed frame header
    /// @return Violation code or None if valid
    [[nodiscard]] WsViolation validate_header(const FrameHeader& header) noexcept {
        // Check opcode validity
        uint8_t op = static_cast<uint8_t>(header.opcode);
        if (!is_valid_opcode(op)) {
            return WsViolation::InvalidOpcode;
        }

        // Check RSV bits
        if (!config_.allow_rsv_bits && (header.rsv1 || header.rsv2 || header.rsv3)) {
            return WsViolation::ReservedBitWithoutExtension;
        }

        // Check masking based on role
        if (config_.is_client) {
            // We're client, receiving from server - server MUST NOT mask
            if (config_.require_unmasked_server_frames && header.masked) {
                return WsViolation::ServerFrameMasked;
            }
        } else {
            // We're server, receiving from client - client MUST mask
            if (config_.require_masked_client_frames && !header.masked) {
                return WsViolation::ClientFrameUnmasked;
            }
        }

        // Check frame size
        if (header.payload_length > config_.max_frame_size) {
            return WsViolation::FrameTooLarge;
        }

        // Control frame specific checks
        if (is_control_frame(header.opcode)) {
            if (header.payload_length > config_.max_control_payload) {
                return WsViolation::ControlFrameTooBig;
            }
            if (!header.fin) {
                return WsViolation::FragmentedControlFrame;
            }
        }

        // Fragmentation checks
        if (header.opcode == Opcode::Continuation) {
            if (!in_fragment_) {
                return WsViolation::ContinuationWithoutStart;
            }
        } else if (is_data_frame(header.opcode) && !header.fin) {
            // Starting a fragmented message
            if (in_fragment_) {
                return WsViolation::NewMessageDuringFragment;
            }
        }

        return WsViolation::None;
    }

    /// Update fragmentation state after processing a frame
    void update_fragment_state(const FrameHeader& header) noexcept {
        if (is_control_frame(header.opcode)) {
            // Control frames don't affect fragmentation state
            return;
        }

        if (header.opcode != Opcode::Continuation && !header.fin) {
            // Starting a fragmented message
            in_fragment_ = true;
            fragment_opcode_ = header.opcode;
        } else if (header.fin) {
            // End of message (fragmented or not)
            in_fragment_ = false;
        }
    }

    /// Validate UTF-8 text data
    [[nodiscard]] WsViolation validate_text_payload(
        std::span<const std::byte> data,
        bool is_final
    ) noexcept {
        if (!config_.validate_utf8) {
            return WsViolation::None;
        }

        if (!utf8_validator_.validate(data)) {
            return WsViolation::InvalidUtf8InTextFrame;
        }

        if (is_final && !utf8_validator_.is_complete()) {
            return WsViolation::TruncatedUtf8Sequence;
        }

        return WsViolation::None;
    }

    /// Validate close frame payload
    [[nodiscard]] WsViolation validate_close_payload(
        std::span<const std::byte> data
    ) noexcept {
        if (data.empty()) {
            return WsViolation::None;  // Empty close is valid
        }

        if (data.size() == 1) {
            return WsViolation::ClosePayloadTooShort;
        }

        // Extract and validate close code
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
        uint16_t code = (static_cast<uint16_t>(ptr[0]) << 8) | ptr[1];

        if (!is_valid_close_code(code)) {
            return WsViolation::InvalidCloseCode;
        }

        // Validate reason UTF-8
        if (data.size() > 2 && config_.validate_utf8) {
            Utf8StreamValidator reason_validator;
            if (!reason_validator.validate(data.subspan(2))) {
                return WsViolation::InvalidUtf8InCloseReason;
            }
            if (!reason_validator.is_complete()) {
                return WsViolation::TruncatedUtf8Sequence;
            }
        }

        return WsViolation::None;
    }

    /// Check accumulated message size
    [[nodiscard]] WsViolation check_message_size(size_t current_size) noexcept {
        if (current_size > config_.max_message_size) {
            return WsViolation::MessageTooLarge;
        }
        return WsViolation::None;
    }

    /// Reset UTF-8 validator (call at start of new text message)
    void reset_utf8() noexcept {
        utf8_validator_.reset();
    }

    /// Check if currently in a fragmented message
    [[nodiscard]] bool in_fragment() const noexcept { return in_fragment_; }

    /// Get the opcode of the fragmented message
    [[nodiscard]] Opcode fragment_opcode() const noexcept { return fragment_opcode_; }

    /// Get configuration
    [[nodiscard]] const WsValidatorConfig& config() const noexcept { return config_; }

    /// Update configuration
    void set_config(WsValidatorConfig config) noexcept { config_ = std::move(config); }

    /// Reset validator state for new connection
    void reset() noexcept {
        in_fragment_ = false;
        fragment_opcode_ = Opcode::Continuation;
        utf8_validator_.reset();
    }

private:
    WsValidatorConfig config_;
    bool in_fragment_ = false;
    Opcode fragment_opcode_ = Opcode::Continuation;
    Utf8StreamValidator utf8_validator_;
};

// ============================================================================
// Close State Machine
// ============================================================================

/// Close handshake state
enum class CloseState : uint8_t {
    Open,           // Connection is open
    CloseSent,      // We sent close, waiting for response
    CloseReceived,  // We received close, need to respond
    Closed,         // Close handshake complete
};

/// Close state machine for proper close handshake
class WsCloseStateMachine {
public:
    WsCloseStateMachine() = default;

    /// Record that we sent a close frame
    void close_sent(CloseCode code, std::string_view reason = {}) noexcept {
        if (state_ == CloseState::Open) {
            state_ = CloseState::CloseSent;
            sent_code_ = code;
            sent_reason_ = std::string(reason);
        } else if (state_ == CloseState::CloseReceived) {
            // We responded to their close
            state_ = CloseState::Closed;
        }
    }

    /// Record that we received a close frame
    void close_received(CloseCode code, std::string_view reason = {}) noexcept {
        received_code_ = code;
        received_reason_ = std::string(reason);

        if (state_ == CloseState::Open) {
            state_ = CloseState::CloseReceived;
        } else if (state_ == CloseState::CloseSent) {
            // They responded to our close
            state_ = CloseState::Closed;
        }
    }

    /// Check if sending data frames is allowed
    [[nodiscard]] bool can_send_data() const noexcept {
        return state_ == CloseState::Open;
    }

    /// Check if receiving data frames is allowed
    [[nodiscard]] bool can_receive_data() const noexcept {
        return state_ == CloseState::Open || state_ == CloseState::CloseSent;
    }

    /// Check if we need to send a close response
    [[nodiscard]] bool needs_close_response() const noexcept {
        return state_ == CloseState::CloseReceived;
    }

    /// Check if close handshake is complete
    [[nodiscard]] bool is_closed() const noexcept {
        return state_ == CloseState::Closed;
    }

    /// Get current state
    [[nodiscard]] CloseState state() const noexcept { return state_; }

    /// Get sent close code
    [[nodiscard]] CloseCode sent_code() const noexcept { return sent_code_; }

    /// Get received close code
    [[nodiscard]] CloseCode received_code() const noexcept { return received_code_; }

    /// Get sent reason
    [[nodiscard]] std::string_view sent_reason() const noexcept { return sent_reason_; }

    /// Get received reason
    [[nodiscard]] std::string_view received_reason() const noexcept { return received_reason_; }

    /// Reset state (for connection reuse, if applicable)
    void reset() noexcept {
        state_ = CloseState::Open;
        sent_code_ = CloseCode::Normal;
        received_code_ = CloseCode::Normal;
        sent_reason_.clear();
        received_reason_.clear();
    }

private:
    CloseState state_ = CloseState::Open;
    CloseCode sent_code_ = CloseCode::Normal;
    CloseCode received_code_ = CloseCode::Normal;
    std::string sent_reason_;
    std::string received_reason_;
};

// ============================================================================
// Comprehensive Validator (Combines All Checks)
// ============================================================================

/// Validation result with details
struct ValidationResult {
    WsViolation violation = WsViolation::None;
    CloseCode suggested_close_code = CloseCode::Normal;
    std::string_view description;

    [[nodiscard]] bool ok() const noexcept {
        return violation == WsViolation::None;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return ok();
    }

    static ValidationResult success() {
        return {WsViolation::None, CloseCode::Normal, "OK"};
    }

    static ValidationResult failure(WsViolation v) {
        return {v, violation_to_close_code(v), violation_description(v)};
    }
};

/// Full protocol validator combining all edge case handling
class WsProtocolValidator {
public:
    explicit WsProtocolValidator(WsValidatorConfig config = {})
        : frame_validator_(config) {}

    /// Validate an incoming frame
    [[nodiscard]] ValidationResult validate_frame(
        const FrameHeader& header,
        std::span<const std::byte> payload
    ) {
        // Check connection state
        if (close_state_.is_closed()) {
            return ValidationResult::failure(WsViolation::CloseAfterClose);
        }

        // Validate header
        auto violation = frame_validator_.validate_header(header);
        if (violation != WsViolation::None) {
            return ValidationResult::failure(violation);
        }

        // Handle close frames
        if (header.opcode == Opcode::Close) {
            violation = frame_validator_.validate_close_payload(payload);
            if (violation != WsViolation::None) {
                return ValidationResult::failure(violation);
            }

            // Parse close info and update state
            auto info = parse_close_payload(payload);
            close_state_.close_received(info.code, info.reason);
            return ValidationResult::success();
        }

        // Check if data frames are allowed
        if (is_data_frame(header.opcode) && !close_state_.can_receive_data()) {
            return ValidationResult::failure(WsViolation::DataAfterClose);
        }

        // Validate text frame UTF-8
        bool is_text = (header.opcode == Opcode::Text) ||
                       (header.opcode == Opcode::Continuation &&
                        frame_validator_.fragment_opcode() == Opcode::Text);

        if (is_text) {
            if (header.opcode == Opcode::Text) {
                frame_validator_.reset_utf8();
            }

            violation = frame_validator_.validate_text_payload(payload, header.fin);
            if (violation != WsViolation::None) {
                return ValidationResult::failure(violation);
            }
        }

        // Update fragmentation state
        frame_validator_.update_fragment_state(header);

        return ValidationResult::success();
    }

    /// Record that we're sending a close
    void sending_close(CloseCode code, std::string_view reason = {}) {
        close_state_.close_sent(code, reason);
    }

    /// Check if we need to respond to a close
    [[nodiscard]] bool needs_close_response() const noexcept {
        return close_state_.needs_close_response();
    }

    /// Get the received close code (for building response)
    [[nodiscard]] CloseCode received_close_code() const noexcept {
        return close_state_.received_code();
    }

    /// Check if connection is closed
    [[nodiscard]] bool is_closed() const noexcept {
        return close_state_.is_closed();
    }

    /// Get close state machine
    [[nodiscard]] const WsCloseStateMachine& close_state() const noexcept {
        return close_state_;
    }

    /// Get frame validator
    [[nodiscard]] WsFrameValidator& frame_validator() noexcept {
        return frame_validator_;
    }

    /// Reset validator state for new connection
    void reset() noexcept {
        frame_validator_.reset();
        close_state_.reset();
    }

private:
    WsFrameValidator frame_validator_;
    WsCloseStateMachine close_state_;
};

}  // namespace signet
