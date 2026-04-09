// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ws_connection.hpp
/// @brief WebSocket connection with full RFC 6455 compliance
///
/// This class provides a complete WebSocket client implementation with:
/// - Automatic handshake handling
/// - Message fragmentation/reassembly
/// - Control frame processing (ping/pong/close)
/// - Automatic masking (client->server)
/// - UTF-8 validation for text frames
/// - Graceful close handshake

#pragma once

#include "signet/ws/ws_types.hpp"
#include "signet/ws/ws_frame.hpp"
#include "signet/ws/ws_handshake.hpp"
#include "signet/tls/tls_connection.hpp"
#include "signet/net/resolver.hpp"
#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"

#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace signet {

// ============================================================================
// WebSocket Configuration
// ============================================================================

/// WebSocket connection configuration
struct WsConfig {
    // Handshake
    WsHandshakeConfig handshake;

    // Limits
    size_t max_message_size = ws_constants::kDefaultMaxMessageSize;
    size_t max_frame_size = 16 * 1024 * 1024;  // 16MB
    size_t receive_buffer_size = ws_constants::kDefaultReceiveBufferSize;
    size_t send_buffer_size = ws_constants::kDefaultSendBufferSize;

    // Behavior
    bool auto_respond_ping = true;      // Automatically send pong for ping
    bool auto_respond_close = true;     // Automatically respond to close
    bool validate_utf8 = true;          // Validate UTF-8 in text messages
    bool allow_rsv_bits = false;        // Allow RSV bits (for extensions)

    // Timeouts (0 = no timeout)
    uint32_t connect_timeout_ms = 10000;
    uint32_t handshake_timeout_ms = 10000;
    uint32_t idle_timeout_ms = 0;
    uint32_t close_timeout_ms = 5000;
};

// ============================================================================
// WebSocket Message
// ============================================================================

/// Received WebSocket message
struct WsMessage {
    WsMessageType type;
    std::vector<std::byte> data;

    /// Get data as string (for text messages)
    [[nodiscard]] std::string_view as_string() const {
        return {reinterpret_cast<const char*>(data.data()), data.size()};
    }

    /// Get close info (for close messages)
    [[nodiscard]] WsCloseInfo close_info() const {
        if (type != WsMessageType::Close) {
            return {};
        }
        return parse_close_payload(data);
    }
};

// ============================================================================
// WebSocket Events
// ============================================================================

/// Event callbacks for WebSocket connection
struct WsCallbacks {
    /// Called when connection is established (after handshake)
    std::function<void()> on_open;

    /// Called when a message is received
    std::function<void(WsMessage)> on_message;

    /// Called when connection is closed
    std::function<void(WsCloseCode, std::string_view reason)> on_close;

    /// Called on error
    std::function<void(const Error&)> on_error;

    /// Called when ping is received (before auto pong)
    std::function<void(std::span<const std::byte>)> on_ping;

    /// Called when pong is received
    std::function<void(std::span<const std::byte>)> on_pong;
};

// ============================================================================
// WebSocket Connection Statistics
// ============================================================================

struct WsConnectionStats {
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t frames_sent = 0;
    uint64_t frames_received = 0;
    uint64_t pings_sent = 0;
    uint64_t pongs_sent = 0;
    uint64_t pings_received = 0;
    uint64_t pongs_received = 0;
};

// ============================================================================
// WebSocket Connection
// ============================================================================

/// WebSocket connection over TLS
class WsConnection {
public:
    /// Create connection with TLS transport
    explicit WsConnection(TlsConnection tls, WsConfig config = {})
        : tls_(std::move(tls))
        , config_(std::move(config))
    {
        recv_buffer_.resize(config_.receive_buffer_size);
        send_buffer_.resize(config_.send_buffer_size);
        frame_parser_.allow_rsv_bits(config_.allow_rsv_bits);
    }

    // Non-copyable, movable
    WsConnection(const WsConnection&) = delete;
    WsConnection& operator=(const WsConnection&) = delete;
    WsConnection(WsConnection&&) = default;
    WsConnection& operator=(WsConnection&&) = default;

    ~WsConnection() {
        // SECURITY (CRITICAL #10): Suppress user callbacks during destructor.
        // close_sync() fires on_close, and if a user callback re-enters this
        // object (now half-destroyed), we get UAF. Wipe callbacks first so the
        // best-effort close is purely a wire-protocol shutdown.
        callbacks_ = WsCallbacks{};
        if (state_ == WsState::Open || state_ == WsState::Closing) {
            // Best effort close
            (void)close_sync(WsCloseCode::GoingAway);
        }
    }

    // ========================================================================
    // Connection Lifecycle
    // ========================================================================

    /// Perform WebSocket handshake (blocking)
    [[nodiscard]] Expected<void> handshake_sync() {
        if (state_ != WsState::Connecting) {
            return unexpected(ErrorCode::InvalidState, "Not in connecting state");
        }

        // Initialize handshake
        handshake_.init(config_.handshake);

        // Send handshake request
        auto request = handshake_.request();
        auto send_result = tls_.write({
            reinterpret_cast<const std::byte*>(request.data()),
            request.size()
        });
        if (!send_result) {
            return unexpected(send_result.error());
        }
        handshake_.request_sent();

        // Read handshake response.
        // SECURITY (HIGH #30): cap the response buffer growth so a malicious
        // peer cannot make us OOM by streaming an infinite header. Real HTTP
        // upgrade responses are well under 8 KB; 64 KB is generous.
        constexpr size_t kMaxHandshakeResponseBytes = 64 * 1024;
        size_t handshake_bytes_read = 0;
        while (!handshake_.complete()) {
            auto read_result = tls_.read(recv_buffer_);
            if (!read_result) {
                return unexpected(read_result.error());
            }
            if (*read_result == 0) {
                return unexpected(ErrorCode::ConnectionClosed, "Connection closed during handshake");
            }
            handshake_bytes_read += *read_result;
            if (handshake_bytes_read > kMaxHandshakeResponseBytes) {
                return unexpected(ErrorCode::WebSocketHandshakeFailed,
                    "Handshake response exceeds maximum allowed size");
            }
            (void)handshake_.feed({recv_buffer_.data(), *read_result});
        }

        // Check result
        if (!handshake_.success()) {
            return unexpected(ErrorCode::WebSocketHandshakeFailed,
                std::string(handshake_result_description(handshake_.result())));
        }

        // Store any remaining data after handshake
        auto remaining = handshake_.remaining_data();
        if (!remaining.empty()) {
            pending_data_.assign(remaining.begin(), remaining.end());
        }

        state_ = WsState::Open;
        selected_protocol_ = std::string(handshake_.selected_protocol());

        if (callbacks_.on_open) {
            callbacks_.on_open();
        }

        return {};
    }

    /// Send a text message (blocking)
    [[nodiscard]] Expected<void> send_text(std::string_view text) {
        return send_message(WsOpcode::Text, {
            reinterpret_cast<const std::byte*>(text.data()),
            text.size()
        });
    }

    /// Send a binary message (blocking)
    [[nodiscard]] Expected<void> send_binary(std::span<const std::byte> data) {
        return send_message(WsOpcode::Binary, data);
    }

    /// Send a ping (blocking)
    [[nodiscard]] Expected<void> send_ping(std::span<const std::byte> data = {}) {
        if (data.size() > ws_constants::kMaxControlFramePayload) {
            return unexpected(ErrorCode::InvalidArgument, "Ping payload too large");
        }
        auto result = send_frame(WsOpcode::Ping, data, true);
        if (result) {
            ++stats_.pings_sent;
        }
        return result;
    }

    /// Send a pong (blocking)
    [[nodiscard]] Expected<void> send_pong(std::span<const std::byte> data = {}) {
        if (data.size() > ws_constants::kMaxControlFramePayload) {
            return unexpected(ErrorCode::InvalidArgument, "Pong payload too large");
        }
        auto result = send_frame(WsOpcode::Pong, data, true);
        if (result) {
            ++stats_.pongs_sent;
        }
        return result;
    }

    /// Initiate graceful close (blocking)
    [[nodiscard]] Expected<void> close_sync(
        WsCloseCode code = WsCloseCode::Normal,
        std::string_view reason = {}
    ) {
        if (state_ == WsState::Closed) {
            return {};  // Already closed
        }

        if (state_ == WsState::Open) {
            // Send close frame
            auto close_payload = frame_builder_.build_close_payload(code, reason);
            auto result = send_frame(WsOpcode::Close, close_payload, true);
            if (!result) {
                state_ = WsState::Closed;
                tls_.close_sync();
                return result;
            }
            state_ = WsState::Closing;
        }

        // Wait for close response or timeout
        // For simplicity in sync mode, just close immediately
        state_ = WsState::Closed;
        tls_.close_sync();

        if (callbacks_.on_close) {
            callbacks_.on_close(code, reason);
        }

        return {};
    }

    /// Read and process one message (blocking)
    /// @return Message or nullopt if connection closed
    [[nodiscard]] Expected<std::optional<WsMessage>> read_message() {
        if (state_ != WsState::Open && state_ != WsState::Closing) {
            return unexpected(ErrorCode::InvalidState, "Connection not open");
        }

        while (true) {
            // Try to read a frame
            auto frame_result = read_frame();
            if (!frame_result) {
                return unexpected(frame_result.error());
            }

            auto& [header, payload] = *frame_result;

            // Handle control frames
            if (is_control_frame(header.opcode)) {
                auto control_result = handle_control_frame(header, payload);
                if (!control_result) {
                    return unexpected(control_result.error());
                }

                // If close received, return empty
                if (header.opcode == WsOpcode::Close) {
                    return std::nullopt;
                }

                // Continue reading for data frames
                continue;
            }

            // Handle data frame
            return handle_data_frame(header, payload);
        }
    }

    // ========================================================================
    // State & Info
    // ========================================================================

    /// Get connection state
    [[nodiscard]] WsState state() const noexcept { return state_; }

    /// Check if connected and open
    [[nodiscard]] bool is_open() const noexcept { return state_ == WsState::Open; }

    /// Get negotiated subprotocol
    [[nodiscard]] std::string_view protocol() const noexcept { return selected_protocol_; }

    /// Get connection statistics
    [[nodiscard]] const WsConnectionStats& stats() const noexcept { return stats_; }

    /// Set event callbacks
    void set_callbacks(WsCallbacks callbacks) { callbacks_ = std::move(callbacks); }

    /// Get underlying TLS connection
    [[nodiscard]] TlsConnection& tls() noexcept { return tls_; }
    [[nodiscard]] const TlsConnection& tls() const noexcept { return tls_; }

private:
    // ========================================================================
    // Internal Frame Handling
    // ========================================================================

    /// Send a single frame (blocking)
    [[nodiscard]] Expected<void> send_frame(
        WsOpcode opcode,
        std::span<const std::byte> payload,
        bool fin = true
    ) {
        if (state_ != WsState::Open && state_ != WsState::Closing) {
            return unexpected(ErrorCode::InvalidState, "Connection not open");
        }

        SIGNET_TIMER_SCOPE(metrics::kWsMessageSend);

        auto mask = generate_masking_key();
        size_t frame_size = WsFrameBuilder::frame_size(payload.size(), true);

        // SECURITY (CRITICAL #2/#3): frame_size returns 0 on integer overflow.
        // Distinguish overflow from "small payload" by checking the input length:
        // a payload that big cannot possibly fit in any buffer — refuse to send.
        if (frame_size == 0 && payload.size() > 0) {
            return unexpected(ErrorCode::MessageTooLarge,
                "Frame size overflow — payload too large");
        }
        if (frame_size > config_.max_frame_size) {
            return unexpected(ErrorCode::MessageTooLarge,
                "Frame size exceeds max_frame_size");
        }

        // Ensure buffer is large enough
        if (send_buffer_.size() < frame_size) {
            send_buffer_.resize(frame_size);
        }

        // Build frame
        size_t built = frame_builder_.build_frame(
            send_buffer_, opcode, payload, true, mask, fin);
        if (built == 0) {
            return unexpected(ErrorCode::BufferTooSmall, "Send buffer too small");
        }

        // Send
        auto result = tls_.write({send_buffer_.data(), built});
        if (!result) {
            return unexpected(result.error());
        }

        ++stats_.frames_sent;
        stats_.bytes_sent += built;

        SIGNET_COUNTER_INC(metrics::kWsMessagesSent);
        return {};
    }

    /// Send a message (possibly fragmented)
    [[nodiscard]] Expected<void> send_message(
        WsOpcode opcode,
        std::span<const std::byte> data
    ) {
        if (data.size() > config_.max_message_size) {
            return unexpected(ErrorCode::MessageTooLarge, "Message exceeds max size");
        }

        // For now, send as single frame (fragmentation can be added later)
        auto result = send_frame(opcode, data, true);
        if (result) {
            ++stats_.messages_sent;
        }
        return result;
    }

    /// Read a single frame (blocking)
    using FrameData = std::pair<WsFrameHeader, std::vector<std::byte>>;

    [[nodiscard]] Expected<FrameData> read_frame() {
        SIGNET_TIMER_SCOPE(metrics::kWsMessageRecv);

        // First, use any pending data from handshake
        std::vector<std::byte> buffer;
        if (!pending_data_.empty()) {
            buffer = std::move(pending_data_);
            pending_data_.clear();
        }

        // Parse header
        while (true) {
            frame_parser_.reset();
            auto parse_result = frame_parser_.parse_header(buffer);

            if (parse_result == WsParseResult::Complete) {
                break;
            } else if (parse_result == WsParseResult::NeedMoreData) {
                // Read more data
                auto read_result = tls_.read(recv_buffer_);
                if (!read_result) {
                    return unexpected(read_result.error());
                }
                if (*read_result == 0) {
                    return unexpected(ErrorCode::ConnectionClosed, "Connection closed");
                }
                buffer.insert(buffer.end(), recv_buffer_.begin(),
                              recv_buffer_.begin() + *read_result);
            } else {
                // Parse error
                return unexpected(ErrorCode::WebSocketProtocolError,
                    std::string(parse_result_description(parse_result)));
            }
        }

        const auto& header = frame_parser_.header();

        // Read payload
        size_t payload_start = header.header_size;
        size_t total_needed = payload_start + header.payload_length;

        while (buffer.size() < total_needed) {
            auto read_result = tls_.read(recv_buffer_);
            if (!read_result) {
                return unexpected(read_result.error());
            }
            if (*read_result == 0) {
                return unexpected(ErrorCode::ConnectionClosed, "Connection closed");
            }
            buffer.insert(buffer.end(), recv_buffer_.begin(),
                          recv_buffer_.begin() + *read_result);
        }

        // Extract payload
        std::vector<std::byte> payload(
            buffer.begin() + payload_start,
            buffer.begin() + total_needed);

        // Unmask if needed (server->client should not be masked, but handle it)
        if (header.masked) {
            apply_mask_inplace(payload, header.masking_key);
        }

        // Store any remaining data
        if (buffer.size() > total_needed) {
            pending_data_.assign(
                buffer.begin() + total_needed,
                buffer.end());
        }

        ++stats_.frames_received;
        stats_.bytes_received += total_needed;

        SIGNET_COUNTER_INC(metrics::kWsMessagesRecv);
        return FrameData{header, std::move(payload)};
    }

    /// Handle control frame
    ///
    /// SECURITY (CRITICAL #9): User callbacks may re-enter this connection.
    /// We snapshot the callback into a local std::function and check `state_`
    /// after each invocation. If the user closed the connection from inside
    /// their callback, we abort processing this frame instead of sending the
    /// auto-pong on a closed/destroyed transport.
    [[nodiscard]] Expected<void> handle_control_frame(
        const WsFrameHeader& header,
        const std::vector<std::byte>& payload
    ) {
        switch (header.opcode) {
            case WsOpcode::Ping: {
                ++stats_.pings_received;
                if (callbacks_.on_ping) {
                    auto cb = callbacks_.on_ping;  // local copy — survives reentry
                    cb(payload);
                    if (state_ != WsState::Open && state_ != WsState::Closing) {
                        return {};  // user callback closed us
                    }
                }
                if (config_.auto_respond_ping) {
                    return send_pong(payload);
                }
                break;
            }

            case WsOpcode::Pong:
                ++stats_.pongs_received;
                if (callbacks_.on_pong) {
                    auto cb = callbacks_.on_pong;
                    cb(payload);
                }
                break;

            case WsOpcode::Close: {
                auto info = parse_close_payload(payload);
                if (state_ == WsState::Open) {
                    // Server initiated close
                    if (config_.auto_respond_close) {
                        // Send close response (best-effort)
                        auto close_payload = frame_builder_.build_close_payload(
                            info.code, info.reason);
                        (void)send_frame(WsOpcode::Close, close_payload, true);
                    }
                    state_ = WsState::Closed;
                    tls_.close_sync();
                } else if (state_ == WsState::Closing) {
                    // We initiated close, this is the response
                    state_ = WsState::Closed;
                    tls_.close_sync();
                }

                if (callbacks_.on_close) {
                    auto cb = callbacks_.on_close;
                    cb(info.code, info.reason);
                }
                break;
            }

            default:
                break;
        }

        return {};
    }

    /// Handle data frame (including fragmentation)
    ///
    /// SECURITY (HIGH #28): On any error path during fragment accumulation,
    /// fragment_buffer_ MUST be cleared — otherwise stale fragments leak into
    /// the next message and a malicious peer could splice payloads across
    /// frames. We use a small RAII guard so every error return clears state.
    [[nodiscard]] Expected<std::optional<WsMessage>> handle_data_frame(
        const WsFrameHeader& header,
        std::vector<std::byte> payload
    ) {
        struct FragmentGuard {
            std::vector<std::byte>& buf;
            bool committed = false;
            ~FragmentGuard() { if (!committed) buf.clear(); }
        };

        // Handle fragmentation
        if (!header.fin || header.opcode == WsOpcode::Continuation) {
            // Reject continuation without prior start
            if (header.opcode == WsOpcode::Continuation && fragment_buffer_.empty() &&
                fragment_opcode_ == WsOpcode::Continuation) {
                return unexpected(ErrorCode::WebSocketProtocolError,
                    "Continuation frame without prior fragment");
            }

            // Start of fragmented message
            if (header.opcode != WsOpcode::Continuation) {
                // Reject nested message starts
                if (!fragment_buffer_.empty()) {
                    fragment_buffer_.clear();
                    fragment_opcode_ = WsOpcode::Continuation;
                    return unexpected(ErrorCode::WebSocketProtocolError,
                        "New message started while previous fragment incomplete");
                }
                fragment_opcode_ = header.opcode;
                fragment_buffer_.clear();
            }

            FragmentGuard guard{fragment_buffer_};

            // Accumulate fragment
            fragment_buffer_.insert(fragment_buffer_.end(),
                payload.begin(), payload.end());

            // Check size limit
            if (fragment_buffer_.size() > config_.max_message_size) {
                return unexpected(ErrorCode::MessageTooLarge,
                    "Fragmented message exceeds max size");
            }

            // Not final fragment
            if (!header.fin) {
                // Continue reading
                while (true) {
                    auto frame_result = read_frame();
                    if (!frame_result) {
                        return unexpected(frame_result.error());
                    }

                    auto& [next_header, next_payload] = *frame_result;

                    // Control frames can be interleaved
                    if (is_control_frame(next_header.opcode)) {
                        auto control_result = handle_control_frame(
                            next_header, next_payload);
                        if (!control_result) {
                            return unexpected(control_result.error());
                        }
                        continue;
                    }

                    // Must be continuation
                    if (next_header.opcode != WsOpcode::Continuation) {
                        return unexpected(ErrorCode::WebSocketProtocolError,
                            "Expected continuation frame");
                    }

                    fragment_buffer_.insert(fragment_buffer_.end(),
                        next_payload.begin(), next_payload.end());

                    if (fragment_buffer_.size() > config_.max_message_size) {
                        return unexpected(ErrorCode::MessageTooLarge,
                            "Fragmented message exceeds max size");
                    }

                    if (next_header.fin) {
                        break;
                    }
                }
            }

            // Final fragment received — commit transfer (guard won't clear)
            payload = std::move(fragment_buffer_);
            fragment_buffer_.clear();
            fragment_opcode_ = WsOpcode::Continuation;
            guard.committed = true;
        }

        // Determine message type
        WsOpcode effective_opcode = (header.opcode == WsOpcode::Continuation)
            ? fragment_opcode_
            : header.opcode;

        // Validate UTF-8 for text messages
        if (config_.validate_utf8 && effective_opcode == WsOpcode::Text) {
            if (!validate_utf8(payload)) {
                return unexpected(ErrorCode::WebSocketProtocolError,
                    "Invalid UTF-8 in text message");
            }
        }

        WsMessage message{
            opcode_to_message_type(effective_opcode),
            std::move(payload)
        };

        ++stats_.messages_received;

        if (callbacks_.on_message) {
            callbacks_.on_message(message);
        }

        return message;
    }

    /// Validate UTF-8 encoding
    [[nodiscard]] static bool validate_utf8(std::span<const std::byte> data) noexcept {
        SIGNET_TIMER_SCOPE(metrics::kWsUtf8Validate);

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
        const uint8_t* end = ptr + data.size();

        while (ptr < end) {
            uint8_t b = *ptr;

            if (b <= 0x7F) {
                // ASCII
                ++ptr;
            } else if ((b & 0xE0) == 0xC0) {
                // 2-byte sequence
                if (ptr + 2 > end) return false;
                if ((ptr[1] & 0xC0) != 0x80) return false;
                // Overlong check
                if (b < 0xC2) return false;
                ptr += 2;
            } else if ((b & 0xF0) == 0xE0) {
                // 3-byte sequence
                if (ptr + 3 > end) return false;
                if ((ptr[1] & 0xC0) != 0x80) return false;
                if ((ptr[2] & 0xC0) != 0x80) return false;
                // Overlong and surrogate check
                uint32_t cp = ((b & 0x0F) << 12) |
                              ((ptr[1] & 0x3F) << 6) |
                              (ptr[2] & 0x3F);
                if (cp < 0x800) return false;  // Overlong
                if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // Surrogate
                ptr += 3;
            } else if ((b & 0xF8) == 0xF0) {
                // 4-byte sequence
                if (ptr + 4 > end) return false;
                if ((ptr[1] & 0xC0) != 0x80) return false;
                if ((ptr[2] & 0xC0) != 0x80) return false;
                if ((ptr[3] & 0xC0) != 0x80) return false;
                // Range check
                uint32_t cp = ((b & 0x07) << 18) |
                              ((ptr[1] & 0x3F) << 12) |
                              ((ptr[2] & 0x3F) << 6) |
                              (ptr[3] & 0x3F);
                if (cp < 0x10000 || cp > 0x10FFFF) return false;
                ptr += 4;
            } else {
                // Invalid lead byte
                return false;
            }
        }

        return true;
    }

    // ========================================================================
    // Members
    // ========================================================================

    TlsConnection tls_;
    WsConfig config_;
    WsState state_ = WsState::Connecting;
    WsCallbacks callbacks_;
    WsConnectionStats stats_;

    // Handshake
    WsHandshake handshake_;
    std::string selected_protocol_;

    // Frame processing
    WsFrameParser frame_parser_;
    WsFrameBuilder frame_builder_;
    std::vector<std::byte> recv_buffer_;
    std::vector<std::byte> send_buffer_;
    std::vector<std::byte> pending_data_;

    // Fragmentation
    WsOpcode fragment_opcode_ = WsOpcode::Continuation;
    std::vector<std::byte> fragment_buffer_;
};

// ============================================================================
// Factory Functions
// ============================================================================

/// Create WebSocket connection to URL (blocking)
/// @param url WebSocket URL (ws:// or wss://)
/// @param tls_ctx TLS context for wss:// connections
/// @param config WebSocket configuration
/// @return Connected WebSocket or error
[[nodiscard]] inline Expected<WsConnection> connect_websocket(
    std::string_view url,
    TlsContext& tls_ctx,
    WsConfig config = {}
) {
    // Parse URL
    auto parsed = ParsedUrl::parse(url);
    if (!parsed) {
        return unexpected(parsed.error());
    }

    // Must be WebSocket URL
    if (parsed->scheme != "ws" && parsed->scheme != "wss") {
        return unexpected(ErrorCode::InvalidArgument,
            "URL must use ws:// or wss:// scheme");
    }

    // Set default port
    uint16_t port = parsed->port;
    if (port == 0) {
        port = parsed->is_secure ? 443 : 80;
    }

    // Resolve hostname
    Resolver resolver;
    auto endpoint = resolver.resolve_one(parsed->host, port);
    if (!endpoint) {
        return unexpected(endpoint.error());
    }

    // Create TLS connection
    auto tls_conn = create_tls_client(*endpoint, tls_ctx, parsed->host);
    if (!tls_conn) {
        return unexpected(tls_conn.error());
    }

    // Configure handshake
    config.handshake.host = parsed->host;
    config.handshake.path = parsed->path.empty() ? "/" : parsed->path;
    config.handshake.port = port;

    // Create WebSocket connection
    WsConnection ws(std::move(*tls_conn), std::move(config));

    // Perform handshake
    auto handshake_result = ws.handshake_sync();
    if (!handshake_result) {
        return unexpected(handshake_result.error());
    }

    return ws;
}

}  // namespace signet
