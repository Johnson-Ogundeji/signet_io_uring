// Signet WebSocket Client
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0
//
// High-level WebSocket client with automatic reconnection,
// extension support, and event-driven callbacks.

#ifndef SIGNET_WS_CLIENT_HPP
#define SIGNET_WS_CLIENT_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "signet/core/types.hpp"
#include "signet/core/error.hpp"
#include "signet/core/clock.hpp"
#include "signet/tls/tls_context.hpp"
#include "signet/ws/ws_types.hpp"
#include "signet/ws/ws_frame.hpp"
#include "signet/ws/ws_handshake.hpp"
#include "signet/ws/ws_connection.hpp"
#include "signet/ws/ws_validator.hpp"
#include "signet/ws/ws_extension.hpp"
#include "signet/ws/ws_deflate.hpp"

namespace signet {

// ═══════════════════════════════════════════════════════════════════════════
// Client Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// WebSocket client configuration
struct WsClientConfig {
    /// Connection timeout (default: 10s)
    std::chrono::milliseconds connect_timeout{10000};

    /// Handshake timeout (default: 5s)
    std::chrono::milliseconds handshake_timeout{5000};

    /// Ping interval (0 = disabled, default: 30s)
    std::chrono::milliseconds ping_interval{30000};

    /// Pong timeout (default: 10s)
    std::chrono::milliseconds pong_timeout{10000};

    /// Maximum message size (default: 16MB)
    size_t max_message_size{16 * 1024 * 1024};

    /// Maximum frame size (default: 1MB)
    size_t max_frame_size{1024 * 1024};

    /// Receive buffer size (default: 64KB)
    size_t recv_buffer_size{64 * 1024};

    /// Send buffer size (default: 64KB)
    size_t send_buffer_size{64 * 1024};

    /// Auto-reconnect on disconnect (default: true)
    bool auto_reconnect{true};

    /// Reconnect delay base (exponential backoff, default: 1s)
    std::chrono::milliseconds reconnect_delay_base{1000};

    /// Maximum reconnect delay (default: 30s)
    std::chrono::milliseconds reconnect_delay_max{30000};

    /// Maximum reconnect attempts (0 = unlimited, default: unlimited)
    uint32_t max_reconnect_attempts{0};

    /// Enable permessage-deflate compression (default: true)
    bool enable_compression{true};

    /// Enable TLS certificate verification (default: true)
    bool verify_certificates{true};

    /// Custom HTTP headers for handshake
    std::vector<std::pair<std::string, std::string>> extra_headers;

    /// WebSocket subprotocols to offer
    std::vector<std::string> subprotocols;

    /// Factory for HFT-optimized config
    [[nodiscard]] static WsClientConfig hft() noexcept {
        WsClientConfig config;
        config.connect_timeout = std::chrono::milliseconds{5000};
        config.handshake_timeout = std::chrono::milliseconds{2000};
        config.ping_interval = std::chrono::milliseconds{15000};
        config.pong_timeout = std::chrono::milliseconds{5000};
        config.recv_buffer_size = 128 * 1024;
        config.send_buffer_size = 64 * 1024;
        config.auto_reconnect = true;
        config.reconnect_delay_base = std::chrono::milliseconds{100};
        config.reconnect_delay_max = std::chrono::milliseconds{5000};
        return config;
    }

    /// Factory for bandwidth-optimized config
    [[nodiscard]] static WsClientConfig bandwidth_optimized() noexcept {
        WsClientConfig config;
        config.enable_compression = true;
        config.recv_buffer_size = 32 * 1024;
        config.send_buffer_size = 32 * 1024;
        return config;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Client State
// ═══════════════════════════════════════════════════════════════════════════

/// WebSocket client state
enum class WsClientState : uint8_t {
    Disconnected,     ///< Not connected
    Connecting,       ///< TCP/TLS connection in progress
    Handshaking,      ///< WebSocket handshake in progress
    Connected,        ///< Connected and ready
    Closing,          ///< Close handshake in progress
    Reconnecting,     ///< Waiting to reconnect
    Failed            ///< Connection failed permanently
};

[[nodiscard]] inline std::string_view ws_client_state_to_string(WsClientState state) noexcept {
    switch (state) {
        case WsClientState::Disconnected: return "Disconnected";
        case WsClientState::Connecting: return "Connecting";
        case WsClientState::Handshaking: return "Handshaking";
        case WsClientState::Connected: return "Connected";
        case WsClientState::Closing: return "Closing";
        case WsClientState::Reconnecting: return "Reconnecting";
        case WsClientState::Failed: return "Failed";
    }
    return "Unknown";
}

// ═══════════════════════════════════════════════════════════════════════════
// Client Events
// ═══════════════════════════════════════════════════════════════════════════

/// Received message
struct WsClientMessage {
    WsMessageType type;           ///< Text or binary
    std::vector<std::byte> data;  ///< Message payload

    /// Get message as text (for text messages)
    [[nodiscard]] std::string_view as_text() const noexcept {
        return {reinterpret_cast<const char*>(data.data()), data.size()};
    }

    /// Get message as binary span
    [[nodiscard]] std::span<const std::byte> as_binary() const noexcept {
        return data;
    }
};

/// Client statistics
struct WsClientStats {
    uint64_t messages_sent{0};
    uint64_t messages_received{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    uint64_t frames_sent{0};
    uint64_t frames_received{0};
    uint64_t pings_sent{0};
    uint64_t pongs_received{0};
    uint64_t reconnect_count{0};
    uint64_t connect_time_ns{0};      ///< Last connection time
    uint64_t handshake_time_ns{0};    ///< Last handshake time
    uint64_t total_connected_ns{0};   ///< Total time connected
};

// ═══════════════════════════════════════════════════════════════════════════
// Client Callbacks
// ═══════════════════════════════════════════════════════════════════════════

/// Callback types
using OnConnectCallback = std::function<void()>;
using OnDisconnectCallback = std::function<void(CloseCode, std::string_view)>;
using OnMessageCallback = std::function<void(const WsClientMessage&)>;
using OnErrorCallback = std::function<void(const Error&)>;
using OnPingCallback = std::function<void(std::span<const std::byte>)>;
using OnPongCallback = std::function<void(std::span<const std::byte>)>;
using OnStateChangeCallback = std::function<void(WsClientState, WsClientState)>;

/// Client callbacks container
struct WsClientCallbacks {
    OnConnectCallback on_connect;
    OnDisconnectCallback on_disconnect;
    OnMessageCallback on_message;
    OnErrorCallback on_error;
    OnPingCallback on_ping;
    OnPongCallback on_pong;
    OnStateChangeCallback on_state_change;
};

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Client
// ═══════════════════════════════════════════════════════════════════════════

/// High-performance WebSocket client
///
/// This client wraps the lower-level WsConnection class with:
/// - Automatic TLS context management
/// - Event-driven callback interface
/// - Automatic reconnection with exponential backoff
/// - Extension chain support (permessage-deflate)
/// - Thread-safe statistics
///
/// @code
/// WsClient client;
/// client.on_message([](const WsClientMessage& msg) {
///     std::cout << msg.as_text() << "\n";
/// });
/// auto result = client.connect("wss://stream.binance.com:9443/ws/btcusdt@trade");
/// if (result) {
///     client.run();
/// }
/// @endcode
class WsClient {
public:
    /// Create client with default configuration
    WsClient() : WsClient(WsClientConfig{}) {}

    /// Create client with custom configuration
    explicit WsClient(WsClientConfig config)
        : config_(std::move(config))
        , state_(WsClientState::Disconnected) {

        // Set up extension chain
        if (config_.enable_compression) {
            extensions_.add(make_deflate_extension_hft());
        }
    }

    ~WsClient() {
        disconnect();
    }

    // Non-copyable
    WsClient(const WsClient&) = delete;
    WsClient& operator=(const WsClient&) = delete;

    // Movable
    WsClient(WsClient&&) = default;
    WsClient& operator=(WsClient&&) = default;

    // ─────────────────────────────────────────────────────────────────────────
    // Configuration
    // ─────────────────────────────────────────────────────────────────────────

    /// Get current configuration
    [[nodiscard]] const WsClientConfig& config() const noexcept {
        return config_;
    }

    /// Set configuration (only valid when disconnected)
    void set_config(WsClientConfig config) {
        if (state_ != WsClientState::Disconnected) {
            return;
        }
        config_ = std::move(config);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Callbacks
    // ─────────────────────────────────────────────────────────────────────────

    /// Set callback for successful connection
    void on_connect(OnConnectCallback cb) {
        callbacks_.on_connect = std::move(cb);
    }

    /// Set callback for disconnection
    void on_disconnect(OnDisconnectCallback cb) {
        callbacks_.on_disconnect = std::move(cb);
    }

    /// Set callback for received messages
    void on_message(OnMessageCallback cb) {
        callbacks_.on_message = std::move(cb);
    }

    /// Set callback for errors
    void on_error(OnErrorCallback cb) {
        callbacks_.on_error = std::move(cb);
    }

    /// Set callback for ping frames
    void on_ping(OnPingCallback cb) {
        callbacks_.on_ping = std::move(cb);
    }

    /// Set callback for pong frames
    void on_pong(OnPongCallback cb) {
        callbacks_.on_pong = std::move(cb);
    }

    /// Set callback for state changes
    void on_state_change(OnStateChangeCallback cb) {
        callbacks_.on_state_change = std::move(cb);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Connection
    // ─────────────────────────────────────────────────────────────────────────

    /// Connect to WebSocket server
    /// @param url WebSocket URL (ws:// or wss://)
    /// @return Success or error
    [[nodiscard]] tl::expected<void, Error> connect(std::string_view url) {
        // Validate URL scheme first
        bool use_tls = url.starts_with("wss://");
        bool use_ws = url.starts_with("ws://");
        if (!use_tls && !use_ws) {
            return tl::unexpected(Error{ErrorCode::InvalidUrl, "URL must use ws:// or wss:// scheme"});
        }

        // Validate that host exists (not ws:///path)
        auto host_start = use_tls ? std::string_view(url).substr(6) : std::string_view(url).substr(5);
        if (host_start.empty() || host_start.starts_with('/')) {
            return tl::unexpected(Error{ErrorCode::InvalidUrl, "URL must contain a host"});
        }

        set_state(WsClientState::Connecting);
        auto connect_start = Clock::now();

        // Create TLS context if needed
        if (use_tls && !tls_context_) {
            TlsContextConfig tls_config;
            tls_config.verify_mode = config_.verify_certificates
                ? TlsVerifyMode::Peer : TlsVerifyMode::None;
            auto ctx = TlsContext::create_client(tls_config);
            if (!ctx) {
                set_state(WsClientState::Disconnected);
                return tl::unexpected(ctx.error());
            }
            tls_context_ = std::move(*ctx);
        }

        // Build WsConfig from WsClientConfig
        WsConfig ws_config;
        ws_config.max_message_size = config_.max_message_size;
        ws_config.max_frame_size = config_.max_frame_size;
        ws_config.receive_buffer_size = config_.recv_buffer_size;
        ws_config.send_buffer_size = config_.send_buffer_size;
        ws_config.connect_timeout_ms = static_cast<uint32_t>(config_.connect_timeout.count());
        ws_config.handshake_timeout_ms = static_cast<uint32_t>(config_.handshake_timeout.count());
        ws_config.allow_rsv_bits = config_.enable_compression;

        // Add extra headers
        for (const auto& [name, value] : config_.extra_headers) {
            ws_config.handshake.extra_headers[name] = value;
        }

        // Add subprotocols
        ws_config.handshake.subprotocols = config_.subprotocols;

        // Add extensions if compression enabled
        if (config_.enable_compression) {
            ws_config.handshake.extensions.push_back("permessage-deflate");
        }

        set_state(WsClientState::Handshaking);

        // Connect using the factory function
        auto conn_result = connect_websocket(url, *tls_context_, ws_config);
        if (!conn_result) {
            set_state(WsClientState::Disconnected);
            if (callbacks_.on_error) {
                callbacks_.on_error(conn_result.error());
            }
            return tl::unexpected(conn_result.error());
        }

        // Store the connection
        connection_ = std::make_unique<WsConnection>(std::move(*conn_result));
        url_ = std::string(url);

        // Update stats
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.connect_time_ns = Clock::now() - connect_start;
        }

        // Wire up callbacks
        setup_callbacks();

        set_state(WsClientState::Connected);
        connected_at_ = Clock::now();
        reconnect_attempts_ = 0;

        if (callbacks_.on_connect) {
            callbacks_.on_connect();
        }

        return {};
    }

    /// Disconnect gracefully
    void disconnect(CloseCode code = CloseCode::Normal,
                   std::string_view reason = "") {
        if (connection_ && (state_ == WsClientState::Connected ||
                           state_ == WsClientState::Closing)) {
            set_state(WsClientState::Closing);
            (void)connection_->close_sync(code, reason);
        }
        cleanup();
        set_state(WsClientState::Disconnected);
    }

    /// Check if connected
    [[nodiscard]] bool is_connected() const noexcept {
        return state_ == WsClientState::Connected;
    }

    /// Get current state
    [[nodiscard]] WsClientState state() const noexcept {
        return state_;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sending
    // ─────────────────────────────────────────────────────────────────────────

    /// Send text message
    [[nodiscard]] tl::expected<void, Error> send(std::string_view text) {
        if (state_ != WsClientState::Connected || !connection_) {
            return tl::unexpected(Error{
                ErrorCode::ConnectionClosed,
                "Not connected"
            });
        }

        auto result = connection_->send_text(text);
        if (result) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_sent++;
            stats_.bytes_sent += text.size();
        }
        return result;
    }

    /// Send binary message
    [[nodiscard]] tl::expected<void, Error> send(std::span<const std::byte> data) {
        if (state_ != WsClientState::Connected || !connection_) {
            return tl::unexpected(Error{
                ErrorCode::ConnectionClosed,
                "Not connected"
            });
        }

        auto result = connection_->send_binary(data);
        if (result) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_sent++;
            stats_.bytes_sent += data.size();
        }
        return result;
    }

    /// Send ping
    [[nodiscard]] tl::expected<void, Error> ping(std::span<const std::byte> payload = {}) {
        if (state_ != WsClientState::Connected || !connection_) {
            return tl::unexpected(Error{
                ErrorCode::ConnectionClosed,
                "Not connected"
            });
        }

        auto result = connection_->send_ping(payload);
        if (result) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.pings_sent++;
        }
        return result;
    }

    /// Send pong
    [[nodiscard]] tl::expected<void, Error> pong(std::span<const std::byte> payload = {}) {
        if (state_ != WsClientState::Connected || !connection_) {
            return tl::unexpected(Error{
                ErrorCode::ConnectionClosed,
                "Not connected"
            });
        }

        return connection_->send_pong(payload);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event Loop
    // ─────────────────────────────────────────────────────────────────────────

    /// Run event loop (blocking)
    void run() {
        while (state_ != WsClientState::Disconnected &&
               state_ != WsClientState::Failed) {
            (void)poll_once();
        }
    }

    /// Run event loop with timeout
    [[nodiscard]] size_t run_for(std::chrono::milliseconds timeout) {
        auto start = Clock::now();
        size_t events = 0;

        while (state_ != WsClientState::Disconnected &&
               state_ != WsClientState::Failed) {
            auto elapsed = std::chrono::nanoseconds(Clock::now() - start);
            if (elapsed >= timeout) {
                break;
            }

            if (poll_once()) {
                events++;
            }
        }

        return events;
    }

    /// Poll for single event (non-blocking)
    [[nodiscard]] bool poll_once() {
        if (state_ == WsClientState::Connected && connection_) {
            // Receive next message
            auto msg_result = connection_->read_message();
            if (msg_result) {
                auto& msg_opt = *msg_result;
                if (msg_opt) {
                    process_message(*msg_opt);
                    return true;
                }
                // Empty optional means close received
                handle_disconnect(CloseCode::Normal, "Server closed connection");
                return true;
            } else if (msg_result.error().code() == ErrorCode::ConnectionClosed) {
                handle_disconnect(CloseCode::Abnormal, "Connection lost");
            }
        } else if (state_ == WsClientState::Reconnecting) {
            return process_reconnect();
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Statistics
    // ─────────────────────────────────────────────────────────────────────────

    /// Get client statistics
    [[nodiscard]] WsClientStats stats() const noexcept {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return stats_;
    }

    /// Reset statistics
    void reset_stats() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = {};
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Extensions
    // ─────────────────────────────────────────────────────────────────────────

    /// Get extension chain
    [[nodiscard]] ExtensionChain& extensions() noexcept {
        return extensions_;
    }

    /// Get negotiated subprotocol (after connection)
    [[nodiscard]] std::string_view subprotocol() const noexcept {
        return subprotocol_;
    }

private:
    void set_state(WsClientState new_state) {
        auto old_state = state_.exchange(new_state);
        if (old_state != new_state && callbacks_.on_state_change) {
            callbacks_.on_state_change(old_state, new_state);
        }
    }

    void setup_callbacks() {
        if (!connection_) return;

        // Wire our callbacks to the underlying connection
        WsCallbacks ws_callbacks;

        ws_callbacks.on_message = [this](WsMessage msg) {
            process_message(msg);
        };

        ws_callbacks.on_close = [this](WsCloseCode code, std::string_view reason) {
            handle_disconnect(static_cast<CloseCode>(code), reason);
        };

        ws_callbacks.on_error = [this](const Error& err) {
            if (callbacks_.on_error) {
                callbacks_.on_error(err);
            }
        };

        ws_callbacks.on_ping = [this](std::span<const std::byte> payload) {
            if (callbacks_.on_ping) {
                callbacks_.on_ping(payload);
            }
        };

        ws_callbacks.on_pong = [this](std::span<const std::byte> payload) {
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.pongs_received++;
            }
            if (callbacks_.on_pong) {
                callbacks_.on_pong(payload);
            }
        };

        connection_->set_callbacks(std::move(ws_callbacks));
    }

    void process_message(const WsMessage& msg) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.messages_received++;
            stats_.bytes_received += msg.data.size();
        }

        if (callbacks_.on_message) {
            WsClientMessage client_msg;
            client_msg.type = msg.type;
            client_msg.data = msg.data;
            callbacks_.on_message(client_msg);
        }
    }

    void handle_disconnect(CloseCode code, std::string_view reason) {
        cleanup();

        if (callbacks_.on_disconnect) {
            callbacks_.on_disconnect(code, reason);
        }

        if (config_.auto_reconnect && state_ != WsClientState::Failed) {
            schedule_reconnect();
        } else {
            set_state(WsClientState::Disconnected);
        }
    }

    void schedule_reconnect() {
        set_state(WsClientState::Reconnecting);

        // Exponential backoff
        auto delay = config_.reconnect_delay_base *
            (1 << std::min(reconnect_attempts_, uint32_t{10}));
        if (delay > config_.reconnect_delay_max) {
            delay = config_.reconnect_delay_max;
        }

        reconnect_at_ = Clock::now() +
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(delay).count());

        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.reconnect_count++;
    }

    [[nodiscard]] bool process_reconnect() {
        auto now = Clock::now();
        if (now >= reconnect_at_) {
            reconnect_attempts_++;

            if (config_.max_reconnect_attempts > 0 &&
                reconnect_attempts_ > config_.max_reconnect_attempts) {
                set_state(WsClientState::Failed);

                if (callbacks_.on_error) {
                    callbacks_.on_error(Error{
                        ErrorCode::ConnectionFailed,
                        "Max reconnect attempts exceeded"
                    });
                }
                return true;
            }

            auto result = connect(url_);
            if (!result) {
                // Schedule another reconnect
                schedule_reconnect();
            }
            return true;
        }
        return false;
    }

    void cleanup() {
        connection_.reset();
        // Keep tls_context_ for reconnection
    }

    WsClientConfig config_;
    WsClientCallbacks callbacks_;
    std::atomic<WsClientState> state_;

    // Connection
    std::string url_;
    std::optional<TlsContext> tls_context_;
    std::unique_ptr<WsConnection> connection_;
    std::string subprotocol_;

    // Extensions
    ExtensionChain extensions_;

    // Reconnection
    uint64_t connected_at_{0};
    uint64_t reconnect_at_{0};
    uint32_t reconnect_attempts_{0};

    // Statistics
    mutable std::mutex stats_mutex_;
    WsClientStats stats_;
};

// ═══════════════════════════════════════════════════════════════════════════
// Factory Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Create WebSocket client with default config
[[nodiscard]] inline std::unique_ptr<WsClient> make_ws_client() {
    return std::make_unique<WsClient>();
}

/// Create WebSocket client with HFT config
[[nodiscard]] inline std::unique_ptr<WsClient> make_ws_client_hft() {
    return std::make_unique<WsClient>(WsClientConfig::hft());
}

/// Create WebSocket client with custom config
[[nodiscard]] inline std::unique_ptr<WsClient>
make_ws_client(WsClientConfig config) {
    return std::make_unique<WsClient>(std::move(config));
}

}  // namespace signet

#endif  // SIGNET_WS_CLIENT_HPP
