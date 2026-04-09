// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/buffer_pool.hpp"
#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/ring.hpp"
#include "signet/net/address.hpp"
#include "signet/net/resolver.hpp"
#include "signet/net/socket.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

namespace signet {

/// Connection state
enum class ConnectionState : uint8_t {
    Disconnected,
    Resolving,
    Connecting,
    Connected,
    Closing,
    Closed,
    Error
};

[[nodiscard]] inline constexpr const char* to_string(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::Disconnected: return "Disconnected";
        case ConnectionState::Resolving: return "Resolving";
        case ConnectionState::Connecting: return "Connecting";
        case ConnectionState::Connected: return "Connected";
        case ConnectionState::Closing: return "Closing";
        case ConnectionState::Closed: return "Closed";
        case ConnectionState::Error: return "Error";
    }
    return "Unknown";
}

/// Metric names for connection operations
namespace metrics {
    constexpr const char* kConnectionEstablish = "connection.establish";
    constexpr const char* kConnectionClose = "connection.close";
    constexpr const char* kConnectionErrors = "connection.errors";
    constexpr const char* kActiveConnections = "connection.active";
}  // namespace metrics

/// Connection event callbacks
struct ConnectionCallbacks {
    std::function<void()> on_connect;
    std::function<void(std::span<const std::byte>)> on_data;
    std::function<void(const Error&)> on_error;
    std::function<void()> on_close;
};

/// Connection statistics
struct ConnectionStats {
    std::chrono::steady_clock::time_point connect_time;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    uint64_t reconnect_count = 0;
};

/// Operation types for io_uring completion handling
enum class OpType : uint8_t {
    None,
    Connect,
    Recv,
    Send,
    Close,
    Timeout
};

/// User data structure for io_uring completions
struct CompletionData {
    OpType type = OpType::None;
    void* connection = nullptr;
    size_t buffer_index = 0;

    static CompletionData* create(OpType type, void* conn, size_t buf_idx = 0) {
        auto* data = new CompletionData;
        data->type = type;
        data->connection = conn;
        data->buffer_index = buf_idx;
        return data;
    }
};

/// TCP connection manager with io_uring support
class Connection {
public:
    /// Create connection with shared resources
    Connection(Ring& ring, BufferPool& buffer_pool)
        : ring_(ring)
        , buffer_pool_(buffer_pool)
    {}

    ~Connection() {
        close_sync();
    }

    // Non-copyable
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // Movable (with care due to callbacks)
    Connection(Connection&&) = default;
    Connection& operator=(Connection&&) = default;

    /// Set event callbacks
    void set_callbacks(ConnectionCallbacks callbacks) {
        callbacks_ = std::move(callbacks);
    }

    /// Get current state
    [[nodiscard]] ConnectionState state() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

    /// Check if connected
    [[nodiscard]] bool is_connected() const noexcept {
        return state() == ConnectionState::Connected;
    }

    /// Get connection statistics
    [[nodiscard]] const ConnectionStats& stats() const noexcept {
        return stats_;
    }

    /// Connect to endpoint
    [[nodiscard]] Expected<void> connect(const Endpoint& endpoint) {
        SIGNET_TIMER_SCOPE(metrics::kConnectionEstablish);

        if (state() != ConnectionState::Disconnected) {
            return unexpected(ErrorCode::InvalidState, "Already connected or connecting");
        }

        remote_endpoint_ = endpoint;

        // Create socket
        auto sock = Socket::create(endpoint.family());
        if (!sock) {
            set_state(ConnectionState::Error);
            return unexpected(sock.error());
        }

        // Apply options
        SocketOptions opts;
        opts.tcp_nodelay = true;
        opts.tcp_quickack = true;
        opts.non_blocking = true;

        auto opt_result = sock->apply_options(opts);
        if (!opt_result) {
            set_state(ConnectionState::Error);
            return unexpected(opt_result.error());
        }

        socket_ = std::move(*sock);
        set_state(ConnectionState::Connecting);

        // Queue async connect
        auto* data = CompletionData::create(OpType::Connect, this);
        auto result = socket_.connect_async(ring_, endpoint, data);
        if (!result) {
            delete data;
            set_state(ConnectionState::Error);
            return unexpected(result.error());
        }

        return {};
    }

    /// Connect by hostname and port (with DNS resolution)
    [[nodiscard]] Expected<void> connect(std::string_view hostname, uint16_t port) {
        set_state(ConnectionState::Resolving);

        Resolver resolver;
        auto result = resolver.resolve_one(hostname, port);
        if (!result) {
            set_state(ConnectionState::Error);
            return unexpected(result.error());
        }

        hostname_ = std::string{hostname};
        return connect(*result);
    }

    /// Connect by URL
    [[nodiscard]] Expected<void> connect(std::string_view url) {
        auto parsed = ParsedUrl::parse(url);
        if (!parsed) {
            return unexpected(parsed.error());
        }

        is_secure_ = parsed->is_secure;
        return connect(parsed->host, parsed->port);
    }

    /// Handle connection established
    void on_connect_complete(int result) {
        if (result < 0) {
            auto err = Error{ErrorCode::ConnectionFailed, -result};
            set_state(ConnectionState::Error);
            SIGNET_COUNTER_INC(metrics::kConnectionErrors);
            if (callbacks_.on_error) {
                callbacks_.on_error(err);
            }
            return;
        }

        set_state(ConnectionState::Connected);
        stats_.connect_time = std::chrono::steady_clock::now();
        SIGNET_GAUGE_INC(metrics::kActiveConnections);

        // Start receiving data
        start_recv();

        if (callbacks_.on_connect) {
            callbacks_.on_connect();
        }
    }

    /// Send data asynchronously
    [[nodiscard]] Expected<void> send(std::span<const std::byte> data) {
        if (!is_connected()) {
            return unexpected(ErrorCode::InvalidState, "Not connected");
        }

        // Acquire buffer and copy data
        auto buffer = buffer_pool_.acquire();
        if (!buffer.valid()) {
            return unexpected(ErrorCode::OutOfMemory, "No buffers available");
        }

        size_t copied = buffer.append(data);
        if (copied < data.size()) {
            // Data too large for single buffer - need fragmentation
            // For now, just send what fits
        }

        auto* comp_data = CompletionData::create(OpType::Send, this, buffer.index());

        // Transfer buffer ownership to pending sends
        size_t buf_idx = buffer.index();
        pending_sends_[buf_idx] = std::move(buffer);

        auto result = socket_.send_async(ring_, pending_sends_[buf_idx].span(), comp_data);
        if (!result) {
            pending_sends_.erase(buf_idx);
            delete comp_data;
            return unexpected(result.error());
        }

        return {};
    }

    /// Send string data
    [[nodiscard]] Expected<void> send(std::string_view data) {
        return send(std::as_bytes(std::span{data.data(), data.size()}));
    }

    /// Handle send completion
    void on_send_complete(int result, size_t buffer_index) {
        // Release the send buffer
        pending_sends_.erase(buffer_index);

        if (result < 0) {
            auto err = Error{ErrorCode::WriteFailed, -result};
            SIGNET_COUNTER_INC(metrics::kConnectionErrors);
            if (callbacks_.on_error) {
                callbacks_.on_error(err);
            }
            return;
        }

        stats_.bytes_sent += static_cast<uint64_t>(result);
        ++stats_.messages_sent;
        SIGNET_COUNTER_ADD(metrics::kBytesWritten, result);
    }

    /// Handle recv completion
    void on_recv_complete(int result) {
        if (result <= 0) {
            if (result == 0) {
                // Connection closed by peer
                close_internal();
                return;
            }

            // Error
            auto err = Error{ErrorCode::ReadFailed, -result};
            SIGNET_COUNTER_INC(metrics::kConnectionErrors);
            if (callbacks_.on_error) {
                callbacks_.on_error(err);
            }
            return;
        }

        stats_.bytes_received += static_cast<uint64_t>(result);
        ++stats_.messages_received;
        SIGNET_COUNTER_ADD(metrics::kBytesRead, result);

        // Deliver data to callback
        if (callbacks_.on_data && recv_buffer_.valid()) {
            recv_buffer_.set_size(static_cast<size_t>(result));
            callbacks_.on_data(recv_buffer_.span());
        }

        // Continue receiving if still connected
        if (is_connected()) {
            start_recv();
        }
    }

    /// Close connection asynchronously
    [[nodiscard]] Expected<void> close() {
        SIGNET_TIMER_SCOPE(metrics::kConnectionClose);

        if (state() == ConnectionState::Disconnected ||
            state() == ConnectionState::Closed) {
            return {};
        }

        set_state(ConnectionState::Closing);

        auto* data = CompletionData::create(OpType::Close, this);
        auto result = socket_.close_async(ring_, data);
        if (!result) {
            delete data;
            // Force sync close
            close_sync();
        }

        return {};
    }

    /// Handle close completion
    void on_close_complete(int /*result*/) {
        close_internal();
    }

    /// Close synchronously
    void close_sync() {
        if (state() != ConnectionState::Disconnected &&
            state() != ConnectionState::Closed) {
            socket_.close_sync();
            close_internal();
        }
    }

    /// Get remote endpoint
    [[nodiscard]] const Endpoint& remote_endpoint() const noexcept {
        return remote_endpoint_;
    }

    /// Get hostname (if connected by hostname)
    [[nodiscard]] const std::string& hostname() const noexcept {
        return hostname_;
    }

    /// Check if connection uses TLS
    [[nodiscard]] bool is_secure() const noexcept {
        return is_secure_;
    }

    /// Get underlying socket (for TLS setup, etc.)
    [[nodiscard]] Socket& socket() noexcept { return socket_; }
    [[nodiscard]] const Socket& socket() const noexcept { return socket_; }

    /// Process a completion event
    static void process_completion(CompletionData* data, int result) {
        if (!data || !data->connection) return;

        auto* conn = static_cast<Connection*>(data->connection);

        switch (data->type) {
            case OpType::Connect:
                conn->on_connect_complete(result);
                break;
            case OpType::Send:
                conn->on_send_complete(result, data->buffer_index);
                break;
            case OpType::Recv:
                conn->on_recv_complete(result);
                break;
            case OpType::Close:
                conn->on_close_complete(result);
                break;
            default:
                break;
        }

        delete data;
    }

private:
    void set_state(ConnectionState state) {
        state_.store(state, std::memory_order_release);
    }

    void start_recv() {
        // Acquire buffer for receiving
        recv_buffer_ = buffer_pool_.acquire();
        if (!recv_buffer_.valid()) {
            // No buffers available - will retry on next event
            return;
        }

        auto* data = CompletionData::create(OpType::Recv, this);
        auto result = socket_.recv_async(ring_, recv_buffer_.full_span(), data);
        if (!result) {
            delete data;
            // Could schedule retry
        }
    }

    void close_internal() {
        bool was_connected = (state() == ConnectionState::Connected);

        set_state(ConnectionState::Closed);

        // Release any pending buffers
        recv_buffer_ = BufferHandle{};
        pending_sends_.clear();

        if (was_connected) {
            SIGNET_GAUGE_DEC(metrics::kActiveConnections);
        }

        if (callbacks_.on_close) {
            callbacks_.on_close();
        }
    }

    Ring& ring_;
    BufferPool& buffer_pool_;
    Socket socket_;

    std::atomic<ConnectionState> state_{ConnectionState::Disconnected};
    Endpoint remote_endpoint_;
    std::string hostname_;
    bool is_secure_ = false;

    ConnectionCallbacks callbacks_;
    ConnectionStats stats_;

    // Receive buffer (single buffer for now)
    BufferHandle recv_buffer_;

    // Pending send buffers (keyed by buffer index)
    std::unordered_map<size_t, BufferHandle> pending_sends_;
};

/// Connection pool for managing multiple connections
class ConnectionPool {
public:
    ConnectionPool(Ring& ring, BufferPool& buffer_pool, size_t max_connections = 100)
        : ring_(ring)
        , buffer_pool_(buffer_pool)
        , max_connections_(max_connections)
    {
        connections_.reserve(max_connections);
    }

    /// Create a new connection
    [[nodiscard]] Expected<Connection*> create() {
        if (connections_.size() >= max_connections_) {
            return unexpected(ErrorCode::ResourceLimit, "Connection pool full");
        }

        connections_.push_back(std::make_unique<Connection>(ring_, buffer_pool_));
        return connections_.back().get();
    }

    /// Remove a connection from the pool
    void remove(Connection* conn) {
        auto it = std::find_if(connections_.begin(), connections_.end(),
            [conn](const auto& ptr) { return ptr.get() == conn; });

        if (it != connections_.end()) {
            (*it)->close_sync();
            connections_.erase(it);
        }
    }

    /// Get number of connections
    [[nodiscard]] size_t size() const noexcept { return connections_.size(); }

    /// Get number of connected connections
    [[nodiscard]] size_t connected_count() const noexcept {
        return std::count_if(connections_.begin(), connections_.end(),
            [](const auto& conn) { return conn->is_connected(); });
    }

    /// Close all connections
    void close_all() {
        for (auto& conn : connections_) {
            conn->close_sync();
        }
        connections_.clear();
    }

private:
    Ring& ring_;
    BufferPool& buffer_pool_;
    size_t max_connections_;
    std::vector<std::unique_ptr<Connection>> connections_;
};

}  // namespace signet
