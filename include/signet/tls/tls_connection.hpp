// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/ring.hpp"
#include "signet/net/socket.hpp"
#include "signet/tls/tls_context.hpp"
#include "signet/tls/ktls.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace signet {

/// TLS connection state
enum class TlsState : uint8_t {
    Disconnected,
    Connecting,         // TCP connecting
    Handshaking,        // TLS handshake in progress
    Connected,          // Handshake complete, ready for data
    ShuttingDown,       // TLS shutdown in progress
    Closed,
    Error
};

[[nodiscard]] inline constexpr const char* to_string(TlsState state) noexcept {
    switch (state) {
        case TlsState::Disconnected: return "Disconnected";
        case TlsState::Connecting: return "Connecting";
        case TlsState::Handshaking: return "Handshaking";
        case TlsState::Connected: return "Connected";
        case TlsState::ShuttingDown: return "ShuttingDown";
        case TlsState::Closed: return "Closed";
        case TlsState::Error: return "Error";
    }
    return "Unknown";
}

/// TLS handshake result
enum class TlsHandshakeResult : uint8_t {
    Complete,           // Handshake finished
    WantRead,           // Need more data from peer
    WantWrite,          // Need to send data to peer
    Error               // Handshake failed
};

/// TLS connection statistics
struct TlsConnectionStats {
    std::chrono::steady_clock::time_point connect_time;
    std::chrono::steady_clock::time_point handshake_start;
    std::chrono::steady_clock::time_point handshake_complete;
    uint64_t bytes_encrypted = 0;
    uint64_t bytes_decrypted = 0;
    bool ktls_enabled = false;
    bool session_reused = false;
    std::string negotiated_protocol;  // ALPN result
    std::string cipher_suite;
    int tls_version = 0;
};

/// TLS connection wrapping a TCP socket
/// Supports both userspace OpenSSL and kernel TLS offload
class TlsConnection {
public:
    /// Create TLS connection over an existing socket
    TlsConnection(Socket socket, TlsContext& ctx)
        : socket_(std::move(socket))
        , ctx_(ctx)
    {}

    ~TlsConnection() {
        close_sync();
    }

    // Non-copyable
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    // Movable (with care)
    TlsConnection(TlsConnection&& other) noexcept
        : socket_(std::move(other.socket_))
        , ctx_(other.ctx_)
        , ssl_(std::move(other.ssl_))
        , state_(other.state_)
        , ktls_enabled_(other.ktls_enabled_)
        , hostname_(std::move(other.hostname_))
        , stats_(other.stats_)
    {
        other.state_ = TlsState::Closed;
    }

    /// Get connection state
    [[nodiscard]] TlsState state() const noexcept { return state_; }

    /// Check if connected and handshake complete
    [[nodiscard]] bool is_connected() const noexcept {
        return state_ == TlsState::Connected;
    }

    /// Check if kTLS is enabled
    [[nodiscard]] bool is_ktls_enabled() const noexcept {
        return ktls_enabled_;
    }

    /// Get connection statistics
    [[nodiscard]] const TlsConnectionStats& stats() const noexcept {
        return stats_;
    }

    /// Get underlying socket
    [[nodiscard]] Socket& socket() noexcept { return socket_; }
    [[nodiscard]] const Socket& socket() const noexcept { return socket_; }

    /// Get SSL object (for advanced operations)
    [[nodiscard]] SSL* native_ssl() const noexcept { return ssl_.get(); }

    /// Initialize TLS connection (after TCP connect)
    [[nodiscard]] Expected<void> init_tls(std::string_view hostname = "") {
        if (ssl_) {
            return unexpected(ErrorCode::InvalidState, "TLS already initialized");
        }

        // Create SSL object
        auto ssl_result = ctx_.create_ssl();
        if (!ssl_result) {
            return unexpected(ssl_result.error());
        }
        ssl_ = std::move(*ssl_result);

        // Set socket as BIO
        if (!SSL_set_fd(ssl_.get(), socket_.fd())) {
            return unexpected(ErrorCode::TLSHandshakeFailed, get_ssl_error_string());
        }

        // Configure for client if applicable
        if (ctx_.is_client()) {
            SSL_set_connect_state(ssl_.get());

            // Set hostname for SNI and verification
            if (!hostname.empty()) {
                hostname_ = std::string(hostname);
                auto result = configure_hostname_verification(ssl_.get(), hostname_);
                if (!result) {
                    return unexpected(result.error());
                }
            }
        } else {
            SSL_set_accept_state(ssl_.get());
        }

        return {};
    }

    /// Start TLS handshake (non-blocking)
    /// Returns WantRead/WantWrite if more I/O needed
    [[nodiscard]] TlsHandshakeResult handshake() {
        SIGNET_TIMER_SCOPE(metrics::kTlsHandshake);

        if (!ssl_) {
            state_ = TlsState::Error;
            return TlsHandshakeResult::Error;
        }

        if (state_ == TlsState::Disconnected || state_ == TlsState::Connecting) {
            state_ = TlsState::Handshaking;
            stats_.handshake_start = std::chrono::steady_clock::now();
        }

        int ret;
        if (ctx_.is_client()) {
            ret = SSL_connect(ssl_.get());
        } else {
            ret = SSL_accept(ssl_.get());
        }

        if (ret == 1) {
            // SECURITY (CRITICAL #8): on_handshake_complete now returns success/fail.
            // If post-handshake verification fails (hostname/cert), we MUST report
            // Error to the caller — otherwise they'd proceed to send data over an
            // unverified channel.
            if (!on_handshake_complete()) {
                return TlsHandshakeResult::Error;
            }
            return TlsHandshakeResult::Complete;
        }

        int err = SSL_get_error(ssl_.get(), ret);
        switch (err) {
            case SSL_ERROR_WANT_READ:
                return TlsHandshakeResult::WantRead;
            case SSL_ERROR_WANT_WRITE:
                return TlsHandshakeResult::WantWrite;
            case SSL_ERROR_ZERO_RETURN:
                // Peer closed connection
                state_ = TlsState::Closed;
                return TlsHandshakeResult::Error;
            default:
                SIGNET_COUNTER_INC(metrics::kTlsHandshakeErrors);
                state_ = TlsState::Error;
                return TlsHandshakeResult::Error;
        }
    }

    /// Perform blocking TLS handshake
    [[nodiscard]] Expected<void> handshake_sync() {
        auto result = handshake();
        while (result == TlsHandshakeResult::WantRead ||
               result == TlsHandshakeResult::WantWrite) {
            // For blocking sockets, just retry
            result = handshake();
        }

        if (result == TlsHandshakeResult::Complete) {
            return {};
        }

        return unexpected(ErrorCode::TLSHandshakeFailed,
                         "Handshake failed: " + get_ssl_error_queue());
    }

    /// Read decrypted data (non-blocking)
    /// @return Bytes read, 0 for WantRead, or error
    [[nodiscard]] Expected<size_t> read(std::span<std::byte> buffer) {
        if (!is_connected()) {
            return unexpected(ErrorCode::InvalidState, "Not connected");
        }

        if (ktls_enabled_) {
            // With kTLS, we can read directly from socket
            // Kernel handles decryption
            return socket_.read_sync(buffer);
        }

        // Userspace TLS
        int n = SSL_read(ssl_.get(), buffer.data(), static_cast<int>(buffer.size()));

        if (n > 0) {
            stats_.bytes_decrypted += static_cast<uint64_t>(n);
            return static_cast<size_t>(n);
        }

        int err = SSL_get_error(ssl_.get(), n);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return size_t{0};
            case SSL_ERROR_ZERO_RETURN:
                // Clean shutdown
                state_ = TlsState::Closed;
                return size_t{0};
            default:
                state_ = TlsState::Error;
                return unexpected(ErrorCode::ReadFailed, get_ssl_error_queue());
        }
    }

    /// Write data for encryption (non-blocking)
    /// @return Bytes written, 0 for WantWrite, or error
    [[nodiscard]] Expected<size_t> write(std::span<const std::byte> data) {
        if (!is_connected()) {
            return unexpected(ErrorCode::InvalidState, "Not connected");
        }

        if (ktls_enabled_) {
            // With kTLS, we can write directly to socket
            // Kernel handles encryption
            return socket_.write_sync(data);
        }

        // Userspace TLS
        int n = SSL_write(ssl_.get(), data.data(), static_cast<int>(data.size()));

        if (n > 0) {
            stats_.bytes_encrypted += static_cast<uint64_t>(n);
            return static_cast<size_t>(n);
        }

        int err = SSL_get_error(ssl_.get(), n);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return size_t{0};
            case SSL_ERROR_ZERO_RETURN:
                state_ = TlsState::Closed;
                return size_t{0};
            default:
                state_ = TlsState::Error;
                return unexpected(ErrorCode::WriteFailed, get_ssl_error_queue());
        }
    }

    /// Write string data
    [[nodiscard]] Expected<size_t> write(std::string_view data) {
        return write(std::as_bytes(std::span{data.data(), data.size()}));
    }

    /// Initiate TLS shutdown (non-blocking)
    [[nodiscard]] Expected<bool> shutdown() {
        if (!ssl_ || state_ == TlsState::Closed) {
            return true;
        }

        state_ = TlsState::ShuttingDown;

        int ret = SSL_shutdown(ssl_.get());
        if (ret == 1) {
            // Clean bidirectional shutdown complete
            state_ = TlsState::Closed;
            return true;
        }
        if (ret == 0) {
            // Shutdown initiated, need to call again for bidirectional
            return false;
        }

        int err = SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return false;
        }

        // Error during shutdown
        state_ = TlsState::Error;
        return unexpected(ErrorCode::Closed, get_ssl_error_queue());
    }

    /// Close connection synchronously
    void close_sync() {
        if (state_ == TlsState::Closed) return;

        if (ssl_ && state_ == TlsState::Connected) {
            // Attempt graceful TLS shutdown (non-blocking)
            SSL_shutdown(ssl_.get());
        }

        ssl_.reset();
        socket_.close_sync();
        state_ = TlsState::Closed;
    }

    /// Enable kTLS if possible (after handshake)
    [[nodiscard]] Expected<void> enable_ktls_offload() {
        if (!is_connected()) {
            return unexpected(ErrorCode::InvalidState, "Not connected");
        }

        if (ktls_enabled_) {
            return {};  // Already enabled
        }

        // Check if cipher is compatible
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
        if (!is_ktls_compatible_cipher(cipher)) {
            return unexpected(ErrorCode::KTLSNotSupported,
                            "Cipher not compatible with kTLS");
        }

        auto result = enable_ktls(socket_.fd(), ssl_.get(), true);
        if (!result) {
            return unexpected(result.error());
        }

        ktls_enabled_ = true;
        stats_.ktls_enabled = true;
        SIGNET_GAUGE_INC(metrics::kKtlsEnabled);

        return {};
    }

    /// Get peer certificate
    [[nodiscard]] X509Ptr get_peer_certificate() const {
        if (!ssl_) return nullptr;
        return X509Ptr(SSL_get_peer_certificate(ssl_.get()));
    }

    /// Get negotiated ALPN protocol
    [[nodiscard]] std::string_view get_alpn_protocol() const {
        if (!ssl_) return {};

        const unsigned char* proto = nullptr;
        unsigned int len = 0;
        SSL_get0_alpn_selected(ssl_.get(), &proto, &len);

        if (proto && len > 0) {
            return std::string_view(reinterpret_cast<const char*>(proto), len);
        }
        return {};
    }

    /// Get negotiated cipher suite
    [[nodiscard]] std::string_view get_cipher() const {
        if (!ssl_) return {};
        const char* cipher = SSL_get_cipher(ssl_.get());
        return cipher ? cipher : "";
    }

    /// Get TLS version
    [[nodiscard]] int get_version() const {
        if (!ssl_) return 0;
        return SSL_version(ssl_.get());
    }

    /// Get TLS version as string
    [[nodiscard]] std::string_view get_version_string() const {
        if (!ssl_) return {};
        const char* ver = SSL_get_version(ssl_.get());
        return ver ? ver : "";
    }

    /// Check if session was reused
    [[nodiscard]] bool is_session_reused() const {
        return ssl_ && SSL_session_reused(ssl_.get());
    }

private:
    /// SECURITY (CRITICAL #8): Returns false if peer certificate / hostname
    /// verification failed. Caller (handshake()) MUST propagate failure to
    /// the user — never report a handshake as Complete on verification failure.
    [[nodiscard]] bool on_handshake_complete() {
        stats_.handshake_complete = std::chrono::steady_clock::now();
        stats_.session_reused = SSL_session_reused(ssl_.get());
        stats_.cipher_suite = std::string(get_cipher());
        stats_.tls_version = SSL_version(ssl_.get());

        auto alpn = get_alpn_protocol();
        if (!alpn.empty()) {
            stats_.negotiated_protocol = std::string(alpn);
        }

        // Verify peer post-handshake. The hostname was set on the SSL via
        // configure_hostname_verification() in init_tls() BEFORE the handshake,
        // so OpenSSL has already done chain + hostname verification — we just
        // confirm the result is X509_V_OK and that a peer cert was actually
        // presented.
        if (ctx_.is_client() && ctx_.config().verify_mode != TlsVerifyMode::None) {
            if (!hostname_.empty() && ctx_.config().verify_hostname) {
                if (!verify_peer_post_handshake(ssl_.get(), hostname_)) {
                    state_ = TlsState::Error;
                    SIGNET_COUNTER_INC(metrics::kTlsHandshakeErrors);
                    return false;
                }
            } else {
                // No hostname check requested — at least confirm chain validation
                // passed and a cert was presented.
                X509* cert = SSL_get_peer_certificate(ssl_.get());
                if (!cert) {
                    state_ = TlsState::Error;
                    SIGNET_COUNTER_INC(metrics::kTlsHandshakeErrors);
                    return false;
                }
                X509_free(cert);
                if (SSL_get_verify_result(ssl_.get()) != X509_V_OK) {
                    state_ = TlsState::Error;
                    SIGNET_COUNTER_INC(metrics::kTlsHandshakeErrors);
                    return false;
                }
            }
        }

        if (stats_.session_reused) {
            SIGNET_COUNTER_INC(metrics::kTlsSessionResume);
        }

        // Only mark as Connected after verification passes.
        state_ = TlsState::Connected;
        return true;
    }

    Socket socket_;
    TlsContext& ctx_;
    SslPtr ssl_;
    TlsState state_ = TlsState::Disconnected;
    bool ktls_enabled_ = false;
    std::string hostname_;
    TlsConnectionStats stats_;
};

/// Factory function to create TLS client connection
[[nodiscard]] inline Expected<TlsConnection> create_tls_client(
    const Endpoint& endpoint,
    TlsContext& ctx,
    std::string_view hostname = "") {

    // Create socket
    auto sock = Socket::create(endpoint.family());
    if (!sock) {
        return unexpected(sock.error());
    }

    // Apply default options
    SocketOptions opts;
    opts.tcp_nodelay = true;
    opts.non_blocking = false;  // Blocking for sync handshake
    auto opt_result = sock->apply_options(opts);
    if (!opt_result) {
        return unexpected(opt_result.error());
    }

    // Connect
    auto conn_result = sock->connect_sync(endpoint);
    if (!conn_result) {
        return unexpected(conn_result.error());
    }

    // Create TLS connection
    TlsConnection conn(std::move(*sock), ctx);

    // Initialize TLS
    auto init_result = conn.init_tls(hostname);
    if (!init_result) {
        return unexpected(init_result.error());
    }

    // Perform handshake
    auto hs_result = conn.handshake_sync();
    if (!hs_result) {
        return unexpected(hs_result.error());
    }

    // Try to enable kTLS (best-effort)
    auto ktls_result = conn.enable_ktls_offload();
    (void)ktls_result;  // kTLS is optional, don't fail if unavailable

    return conn;
}

}  // namespace signet
