// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/ring.hpp"
#include "signet/net/address.hpp"

#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace signet {

// Forward declarations
class Ring;

/// Socket options for TCP tuning
struct SocketOptions {
    bool reuse_addr = true;
    bool reuse_port = false;
    bool tcp_nodelay = true;              // Disable Nagle's algorithm
    bool tcp_quickack = true;             // Send ACKs immediately
    int tcp_keepalive_idle = 60;          // Seconds before keepalive probes
    int tcp_keepalive_interval = 10;      // Seconds between probes
    int tcp_keepalive_count = 3;          // Failed probes before connection drop
    int send_buffer_size = 0;             // 0 = system default
    int recv_buffer_size = 0;             // 0 = system default
    bool non_blocking = true;
};

/// Metric names for socket operations
namespace metrics {
    constexpr const char* kSocketConnect = "socket.connect";
    constexpr const char* kSocketRead = "socket.read";
    constexpr const char* kSocketWrite = "socket.write";
    constexpr const char* kSocketClose = "socket.close";
    constexpr const char* kBytesRead = "socket.bytes_read";
    constexpr const char* kBytesWritten = "socket.bytes_written";
}  // namespace metrics

/// TCP socket with io_uring integration
class Socket {
public:
    /// Create an unconnected socket
    Socket() noexcept = default;

    /// Create from existing file descriptor (takes ownership)
    explicit Socket(int fd) noexcept : fd_(fd) {}

    ~Socket() {
        close_sync();
    }

    // Non-copyable
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Movable
    Socket(Socket&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close_sync();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    /// Create a TCP socket
    [[nodiscard]] static Expected<Socket> create(int family = AF_INET) {
        int fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            return unexpected(ErrorCode::SocketError, errno);
        }
        return Socket{fd};
    }

    /// Create with options applied
    [[nodiscard]] static Expected<Socket> create(int family, const SocketOptions& opts) {
        auto sock = create(family);
        if (!sock) return sock;

        auto result = sock->apply_options(opts);
        if (!result) {
            return unexpected(result.error());
        }
        return sock;
    }

    /// Apply socket options
    [[nodiscard]] Expected<void> apply_options(const SocketOptions& opts) {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        int optval = 1;

        // SO_REUSEADDR
        if (opts.reuse_addr) {
            if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
                return unexpected(ErrorCode::SocketError, errno);
            }
        }

        // SO_REUSEPORT
        if (opts.reuse_port) {
            if (setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
                return unexpected(ErrorCode::SocketError, errno);
            }
        }

        // TCP_NODELAY (disable Nagle)
        if (opts.tcp_nodelay) {
            if (setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
                return unexpected(ErrorCode::SocketError, errno);
            }
        }

        // TCP_QUICKACK
        if (opts.tcp_quickack) {
            if (setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, &optval, sizeof(optval)) < 0) {
                // Non-fatal, might not be supported
            }
        }

        // TCP keepalive
        if (opts.tcp_keepalive_idle > 0) {
            optval = 1;
            setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
            setsockopt(fd_, IPPROTO_TCP, TCP_KEEPIDLE, &opts.tcp_keepalive_idle, sizeof(int));
            setsockopt(fd_, IPPROTO_TCP, TCP_KEEPINTVL, &opts.tcp_keepalive_interval, sizeof(int));
            setsockopt(fd_, IPPROTO_TCP, TCP_KEEPCNT, &opts.tcp_keepalive_count, sizeof(int));
        }

        // Buffer sizes
        if (opts.send_buffer_size > 0) {
            setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &opts.send_buffer_size, sizeof(int));
        }
        if (opts.recv_buffer_size > 0) {
            setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &opts.recv_buffer_size, sizeof(int));
        }

        // Non-blocking
        if (opts.non_blocking) {
            int flags = fcntl(fd_, F_GETFL, 0);
            if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
                return unexpected(ErrorCode::SocketError, errno);
            }
        }

        return {};
    }

    /// Check if socket is open
    [[nodiscard]] bool is_open() const noexcept { return fd_ >= 0; }

    /// Get file descriptor
    [[nodiscard]] int fd() const noexcept { return fd_; }

    /// Release ownership of file descriptor
    [[nodiscard]] int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    /// Connect synchronously (blocking)
    [[nodiscard]] Expected<void> connect_sync(const Endpoint& endpoint) {
        SIGNET_TIMER_SCOPE(metrics::kSocketConnect);

        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        sockaddr_storage addr{};
        socklen_t addr_len;
        endpoint.to_sockaddr(&addr, &addr_len);

        // For non-blocking sockets, connect returns immediately with EINPROGRESS
        int ret = ::connect(fd_, reinterpret_cast<sockaddr*>(&addr), addr_len);
        if (ret < 0) {
            if (errno == EINPROGRESS) {
                // Need to wait for connection to complete
                // Use poll/select or let io_uring handle it
                return {};  // Caller should use async connect
            }
            return unexpected(ErrorCode::ConnectionFailed, errno);
        }

        return {};
    }

    /// Queue async connect via io_uring
    [[nodiscard]] Expected<void> connect_async(Ring& ring, const Endpoint& endpoint, void* user_data = nullptr) {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        // Store address in member for lifetime management
        endpoint.to_sockaddr(&connect_addr_, &connect_addr_len_);

        if (!ring.prep_connect(fd_, reinterpret_cast<sockaddr*>(&connect_addr_),
                               connect_addr_len_, user_data)) {
            return unexpected(ErrorCode::IoUringSQFull, "SQ full");
        }
        return {};
    }

    /// Queue async recv via io_uring
    [[nodiscard]] Expected<void> recv_async(Ring& ring, std::span<std::byte> buffer, void* user_data = nullptr) {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }
        if (!ring.prep_recv(fd_, buffer, 0, user_data)) {
            return unexpected(ErrorCode::IoUringSQFull, "SQ full");
        }
        return {};
    }

    /// Queue async send via io_uring
    [[nodiscard]] Expected<void> send_async(Ring& ring, std::span<const std::byte> data, void* user_data = nullptr) {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }
        if (!ring.prep_send(fd_, data, 0, user_data)) {
            return unexpected(ErrorCode::IoUringSQFull, "SQ full");
        }
        return {};
    }

    /// Queue async close via io_uring
    [[nodiscard]] Expected<void> close_async(Ring& ring, void* user_data = nullptr) {
        if (fd_ < 0) {
            return {};  // Already closed
        }
        if (!ring.prep_close(fd_, user_data)) {
            return unexpected(ErrorCode::IoUringSQFull, "SQ full");
        }
        fd_ = -1;  // Mark as closed
        return {};
    }

    /// Synchronous read (blocking)
    [[nodiscard]] Expected<size_t> read_sync(std::span<std::byte> buffer) {
        SIGNET_TIMER_SCOPE(metrics::kSocketRead);

        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        ssize_t n = ::read(fd_, buffer.data(), buffer.size());
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return size_t{0};  // Would block, try again
            }
            return unexpected(ErrorCode::ReadFailed, errno);
        }

        SIGNET_COUNTER_ADD(metrics::kBytesRead, n);
        return static_cast<size_t>(n);
    }

    /// Synchronous write (blocking)
    [[nodiscard]] Expected<size_t> write_sync(std::span<const std::byte> data) {
        SIGNET_TIMER_SCOPE(metrics::kSocketWrite);

        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        ssize_t n = ::write(fd_, data.data(), data.size());
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return size_t{0};  // Would block, try again
            }
            return unexpected(ErrorCode::WriteFailed, errno);
        }

        SIGNET_COUNTER_ADD(metrics::kBytesWritten, n);
        return static_cast<size_t>(n);
    }

    /// Synchronous close
    void close_sync() noexcept {
        SIGNET_TIMER_SCOPE(metrics::kSocketClose);

        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    /// Get local endpoint
    [[nodiscard]] Expected<Endpoint> local_endpoint() const {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        if (getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
            return unexpected(ErrorCode::SocketError, errno);
        }

        return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&addr));
    }

    /// Get remote endpoint
    [[nodiscard]] Expected<Endpoint> remote_endpoint() const {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        if (getpeername(fd_, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
            return unexpected(ErrorCode::SocketError, errno);
        }

        return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&addr));
    }

    /// Shutdown socket (SHUT_RD, SHUT_WR, or SHUT_RDWR)
    [[nodiscard]] Expected<void> shutdown(int how = SHUT_RDWR) {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        if (::shutdown(fd_, how) < 0) {
            return unexpected(ErrorCode::SocketError, errno);
        }
        return {};
    }

    /// Get socket error (for checking async connect result)
    [[nodiscard]] Expected<int> get_error() const {
        if (fd_ < 0) {
            return unexpected(ErrorCode::InvalidState, "Socket not open");
        }

        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            return unexpected(ErrorCode::SocketError, errno);
        }
        return error;
    }

private:
    int fd_ = -1;

    // Storage for async connect address
    sockaddr_storage connect_addr_{};
    socklen_t connect_addr_len_ = 0;
};

/// RAII socket guard that closes on destruction
class SocketGuard {
public:
    explicit SocketGuard(Socket& sock) noexcept : sock_(sock) {}

    ~SocketGuard() {
        sock_.close_sync();
    }

    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

private:
    Socket& sock_;
};

}  // namespace signet
