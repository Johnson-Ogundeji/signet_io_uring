// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

// Use tl::expected for error handling
#include <tl/expected.hpp>

namespace signet {

/// Error codes for Signet operations
enum class ErrorCode : uint32_t {
    // Success
    Success = 0,

    // Connection errors (100-199)
    ConnectionFailed = 100,
    ConnectionTimeout = 101,
    ConnectionRefused = 102,
    ConnectionReset = 103,
    DNSFailed = 104,
    HostUnreachable = 105,
    NetworkUnreachable = 106,
    AlreadyConnected = 107,
    NotConnected = 108,

    // TLS errors (200-299)
    TLSHandshakeFailed = 200,
    TLSCertificateInvalid = 201,
    TLSCertificateExpired = 202,
    TLSCertificateRevoked = 203,
    TLSProtocolError = 204,
    TLSKeyError = 205,
    KTLSNotSupported = 206,
    KTLSSetupFailed = 207,

    // WebSocket protocol errors (300-399)
    HandshakeFailed = 300,
    HandshakeTimeout = 301,
    InvalidUpgradeResponse = 302,
    InvalidFrame = 303,
    InvalidOpcode = 304,
    InvalidUTF8 = 305,
    InvalidCloseCode = 306,
    MessageTooLarge = 307,
    FrameTooLarge = 308,
    ControlFrameTooLarge = 309,
    FragmentedControlFrame = 310,
    UnexpectedContinuation = 311,
    ExpectedContinuation = 312,
    ReservedBitSet = 313,
    MaskingRequired = 314,
    MaskingForbidden = 315,
    ProtocolViolation = 316,
    ExtensionError = 317,
    CompressionFailed = 318,
    DecompressionFailed = 319,

    // io_uring errors (400-499)
    IoUringSetupFailed = 400,
    IoUringSubmitFailed = 401,
    IoUringWaitFailed = 402,
    IoUringSQFull = 403,
    IoUringCQOverflow = 404,
    IoUringBufferRegisterFailed = 405,
    IoUringNotSupported = 406,

    // Buffer errors (500-599)
    BufferExhausted = 500,
    BufferTooSmall = 501,
    BufferOverflow = 502,
    BufferUnderflow = 503,

    // System errors (600-699)
    IOError = 600,
    OutOfMemory = 601,
    PermissionDenied = 602,
    ResourceBusy = 603,
    Timeout = 604,
    Interrupted = 605,
    WouldBlock = 606,
    SocketError = 607,
    ReadFailed = 608,
    WriteFailed = 609,
    DnsResolutionFailed = 610,
    ResourceLimit = 611,

    // Application errors (700-799)
    Cancelled = 700,
    Closed = 701,
    InvalidArgument = 702,
    InvalidState = 703,
    NotSupported = 704,
    AlreadyExists = 705,
    ConnectionClosed = 706,
    WebSocketHandshakeFailed = 707,
    WebSocketProtocolError = 708,
    InvalidUrl = 709,

    // Unknown
    Unknown = 999
};

/// Convert error code to string
[[nodiscard]] constexpr std::string_view error_code_to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Success: return "Success";

        // Connection
        case ErrorCode::ConnectionFailed: return "Connection failed";
        case ErrorCode::ConnectionTimeout: return "Connection timeout";
        case ErrorCode::ConnectionRefused: return "Connection refused";
        case ErrorCode::ConnectionReset: return "Connection reset";
        case ErrorCode::DNSFailed: return "DNS resolution failed";
        case ErrorCode::HostUnreachable: return "Host unreachable";
        case ErrorCode::NetworkUnreachable: return "Network unreachable";
        case ErrorCode::AlreadyConnected: return "Already connected";
        case ErrorCode::NotConnected: return "Not connected";

        // TLS
        case ErrorCode::TLSHandshakeFailed: return "TLS handshake failed";
        case ErrorCode::TLSCertificateInvalid: return "Invalid TLS certificate";
        case ErrorCode::TLSCertificateExpired: return "TLS certificate expired";
        case ErrorCode::TLSCertificateRevoked: return "TLS certificate revoked";
        case ErrorCode::TLSProtocolError: return "TLS protocol error";
        case ErrorCode::TLSKeyError: return "TLS key error";
        case ErrorCode::KTLSNotSupported: return "kTLS not supported";
        case ErrorCode::KTLSSetupFailed: return "kTLS setup failed";

        // WebSocket
        case ErrorCode::HandshakeFailed: return "WebSocket handshake failed";
        case ErrorCode::HandshakeTimeout: return "WebSocket handshake timeout";
        case ErrorCode::InvalidUpgradeResponse: return "Invalid upgrade response";
        case ErrorCode::InvalidFrame: return "Invalid WebSocket frame";
        case ErrorCode::InvalidOpcode: return "Invalid opcode";
        case ErrorCode::InvalidUTF8: return "Invalid UTF-8 in text frame";
        case ErrorCode::InvalidCloseCode: return "Invalid close code";
        case ErrorCode::MessageTooLarge: return "Message too large";
        case ErrorCode::FrameTooLarge: return "Frame too large";
        case ErrorCode::ControlFrameTooLarge: return "Control frame too large";
        case ErrorCode::FragmentedControlFrame: return "Fragmented control frame";
        case ErrorCode::UnexpectedContinuation: return "Unexpected continuation frame";
        case ErrorCode::ExpectedContinuation: return "Expected continuation frame";
        case ErrorCode::ReservedBitSet: return "Reserved bit set";
        case ErrorCode::MaskingRequired: return "Masking required";
        case ErrorCode::MaskingForbidden: return "Masking forbidden";
        case ErrorCode::ProtocolViolation: return "Protocol violation";
        case ErrorCode::ExtensionError: return "Extension error";
        case ErrorCode::CompressionFailed: return "Compression failed";
        case ErrorCode::DecompressionFailed: return "Decompression failed";

        // io_uring
        case ErrorCode::IoUringSetupFailed: return "io_uring setup failed";
        case ErrorCode::IoUringSubmitFailed: return "io_uring submit failed";
        case ErrorCode::IoUringWaitFailed: return "io_uring wait failed";
        case ErrorCode::IoUringSQFull: return "io_uring submission queue full";
        case ErrorCode::IoUringCQOverflow: return "io_uring completion queue overflow";
        case ErrorCode::IoUringBufferRegisterFailed: return "io_uring buffer registration failed";
        case ErrorCode::IoUringNotSupported: return "io_uring not supported";

        // Buffer
        case ErrorCode::BufferExhausted: return "Buffer pool exhausted";
        case ErrorCode::BufferTooSmall: return "Buffer too small";
        case ErrorCode::BufferOverflow: return "Buffer overflow";
        case ErrorCode::BufferUnderflow: return "Buffer underflow";

        // System
        case ErrorCode::IOError: return "I/O error";
        case ErrorCode::OutOfMemory: return "Out of memory";
        case ErrorCode::PermissionDenied: return "Permission denied";
        case ErrorCode::ResourceBusy: return "Resource busy";
        case ErrorCode::Timeout: return "Operation timeout";
        case ErrorCode::Interrupted: return "Operation interrupted";
        case ErrorCode::WouldBlock: return "Operation would block";
        case ErrorCode::SocketError: return "Socket error";
        case ErrorCode::ReadFailed: return "Read failed";
        case ErrorCode::WriteFailed: return "Write failed";
        case ErrorCode::DnsResolutionFailed: return "DNS resolution failed";
        case ErrorCode::ResourceLimit: return "Resource limit exceeded";

        // Application
        case ErrorCode::Cancelled: return "Operation cancelled";
        case ErrorCode::Closed: return "Connection closed";
        case ErrorCode::InvalidArgument: return "Invalid argument";
        case ErrorCode::InvalidState: return "Invalid state";
        case ErrorCode::NotSupported: return "Operation not supported";
        case ErrorCode::AlreadyExists: return "Already exists";
        case ErrorCode::ConnectionClosed: return "Connection closed";
        case ErrorCode::WebSocketHandshakeFailed: return "WebSocket handshake failed";
        case ErrorCode::WebSocketProtocolError: return "WebSocket protocol error";
        case ErrorCode::InvalidUrl: return "Invalid URL";

        case ErrorCode::Unknown: return "Unknown error";
        default: return "Unknown error";
    }
}

/// Error class with code and optional details
class Error {
public:
    Error() = default;

    explicit Error(ErrorCode code) noexcept
        : code_(code) {}

    Error(ErrorCode code, std::string detail) noexcept
        : code_(code), detail_(std::move(detail)) {}

    Error(ErrorCode code, int system_errno) noexcept
        : code_(code), system_errno_(system_errno) {}

    Error(ErrorCode code, std::string detail, int system_errno) noexcept
        : code_(code), detail_(std::move(detail)), system_errno_(system_errno) {}

    /// Get error code
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }

    /// Get error message
    [[nodiscard]] std::string_view message() const noexcept {
        return error_code_to_string(code_);
    }

    /// Get additional detail
    [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

    /// Get system errno (if applicable)
    [[nodiscard]] int system_errno() const noexcept { return system_errno_; }

    /// Get full error description
    [[nodiscard]] std::string to_string() const {
        std::string result(message());
        if (!detail_.empty()) {
            result += ": ";
            result += detail_;
        }
        if (system_errno_ != 0) {
            result += " (errno: ";
            result += std::to_string(system_errno_);
            result += ")";
        }
        return result;
    }

    /// Check if this is an error (non-success)
    explicit operator bool() const noexcept {
        return code_ != ErrorCode::Success;
    }

    /// Equality comparison
    bool operator==(const Error& other) const noexcept {
        return code_ == other.code_;
    }

    bool operator==(ErrorCode code) const noexcept {
        return code_ == code;
    }

private:
    ErrorCode code_ = ErrorCode::Success;
    std::string detail_;
    int system_errno_ = 0;
};

/// Expected type alias for Signet
template<typename T>
using Expected = tl::expected<T, Error>;

/// Unexpected error helper
inline auto unexpected(ErrorCode code) {
    return tl::unexpected(Error(code));
}

inline auto unexpected(ErrorCode code, std::string detail) {
    return tl::unexpected(Error(code, std::move(detail)));
}

inline auto unexpected(ErrorCode code, int system_errno) {
    return tl::unexpected(Error(code, system_errno));
}

inline auto unexpected(Error error) {
    return tl::unexpected(std::move(error));
}

/// Convert system errno to ErrorCode
[[nodiscard]] inline ErrorCode errno_to_error_code(int err) noexcept {
    switch (err) {
        case 0: return ErrorCode::Success;
        case ECONNREFUSED: return ErrorCode::ConnectionRefused;
        case ECONNRESET: return ErrorCode::ConnectionReset;
        case ETIMEDOUT: return ErrorCode::ConnectionTimeout;
        case EHOSTUNREACH: return ErrorCode::HostUnreachable;
        case ENETUNREACH: return ErrorCode::NetworkUnreachable;
        case EACCES:
        case EPERM: return ErrorCode::PermissionDenied;
        case ENOMEM: return ErrorCode::OutOfMemory;
        case EBUSY: return ErrorCode::ResourceBusy;
        case EINTR: return ErrorCode::Interrupted;
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            return ErrorCode::WouldBlock;
        case EINVAL: return ErrorCode::InvalidArgument;
        case EEXIST: return ErrorCode::AlreadyExists;
        case ENOTSUP:
#if ENOTSUP != EOPNOTSUPP
        case EOPNOTSUPP:
#endif
            return ErrorCode::NotSupported;
        default: return ErrorCode::IOError;
    }
}

/// Create error from errno
[[nodiscard]] inline Error error_from_errno(int err) {
    return Error(errno_to_error_code(err), err);
}

/// Create error from errno with detail
[[nodiscard]] inline Error error_from_errno(int err, std::string detail) {
    return Error(errno_to_error_code(err), std::move(detail), err);
}

}  // namespace signet
