// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ktls.hpp
/// @brief Kernel TLS (kTLS) offload support for zero-copy encryption
///
/// kTLS allows the kernel to handle TLS encryption/decryption, enabling:
/// - Zero-copy sendfile() for TLS connections
/// - Hardware TLS offload on supported NICs
/// - Reduced CPU usage for TLS operations
/// - Integration with io_uring for async TLS I/O
///
/// Requirements:
/// - Linux kernel >= 4.17 (basic kTLS)
/// - Linux kernel >= 5.1 (TLS 1.3 receive)
/// - OpenSSL >= 3.0 (recommended)
/// - CONFIG_TLS in kernel config

#pragma once

#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef __linux__
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <string_view>

namespace signet {

/// kTLS support level
enum class KtlsSupport : uint8_t {
    None,           // No kTLS support
    SendOnly,       // TX offload only
    Full            // TX + RX offload
};

/// kTLS cipher info
struct KtlsCipherInfo {
    int tls_version;
    std::string_view cipher_name;
    bool supported;
};

/// Check if kTLS is supported on this system
[[nodiscard]] inline KtlsSupport check_ktls_support() noexcept {
#ifdef __linux__
    // Check if TLS kernel module is available
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return KtlsSupport::None;

    // Try to set TCP_ULP to "tls" - this will fail if not supported
    const char* ulp = "tls";
    int ret = setsockopt(fd, SOL_TCP, TCP_ULP, ulp, sizeof(ulp));
    close(fd);

    if (ret != 0) {
        return KtlsSupport::None;
    }

    // Check kernel version for RX support
    // TLS RX requires kernel >= 5.1
    struct utsname uts;
    if (uname(&uts) == 0) {
        int major = 0, minor = 0;
        if (std::sscanf(uts.release, "%d.%d", &major, &minor) >= 2) {
            if (major > 5 || (major == 5 && minor >= 1)) {
                return KtlsSupport::Full;
            }
        }
    }

    return KtlsSupport::SendOnly;
#else
    return KtlsSupport::None;
#endif
}

#ifdef __linux__

/// Enable kTLS on a socket after TLS handshake
/// This uses OpenSSL 3.x's native kTLS support if available
/// @param fd Socket file descriptor
/// @param ssl SSL object (after successful handshake)
/// @param enable_rx Enable receive offload (requires kernel >= 5.1)
/// @return Success or error
[[nodiscard]] inline Expected<void> enable_ktls(int fd, SSL* ssl, bool enable_rx = true) {
    (void)enable_rx;  // Currently we let OpenSSL handle RX offload

    if (!ssl) {
        return unexpected(ErrorCode::InvalidArgument, "SSL object is null");
    }

    // Get cipher info from SSL
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (!cipher) {
        return unexpected(ErrorCode::KTLSSetupFailed, "No cipher negotiated");
    }

    // Check TLS version
    int version = SSL_version(ssl);
    if (version < TLS1_2_VERSION) {
        return unexpected(ErrorCode::KTLSNotSupported,
                         "kTLS requires TLS 1.2 or later");
    }

    // Check cipher compatibility
    int cipher_nid = SSL_CIPHER_get_cipher_nid(cipher);
    bool cipher_supported = false;
    switch (cipher_nid) {
        case NID_aes_128_gcm:
        case NID_aes_256_gcm:
        case NID_chacha20_poly1305:
            cipher_supported = true;
            break;
        default:
            break;
    }

    if (!cipher_supported) {
        return unexpected(ErrorCode::KTLSNotSupported,
                         "Cipher not compatible with kTLS");
    }

    // OpenSSL 3.x has built-in kTLS support via SSL_OP_ENABLE_KTLS
    // We can also use BIO_get_ktls_send/recv to check status
#if defined(SSL_OP_ENABLE_KTLS)
    // Enable kTLS if OpenSSL supports it
    // Note: This must be set before handshake in production code
    // Here we just check if it's already enabled
    long options = SSL_get_options(ssl);
    if (!(options & SSL_OP_ENABLE_KTLS)) {
        // kTLS wasn't enabled before handshake, try to enable now
        // This may not work depending on OpenSSL version/config
        return unexpected(ErrorCode::KTLSNotSupported,
                         "kTLS must be enabled before handshake via SSL_OP_ENABLE_KTLS");
    }

    // Check if kTLS is actually active
    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    bool ktls_send = wbio && BIO_get_ktls_send(wbio);
    bool ktls_recv = rbio && BIO_get_ktls_recv(rbio);

    if (!ktls_send && !ktls_recv) {
        return unexpected(ErrorCode::KTLSSetupFailed,
                         "kTLS not active despite SSL_OP_ENABLE_KTLS");
    }

    return {};
#else
    // Manual kTLS setup would require extracting keys from OpenSSL
    // This is complex and version-dependent
    (void)fd;
    return unexpected(ErrorCode::KTLSNotSupported,
                     "OpenSSL version doesn't support SSL_OP_ENABLE_KTLS");
#endif
}

#else  // !__linux__

[[nodiscard]] inline Expected<void> enable_ktls(int, SSL*, bool = true) {
    return unexpected(ErrorCode::KTLSNotSupported, "kTLS only available on Linux");
}

#endif  // __linux__

/// Get kTLS statistics for a socket
struct KtlsStats {
    uint64_t tx_encrypted_bytes = 0;
    uint64_t rx_decrypted_bytes = 0;
    bool tx_offloaded = false;
    bool rx_offloaded = false;
};

#ifdef __linux__

[[nodiscard]] inline Expected<KtlsStats> get_ktls_stats([[maybe_unused]] int fd) {
    KtlsStats stats;
    // Note: Actual byte counters would require kernel support
    // or tracking in userspace. For now we just return structure.
    return stats;
}

#else

[[nodiscard]] inline Expected<KtlsStats> get_ktls_stats(int) {
    return KtlsStats{};
}

#endif

/// Check kTLS status on SSL connection
struct KtlsStatus {
    bool send_offloaded = false;
    bool recv_offloaded = false;
};

[[nodiscard]] inline KtlsStatus check_ktls_status(SSL* ssl) {
    KtlsStatus status;

    if (!ssl) return status;

#if defined(SSL_OP_ENABLE_KTLS)
    BIO* rbio = SSL_get_rbio(ssl);
    BIO* wbio = SSL_get_wbio(ssl);

    if (wbio) {
        status.send_offloaded = BIO_get_ktls_send(wbio) != 0;
    }
    if (rbio) {
        status.recv_offloaded = BIO_get_ktls_recv(rbio) != 0;
    }
#endif

    return status;
}

/// Determine if a cipher is suitable for kTLS
[[nodiscard]] inline bool is_ktls_compatible_cipher(const SSL_CIPHER* cipher) {
    if (!cipher) return false;

    int nid = SSL_CIPHER_get_cipher_nid(cipher);
    switch (nid) {
        case NID_aes_128_gcm:
        case NID_aes_256_gcm:
        case NID_chacha20_poly1305:
            return true;
        default:
            return false;
    }
}

/// Configure SSL context for kTLS support
/// Call this before creating SSL connections
[[nodiscard]] inline Expected<void> configure_ktls_context(SSL_CTX* ctx) {
    if (!ctx) {
        return unexpected(ErrorCode::InvalidArgument, "SSL_CTX is null");
    }

#if defined(SSL_OP_ENABLE_KTLS)
    // Enable kTLS for all connections from this context
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    return {};
#else
    return unexpected(ErrorCode::KTLSNotSupported,
                     "OpenSSL doesn't support SSL_OP_ENABLE_KTLS");
#endif
}

}  // namespace signet
