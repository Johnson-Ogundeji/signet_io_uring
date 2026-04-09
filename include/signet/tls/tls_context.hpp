// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace signet {

/// TLS verification mode
enum class TlsVerifyMode : uint8_t {
    None,           // No verification (insecure)
    Peer,           // Verify peer certificate
    FailIfNoPeer    // Fail if peer doesn't present certificate
};

/// TLS version constraints
struct TlsVersions {
    int min_version = TLS1_2_VERSION;
    int max_version = TLS1_3_VERSION;
};

/// TLS context configuration
struct TlsContextConfig {
    TlsVerifyMode verify_mode = TlsVerifyMode::Peer;
    TlsVersions versions;

    // Certificate verification
    std::string ca_file;                    // CA certificate file
    std::string ca_path;                    // CA certificate directory
    bool verify_hostname = true;            // Verify hostname in certificate

    // Client certificate (mutual TLS)
    std::string cert_file;                  // Client certificate file
    std::string key_file;                   // Client private key file
    std::string key_password;               // Private key password (if encrypted)

    // Cipher configuration
    std::string ciphers;                    // OpenSSL cipher string (TLS 1.2)
    std::string ciphersuites;               // TLS 1.3 ciphersuites

    // Session caching
    bool enable_session_cache = true;
    size_t session_cache_size = 1024;

    // ALPN (Application-Layer Protocol Negotiation)
    std::vector<std::string> alpn_protocols;
};

// TLS metrics are defined in signet/core/metrics.hpp
// We just use the signet::metrics namespace here

/// Custom deleter for OpenSSL objects
struct SslContextDeleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct SslDeleter {
    void operator()(SSL* ssl) const noexcept {
        if (ssl) SSL_free(ssl);
    }
};

struct X509Deleter {
    void operator()(X509* cert) const noexcept {
        if (cert) X509_free(cert);
    }
};

using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

/// Get OpenSSL error string
[[nodiscard]] inline std::string get_ssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "No error";

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

/// Get all OpenSSL errors from the queue
[[nodiscard]] inline std::string get_ssl_error_queue() {
    std::string result;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!result.empty()) result += "; ";
        result += buf;
    }
    return result.empty() ? "No error" : result;
}

/// TLS context for creating TLS connections
/// Thread-safe: can be shared across connections
class TlsContext {
public:
    /// Create client TLS context
    [[nodiscard]] static Expected<TlsContext> create_client(TlsContextConfig config = {}) {
        // Initialize OpenSSL (thread-safe, idempotent)
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

        // Create SSL context with TLS client method
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            return unexpected(ErrorCode::TLSKeyError, get_ssl_error_string());
        }

        TlsContext tls_ctx;
        tls_ctx.ctx_.reset(ctx);
        tls_ctx.config_ = std::move(config);
        tls_ctx.is_client_ = true;

        // Configure context
        auto result = tls_ctx.configure();
        if (!result) {
            return unexpected(result.error());
        }

        return tls_ctx;
    }

    /// Create server TLS context
    [[nodiscard]] static Expected<TlsContext> create_server(TlsContextConfig config) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            return unexpected(ErrorCode::TLSKeyError, get_ssl_error_string());
        }

        TlsContext tls_ctx;
        tls_ctx.ctx_.reset(ctx);
        tls_ctx.config_ = std::move(config);
        tls_ctx.is_client_ = false;

        auto result = tls_ctx.configure();
        if (!result) {
            return unexpected(result.error());
        }

        return tls_ctx;
    }

    // Movable
    TlsContext(TlsContext&&) = default;
    TlsContext& operator=(TlsContext&&) = default;

    // Non-copyable (SSL_CTX can be shared but we use unique_ptr)
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    /// Get native SSL_CTX handle
    [[nodiscard]] SSL_CTX* native_handle() const noexcept {
        return ctx_.get();
    }

    /// Check if this is a client context
    [[nodiscard]] bool is_client() const noexcept { return is_client_; }

    /// Get configuration
    [[nodiscard]] const TlsContextConfig& config() const noexcept {
        return config_;
    }

    /// Create a new SSL connection object
    [[nodiscard]] Expected<SslPtr> create_ssl() const {
        SSL* ssl = SSL_new(ctx_.get());
        if (!ssl) {
            return unexpected(ErrorCode::TLSHandshakeFailed, get_ssl_error_string());
        }
        return SslPtr(ssl);
    }

private:
    TlsContext() = default;

    /// Configure the SSL context based on config
    [[nodiscard]] Expected<void> configure() {
        // Set TLS versions
        if (!SSL_CTX_set_min_proto_version(ctx_.get(), config_.versions.min_version)) {
            return unexpected(ErrorCode::TLSProtocolError, "Failed to set min TLS version");
        }
        if (!SSL_CTX_set_max_proto_version(ctx_.get(), config_.versions.max_version)) {
            return unexpected(ErrorCode::TLSProtocolError, "Failed to set max TLS version");
        }

        // Configure verification
        int verify_flags = SSL_VERIFY_NONE;
        switch (config_.verify_mode) {
            case TlsVerifyMode::None:
                verify_flags = SSL_VERIFY_NONE;
                break;
            case TlsVerifyMode::Peer:
                verify_flags = SSL_VERIFY_PEER;
                break;
            case TlsVerifyMode::FailIfNoPeer:
                verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                break;
        }
        // SECURITY (CRITICAL #7): Use default OpenSSL verification callback (nullptr).
        // The default callback DOES validate the cert chain against the CA store and
        // honors X509_VERIFY_PARAM_set1_host hostname constraints set per-connection.
        // The cert chain check happens during the handshake; hostname verification
        // is enforced by configure_hostname_verification() called in init_tls() BEFORE
        // SSL_connect(). Without that pre-handshake setup, the chain still validates
        // but hostname mismatches are not caught. tls_connection.hpp handles both.
        SSL_CTX_set_verify(ctx_.get(), verify_flags, nullptr);

        // Load CA certificates
        if (!config_.ca_file.empty() || !config_.ca_path.empty()) {
            if (!SSL_CTX_load_verify_locations(
                    ctx_.get(),
                    config_.ca_file.empty() ? nullptr : config_.ca_file.c_str(),
                    config_.ca_path.empty() ? nullptr : config_.ca_path.c_str())) {
                return unexpected(ErrorCode::TLSCertificateInvalid,
                                 "Failed to load CA certificates: " + get_ssl_error_string());
            }
        } else {
            // SECURITY (MEDIUM #40): Default CA paths. SSL_CTX_set_default_verify_paths
            // returns 1 on success and 0 on failure. If verification is enabled and we
            // couldn't load any CA store, fail loudly — silently trusting nothing means
            // every cert validation will fail at handshake time with confusing errors.
            if (verify_flags != SSL_VERIFY_NONE) {
                if (SSL_CTX_set_default_verify_paths(ctx_.get()) != 1) {
                    return unexpected(ErrorCode::TLSCertificateInvalid,
                                     "Verification enabled but no CA file/path provided "
                                     "and default CA paths failed to load: " +
                                     get_ssl_error_string());
                }
            } else {
                SSL_CTX_set_default_verify_paths(ctx_.get());
            }
        }

        // Load client certificate (for mutual TLS)
        if (!config_.cert_file.empty()) {
            if (SSL_CTX_use_certificate_file(ctx_.get(), config_.cert_file.c_str(),
                                            SSL_FILETYPE_PEM) != 1) {
                return unexpected(ErrorCode::TLSCertificateInvalid,
                                 "Failed to load certificate: " + get_ssl_error_string());
            }
        }

        // Load private key
        if (!config_.key_file.empty()) {
            // Set password callback if key is encrypted
            if (!config_.key_password.empty()) {
                SSL_CTX_set_default_passwd_cb_userdata(
                    ctx_.get(), const_cast<char*>(config_.key_password.c_str()));
                SSL_CTX_set_default_passwd_cb(ctx_.get(),
                    [](char* buf, int size, int, void* userdata) -> int {
                        const char* pwd = static_cast<const char*>(userdata);
                        int len = static_cast<int>(std::strlen(pwd));
                        if (len > size) len = size;
                        std::memcpy(buf, pwd, static_cast<size_t>(len));
                        return len;
                    });
            }

            int key_load_result = SSL_CTX_use_PrivateKey_file(ctx_.get(), config_.key_file.c_str(),
                                                              SSL_FILETYPE_PEM);

            // SECURITY (HIGH #31): Wipe private key password from memory immediately
            // after key is loaded. Clear callback so config_.key_password can never be
            // re-read by OpenSSL.
            if (!config_.key_password.empty()) {
                SSL_CTX_set_default_passwd_cb_userdata(ctx_.get(), nullptr);
                SSL_CTX_set_default_passwd_cb(ctx_.get(), nullptr);
                OPENSSL_cleanse(config_.key_password.data(), config_.key_password.size());
                config_.key_password.clear();
                config_.key_password.shrink_to_fit();
            }

            if (key_load_result != 1) {
                return unexpected(ErrorCode::TLSKeyError,
                                 "Failed to load private key: " + get_ssl_error_string());
            }

            // Verify key matches certificate
            if (!SSL_CTX_check_private_key(ctx_.get())) {
                return unexpected(ErrorCode::TLSKeyError,
                                 "Private key doesn't match certificate");
            }
        }

        // Set cipher suites
        if (!config_.ciphers.empty()) {
            if (!SSL_CTX_set_cipher_list(ctx_.get(), config_.ciphers.c_str())) {
                return unexpected(ErrorCode::TLSProtocolError,
                                 "Invalid cipher list: " + get_ssl_error_string());
            }
        }

        if (!config_.ciphersuites.empty()) {
            if (!SSL_CTX_set_ciphersuites(ctx_.get(), config_.ciphersuites.c_str())) {
                return unexpected(ErrorCode::TLSProtocolError,
                                 "Invalid TLS 1.3 ciphersuites: " + get_ssl_error_string());
            }
        }

        // Session caching
        if (config_.enable_session_cache) {
            SSL_CTX_set_session_cache_mode(ctx_.get(),
                is_client_ ? SSL_SESS_CACHE_CLIENT : SSL_SESS_CACHE_SERVER);
            SSL_CTX_sess_set_cache_size(ctx_.get(), static_cast<long>(config_.session_cache_size));
        } else {
            SSL_CTX_set_session_cache_mode(ctx_.get(), SSL_SESS_CACHE_OFF);
        }

        // ALPN configuration
        if (!config_.alpn_protocols.empty()) {
            // Build wire format: length-prefixed strings
            std::vector<uint8_t> alpn_wire;
            for (const auto& proto : config_.alpn_protocols) {
                alpn_wire.push_back(static_cast<uint8_t>(proto.size()));
                alpn_wire.insert(alpn_wire.end(), proto.begin(), proto.end());
            }

            if (is_client_) {
                if (SSL_CTX_set_alpn_protos(ctx_.get(), alpn_wire.data(),
                                           static_cast<unsigned int>(alpn_wire.size())) != 0) {
                    return unexpected(ErrorCode::TLSProtocolError, "Failed to set ALPN protocols");
                }
            } else {
                // For server, set callback
                alpn_protocols_ = std::move(alpn_wire);
                SSL_CTX_set_alpn_select_cb(ctx_.get(), alpn_select_callback, this);
            }
        }

        // Enable options for security and performance
        SSL_CTX_set_options(ctx_.get(),
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_COMPRESSION |
            SSL_OP_SINGLE_DH_USE |
            SSL_OP_SINGLE_ECDH_USE);

        return {};
    }

    static int alpn_select_callback(SSL*, const unsigned char** out,
                                   unsigned char* outlen,
                                   const unsigned char* in, unsigned int inlen,
                                   void* arg) {
        auto* ctx = static_cast<TlsContext*>(arg);

        if (SSL_select_next_proto(
                const_cast<unsigned char**>(out), outlen,
                ctx->alpn_protocols_.data(),
                static_cast<unsigned int>(ctx->alpn_protocols_.size()),
                in, inlen) == OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }

        return SSL_TLSEXT_ERR_NOACK;
    }

    SslContextPtr ctx_;
    TlsContextConfig config_;
    bool is_client_ = true;
    std::vector<uint8_t> alpn_protocols_;
};

/// Post-handshake verification check.
///
/// SECURITY (CRITICAL #8): The hostname MUST be set on the SSL via
/// configure_hostname_verification() BEFORE the handshake starts. This function
/// only inspects the result of OpenSSL's built-in chain + hostname verification
/// that ran during the handshake. It does NOT (and cannot) re-run hostname
/// verification post-handshake, because by then the symmetric session keys have
/// already been derived from a potentially attacker-controlled certificate.
///
/// @param ssl       Connected SSL object (post-handshake)
/// @param hostname  Expected hostname (kept for diagnostic logging only)
/// @return true if peer cert presented AND chain+hostname verified during handshake
[[nodiscard]] inline bool verify_peer_post_handshake(SSL* ssl, std::string_view /*hostname*/) {
    // Peer must have presented a certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return false;
    X509Ptr cert_guard(cert);

    // Inspect the verification result that OpenSSL computed during handshake.
    // If X509_VERIFY_PARAM_set1_host was called pre-handshake, this also covers
    // hostname matching. If the verify_mode was None, this returns X509_V_OK
    // even for invalid certs — caller must enforce verify_mode separately.
    return SSL_get_verify_result(ssl) == X509_V_OK;
}

/// DEPRECATED: kept for ABI compatibility. Use verify_peer_post_handshake instead.
/// This function used to incorrectly call X509_VERIFY_PARAM_set1_host AFTER the
/// handshake, which had no effect on the already-completed verification.
[[nodiscard]] inline bool verify_hostname(SSL* ssl, std::string_view hostname) {
    return verify_peer_post_handshake(ssl, hostname);
}

/// Set SNI (Server Name Indication) on SSL connection
[[nodiscard]] inline bool set_sni(SSL* ssl, std::string_view hostname) {
    return SSL_set_tlsext_host_name(ssl, std::string(hostname).c_str()) == 1;
}

/// Configure SSL for hostname verification
[[nodiscard]] inline Expected<void> configure_hostname_verification(SSL* ssl, std::string_view hostname) {
    // Set SNI
    if (!set_sni(ssl, hostname)) {
        return unexpected(ErrorCode::TLSHandshakeFailed, "Failed to set SNI");
    }

    // Configure hostname verification parameter
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!X509_VERIFY_PARAM_set1_host(param, hostname.data(), hostname.size())) {
        return unexpected(ErrorCode::TLSHandshakeFailed, "Failed to set verification hostname");
    }

    return {};
}

}  // namespace signet
