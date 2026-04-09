// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file ws_handshake.hpp
/// @brief WebSocket HTTP upgrade handshake (RFC 6455 Section 4)
///
/// The opening handshake is designed to be compatible with HTTP-based
/// server-side software and intermediaries, so that a single port can
/// be used by both HTTP clients talking to that server and WebSocket
/// clients talking to that server.

#pragma once

#include "signet/ws/ws_types.hpp"
#include "signet/core/error.hpp"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace signet {

// ============================================================================
// Handshake Key Generation/Validation
// ============================================================================

/// Generate a random 16-byte key, base64 encoded (24 chars)
/// Uses OpenSSL's RAND_bytes for robust cross-platform randomness
[[nodiscard]] inline std::string generate_websocket_key() {
    // Generate 16 random bytes using OpenSSL (robust across all platforms)
    std::array<uint8_t, 16> random_bytes;
    RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size()));

    // Base64 encode: 16 bytes = 5 full triplets (15 bytes) + 1 remaining byte
    // Output: 5*4 + 2 chars + 2 padding = 24 chars
    static constexpr char kBase64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(24);

    // Process 5 complete triplets (15 bytes)
    for (size_t i = 0; i < 15; i += 3) {
        uint32_t triple = (static_cast<uint32_t>(random_bytes[i]) << 16) |
                          (static_cast<uint32_t>(random_bytes[i + 1]) << 8) |
                          static_cast<uint32_t>(random_bytes[i + 2]);
        result += kBase64Chars[(triple >> 18) & 0x3F];
        result += kBase64Chars[(triple >> 12) & 0x3F];
        result += kBase64Chars[(triple >> 6) & 0x3F];
        result += kBase64Chars[triple & 0x3F];
    }

    // Handle last byte with padding (index 15)
    uint32_t last = static_cast<uint32_t>(random_bytes[15]) << 16;
    result += kBase64Chars[(last >> 18) & 0x3F];
    result += kBase64Chars[(last >> 12) & 0x3F];
    result += '=';
    result += '=';

    return result;
}

/// Compute the expected Sec-WebSocket-Accept value
/// @param client_key The Sec-WebSocket-Key sent by client
/// @return Base64-encoded SHA-1 hash of (key + GUID)
[[nodiscard]] inline std::string compute_accept_key(std::string_view client_key) {
    // Concatenate key with magic GUID
    std::string concat;
    concat.reserve(client_key.size() + ws_constants::kWebSocketGuid.size());
    concat.append(client_key);
    concat.append(ws_constants::kWebSocketGuid);

    // Compute SHA-1 hash
    std::array<uint8_t, SHA_DIGEST_LENGTH> hash;
    SHA1(reinterpret_cast<const uint8_t*>(concat.data()), concat.size(), hash.data());

    // Base64 encode the hash
    static constexpr char kBase64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(28);

    for (size_t i = 0; i < 18; i += 3) {
        uint32_t triple = (static_cast<uint32_t>(hash[i]) << 16) |
                          (static_cast<uint32_t>(hash[i + 1]) << 8) |
                          static_cast<uint32_t>(hash[i + 2]);
        result += kBase64Chars[(triple >> 18) & 0x3F];
        result += kBase64Chars[(triple >> 12) & 0x3F];
        result += kBase64Chars[(triple >> 6) & 0x3F];
        result += kBase64Chars[triple & 0x3F];
    }

    // Last 2 bytes
    uint32_t last = (static_cast<uint32_t>(hash[18]) << 16) |
                    (static_cast<uint32_t>(hash[19]) << 8);
    result += kBase64Chars[(last >> 18) & 0x3F];
    result += kBase64Chars[(last >> 12) & 0x3F];
    result += kBase64Chars[(last >> 6) & 0x3F];
    result += '=';

    return result;
}

// ============================================================================
// HTTP Header Parsing
// ============================================================================

/// Parsed HTTP headers (case-insensitive)
class HttpHeaders {
public:
    HttpHeaders() = default;

    /// Add a header (key is lowercased for case-insensitive lookup)
    void add(std::string_view key, std::string_view value) {
        std::string lower_key;
        lower_key.reserve(key.size());
        for (char c : key) {
            lower_key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        headers_[std::move(lower_key)] = std::string(value);
    }

    /// Get header value (case-insensitive)
    [[nodiscard]] std::optional<std::string_view> get(std::string_view key) const {
        std::string lower_key;
        lower_key.reserve(key.size());
        for (char c : key) {
            lower_key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        auto it = headers_.find(lower_key);
        if (it != headers_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /// Check if header contains a value (comma-separated, case-insensitive)
    [[nodiscard]] bool contains_value(std::string_view key, std::string_view value) const {
        auto header = get(key);
        if (!header) return false;

        // Parse comma-separated values
        std::string lower_value;
        lower_value.reserve(value.size());
        for (char c : value) {
            lower_value += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        size_t pos = 0;
        while (pos < header->size()) {
            // Skip whitespace
            while (pos < header->size() && std::isspace(static_cast<unsigned char>((*header)[pos]))) {
                ++pos;
            }

            // Find end of value (comma or end of string)
            size_t end = header->find(',', pos);
            if (end == std::string_view::npos) {
                end = header->size();
            }

            // Trim trailing whitespace
            size_t val_end = end;
            while (val_end > pos && std::isspace(static_cast<unsigned char>((*header)[val_end - 1]))) {
                --val_end;
            }

            // Compare value (case-insensitive)
            std::string_view current = header->substr(pos, val_end - pos);
            if (current.size() == lower_value.size()) {
                bool match = true;
                for (size_t i = 0; i < current.size(); ++i) {
                    if (std::tolower(static_cast<unsigned char>(current[i])) !=
                        lower_value[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }

            pos = (end < header->size()) ? end + 1 : end;
        }

        return false;
    }

    /// Clear all headers
    void clear() { headers_.clear(); }

    /// Get number of headers
    [[nodiscard]] size_t size() const { return headers_.size(); }

private:
    std::unordered_map<std::string, std::string> headers_;
};

/// HTTP response parse result
struct HttpResponse {
    int status_code = 0;
    std::string status_text;
    HttpHeaders headers;
    size_t header_end = 0;  // Offset to end of headers (start of body)
    bool complete = false;
};

/// Parse HTTP response headers
/// @param data Input buffer
/// @return Parsed response (complete=false if need more data)
[[nodiscard]] inline HttpResponse parse_http_response(std::span<const std::byte> data) {
    HttpResponse response;
    std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());

    // Find end of headers
    size_t header_end = text.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return response;  // Need more data
    }
    response.header_end = header_end + 4;

    // Parse status line: HTTP/1.1 101 Switching Protocols
    size_t line_end = text.find("\r\n");
    std::string_view status_line = text.substr(0, line_end);

    // Find HTTP version
    if (!status_line.starts_with("HTTP/")) {
        return response;  // Invalid
    }

    // Find status code
    size_t space1 = status_line.find(' ');
    if (space1 == std::string_view::npos) return response;

    size_t space2 = status_line.find(' ', space1 + 1);
    std::string_view code_str = status_line.substr(space1 + 1,
        (space2 != std::string_view::npos) ? space2 - space1 - 1 : std::string_view::npos);

    auto [ptr, ec] = std::from_chars(code_str.data(), code_str.data() + code_str.size(),
                                     response.status_code);
    if (ec != std::errc()) return response;

    if (space2 != std::string_view::npos) {
        response.status_text = std::string(status_line.substr(space2 + 1));
    }

    // Parse headers
    size_t pos = line_end + 2;  // Skip first \r\n
    while (pos < header_end) {
        size_t next_line = text.find("\r\n", pos);
        if (next_line == std::string_view::npos || next_line > header_end) {
            break;
        }

        std::string_view line = text.substr(pos, next_line - pos);
        size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string_view key = line.substr(0, colon);
            std::string_view value = line.substr(colon + 1);

            // Trim leading whitespace from value
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value[0]))) {
                value.remove_prefix(1);
            }
            // Trim trailing whitespace from value
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
                value.remove_suffix(1);
            }

            response.headers.add(key, value);
        }

        pos = next_line + 2;
    }

    response.complete = true;
    return response;
}

// ============================================================================
// Handshake Request Builder
// ============================================================================

/// WebSocket handshake configuration
struct WsHandshakeConfig {
    std::string host;
    std::string path = "/";
    uint16_t port = 443;
    std::vector<std::string> subprotocols;
    std::vector<std::string> extensions;
    std::string origin;
    std::unordered_map<std::string, std::string> extra_headers;
};

/// Build WebSocket upgrade request
/// @param config Handshake configuration
/// @param key The generated Sec-WebSocket-Key
/// @return HTTP upgrade request string
[[nodiscard]] inline std::string build_handshake_request(
    const WsHandshakeConfig& config,
    std::string_view key
) {
    std::string request;
    request.reserve(512);

    // Request line
    request += "GET ";
    request += config.path.empty() ? "/" : config.path;
    request += " HTTP/1.1\r\n";

    // Required headers
    request += "Host: ";
    request += config.host;
    if (config.port != 80 && config.port != 443) {
        request += ":";
        request += std::to_string(config.port);
    }
    request += "\r\n";

    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: ";
    request += key;
    request += "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n";

    // Optional headers
    if (!config.origin.empty()) {
        request += "Origin: ";
        request += config.origin;
        request += "\r\n";
    }

    if (!config.subprotocols.empty()) {
        request += "Sec-WebSocket-Protocol: ";
        for (size_t i = 0; i < config.subprotocols.size(); ++i) {
            if (i > 0) request += ", ";
            request += config.subprotocols[i];
        }
        request += "\r\n";
    }

    if (!config.extensions.empty()) {
        request += "Sec-WebSocket-Extensions: ";
        for (size_t i = 0; i < config.extensions.size(); ++i) {
            if (i > 0) request += ", ";
            request += config.extensions[i];
        }
        request += "\r\n";
    }

    // Extra headers
    for (const auto& [key_hdr, value] : config.extra_headers) {
        request += key_hdr;
        request += ": ";
        request += value;
        request += "\r\n";
    }

    // End of headers
    request += "\r\n";

    return request;
}

// ============================================================================
// Handshake Response Validation
// ============================================================================

/// Handshake validation result
enum class HandshakeResult {
    Success,
    NotHttp101,
    MissingUpgrade,
    InvalidUpgrade,
    MissingConnection,
    InvalidConnection,
    MissingAccept,
    InvalidAccept,
    UnsupportedProtocol,
    UnsupportedExtension,
};

/// Get handshake result description
[[nodiscard]] constexpr std::string_view handshake_result_description(HandshakeResult result) noexcept {
    switch (result) {
        case HandshakeResult::Success: return "Success";
        case HandshakeResult::NotHttp101: return "Server did not return HTTP 101";
        case HandshakeResult::MissingUpgrade: return "Missing Upgrade header";
        case HandshakeResult::InvalidUpgrade: return "Upgrade header not 'websocket'";
        case HandshakeResult::MissingConnection: return "Missing Connection header";
        case HandshakeResult::InvalidConnection: return "Connection header doesn't contain 'Upgrade'";
        case HandshakeResult::MissingAccept: return "Missing Sec-WebSocket-Accept header";
        case HandshakeResult::InvalidAccept: return "Sec-WebSocket-Accept value doesn't match";
        case HandshakeResult::UnsupportedProtocol: return "Server selected unsupported subprotocol";
        case HandshakeResult::UnsupportedExtension: return "Server selected unsupported extension";
        default: return "Unknown";
    }
}

/// Validate WebSocket handshake response
/// @param response Parsed HTTP response
/// @param client_key The Sec-WebSocket-Key we sent
/// @param offered_protocols Subprotocols we offered
/// @param offered_extensions Extensions we offered
/// @return Validation result
[[nodiscard]] inline HandshakeResult validate_handshake_response(
    const HttpResponse& response,
    std::string_view client_key,
    const std::vector<std::string>& offered_protocols = {},
    const std::vector<std::string>& offered_extensions = {}
) {
    // Must be HTTP 101 Switching Protocols
    if (response.status_code != 101) {
        return HandshakeResult::NotHttp101;
    }

    // Must have Upgrade: websocket
    auto upgrade = response.headers.get("upgrade");
    if (!upgrade) {
        return HandshakeResult::MissingUpgrade;
    }
    // Case-insensitive comparison
    std::string lower_upgrade;
    for (char c : *upgrade) {
        lower_upgrade += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (lower_upgrade != "websocket") {
        return HandshakeResult::InvalidUpgrade;
    }

    // Must have Connection: Upgrade
    auto connection = response.headers.get("connection");
    if (!connection) {
        return HandshakeResult::MissingConnection;
    }
    if (!response.headers.contains_value("connection", "upgrade")) {
        return HandshakeResult::InvalidConnection;
    }

    // Must have valid Sec-WebSocket-Accept
    auto accept = response.headers.get("sec-websocket-accept");
    if (!accept) {
        return HandshakeResult::MissingAccept;
    }
    std::string expected = compute_accept_key(client_key);
    if (*accept != expected) {
        return HandshakeResult::InvalidAccept;
    }

    // Validate subprotocol (if any)
    auto protocol = response.headers.get("sec-websocket-protocol");
    if (protocol) {
        bool found = false;
        for (const auto& offered : offered_protocols) {
            if (*protocol == offered) {
                found = true;
                break;
            }
        }
        if (!found && !offered_protocols.empty()) {
            return HandshakeResult::UnsupportedProtocol;
        }
    }

    // Validate extensions (if any)
    auto extensions = response.headers.get("sec-websocket-extensions");
    if (extensions && !extensions->empty()) {
        // Basic check - server shouldn't send extensions we didn't offer
        // Full validation would need to parse extension parameters
        if (offered_extensions.empty()) {
            return HandshakeResult::UnsupportedExtension;
        }
    }

    return HandshakeResult::Success;
}

/// Handshake state machine for incremental processing
class WsHandshake {
public:
    WsHandshake() = default;

    /// Initialize handshake with configuration
    void init(WsHandshakeConfig config) {
        config_ = std::move(config);
        key_ = generate_websocket_key();
        request_ = build_handshake_request(config_, key_);
        state_ = State::SendingRequest;
    }

    /// Get the handshake request to send
    [[nodiscard]] std::string_view request() const { return request_; }

    /// Get the generated key (for response validation)
    [[nodiscard]] std::string_view key() const { return key_; }

    /// Feed response data
    /// @return true if handshake complete (check result())
    [[nodiscard]] bool feed(std::span<const std::byte> data) {
        if (state_ != State::ReceivingResponse) {
            return false;
        }

        // Append to buffer
        response_buffer_.insert(response_buffer_.end(),
            reinterpret_cast<const char*>(data.data()),
            reinterpret_cast<const char*>(data.data()) + data.size());

        // Try to parse
        auto response = parse_http_response({
            reinterpret_cast<const std::byte*>(response_buffer_.data()),
            response_buffer_.size()
        });

        if (!response.complete) {
            return false;  // Need more data
        }

        // Validate handshake
        result_ = validate_handshake_response(response, key_,
            config_.subprotocols, config_.extensions);

        // Extract selected protocol/extensions
        if (result_ == HandshakeResult::Success) {
            if (auto proto = response.headers.get("sec-websocket-protocol")) {
                selected_protocol_ = std::string(*proto);
            }
            if (auto ext = response.headers.get("sec-websocket-extensions")) {
                selected_extensions_ = std::string(*ext);
            }
        }

        // Calculate any remaining data after headers
        remaining_data_offset_ = response.header_end;
        state_ = State::Complete;
        return true;
    }

    /// Mark request as sent, ready to receive response
    void request_sent() {
        state_ = State::ReceivingResponse;
    }

    /// Get handshake result (valid after complete)
    [[nodiscard]] HandshakeResult result() const { return result_; }

    /// Check if handshake succeeded
    [[nodiscard]] bool success() const { return result_ == HandshakeResult::Success; }

    /// Get selected subprotocol
    [[nodiscard]] std::string_view selected_protocol() const { return selected_protocol_; }

    /// Get selected extensions
    [[nodiscard]] std::string_view selected_extensions() const { return selected_extensions_; }

    /// Get any data after HTTP headers (beginning of WebSocket frames)
    [[nodiscard]] std::span<const std::byte> remaining_data() const {
        if (remaining_data_offset_ >= response_buffer_.size()) {
            return {};
        }
        return {
            reinterpret_cast<const std::byte*>(response_buffer_.data() + remaining_data_offset_),
            response_buffer_.size() - remaining_data_offset_
        };
    }

    /// Check if complete
    [[nodiscard]] bool complete() const { return state_ == State::Complete; }

private:
    enum class State {
        Idle,
        SendingRequest,
        ReceivingResponse,
        Complete,
    };

    WsHandshakeConfig config_;
    std::string key_;
    std::string request_;
    std::string response_buffer_;
    State state_ = State::Idle;
    HandshakeResult result_ = HandshakeResult::Success;
    std::string selected_protocol_;
    std::string selected_extensions_;
    size_t remaining_data_offset_ = 0;
};

}  // namespace signet
