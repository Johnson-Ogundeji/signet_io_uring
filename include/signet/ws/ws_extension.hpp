// Signet WebSocket Extension Framework
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0
//
// Modular extension system for WebSocket protocol extensions (RFC 6455 Section 9)

#ifndef SIGNET_WS_EXTENSION_HPP
#define SIGNET_WS_EXTENSION_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

#include "signet/core/error.hpp"

namespace signet {

// ═══════════════════════════════════════════════════════════════════════════
// Extension Parameter
// ═══════════════════════════════════════════════════════════════════════════

/// Single extension parameter (name with optional value)
struct ExtensionParam {
    std::string name;
    std::string value;  // Empty if parameter has no value

    [[nodiscard]] bool has_value() const noexcept {
        return !value.empty();
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Extension Offer/Response
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed extension offer from Sec-WebSocket-Extensions header
struct ExtensionOffer {
    std::string name;
    std::vector<ExtensionParam> params;

    /// Check if parameter exists
    [[nodiscard]] bool has_param(std::string_view param_name) const noexcept {
        return std::any_of(params.begin(), params.end(),
            [param_name](const auto& p) { return p.name == param_name; });
    }

    /// Get parameter value (empty if not present or no value)
    [[nodiscard]] std::string_view get_param(std::string_view param_name) const noexcept {
        auto it = std::find_if(params.begin(), params.end(),
            [param_name](const auto& p) { return p.name == param_name; });
        if (it != params.end()) {
            return it->value;
        }
        return {};
    }

    /// Get integer parameter value
    [[nodiscard]] std::optional<int> get_int_param(std::string_view param_name) const noexcept {
        auto val = get_param(param_name);
        if (val.empty()) return std::nullopt;

        int result = 0;
        for (char c : val) {
            if (c < '0' || c > '9') return std::nullopt;
            result = result * 10 + (c - '0');
        }
        return result;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Extension Interface
// ═══════════════════════════════════════════════════════════════════════════

/// Result of extension processing
struct ExtensionResult {
    std::vector<std::byte> data;
    bool rsv1{false};  // Extension may set RSV bits
    bool rsv2{false};
    bool rsv3{false};

    [[nodiscard]] static ExtensionResult success(std::vector<std::byte> data) {
        return ExtensionResult{std::move(data), false, false, false};
    }

    [[nodiscard]] static ExtensionResult with_rsv1(std::vector<std::byte> data) {
        return ExtensionResult{std::move(data), true, false, false};
    }
};

/// Base class for WebSocket extensions
class WsExtension {
public:
    virtual ~WsExtension() = default;

    /// Extension name (e.g., "permessage-deflate")
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /// Generate extension offer for handshake
    [[nodiscard]] virtual std::string generate_offer() const = 0;

    /// Configure extension from server response
    [[nodiscard]] virtual tl::expected<void, Error>
    configure(const ExtensionOffer& response) = 0;

    /// Process outgoing message (before framing)
    [[nodiscard]] virtual tl::expected<ExtensionResult, Error>
    process_outgoing(std::span<const std::byte> data, bool is_text) = 0;

    /// Process incoming message (after deframing)
    [[nodiscard]] virtual tl::expected<std::vector<std::byte>, Error>
    process_incoming(std::span<const std::byte> data, bool rsv1, bool is_text) = 0;

    /// Reset extension state (for new connection)
    virtual void reset() = 0;

    /// Check if extension uses RSV1 bit
    [[nodiscard]] virtual bool uses_rsv1() const noexcept { return false; }
    [[nodiscard]] virtual bool uses_rsv2() const noexcept { return false; }
    [[nodiscard]] virtual bool uses_rsv3() const noexcept { return false; }
};

// ═══════════════════════════════════════════════════════════════════════════
// Extension Parser
// ═══════════════════════════════════════════════════════════════════════════

/// Parse Sec-WebSocket-Extensions header value
[[nodiscard]] inline std::vector<ExtensionOffer>
parse_extension_header(std::string_view header) {
    std::vector<ExtensionOffer> offers;

    size_t pos = 0;
    while (pos < header.size()) {
        // Skip leading whitespace
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t')) {
            ++pos;
        }

        if (pos >= header.size()) break;

        // Find end of this extension (comma-separated)
        size_t ext_end = header.find(',', pos);
        if (ext_end == std::string_view::npos) {
            ext_end = header.size();
        }

        std::string_view ext_str = header.substr(pos, ext_end - pos);

        // Parse extension name and parameters
        ExtensionOffer offer;
        size_t param_pos = 0;

        // Find extension name
        while (param_pos < ext_str.size() &&
               ext_str[param_pos] != ';' &&
               ext_str[param_pos] != ' ' &&
               ext_str[param_pos] != '\t') {
            ++param_pos;
        }

        offer.name = std::string(ext_str.substr(0, param_pos));

        // Parse parameters (semicolon-separated)
        while (param_pos < ext_str.size()) {
            // Skip whitespace and semicolons
            while (param_pos < ext_str.size() &&
                   (ext_str[param_pos] == ';' ||
                    ext_str[param_pos] == ' ' ||
                    ext_str[param_pos] == '\t')) {
                ++param_pos;
            }

            if (param_pos >= ext_str.size()) break;

            // Find parameter name
            size_t name_end = param_pos;
            while (name_end < ext_str.size() &&
                   ext_str[name_end] != '=' &&
                   ext_str[name_end] != ';' &&
                   ext_str[name_end] != ' ' &&
                   ext_str[name_end] != '\t') {
                ++name_end;
            }

            ExtensionParam param;
            param.name = std::string(ext_str.substr(param_pos, name_end - param_pos));
            param_pos = name_end;

            // Check for value
            while (param_pos < ext_str.size() &&
                   (ext_str[param_pos] == ' ' || ext_str[param_pos] == '\t')) {
                ++param_pos;
            }

            if (param_pos < ext_str.size() && ext_str[param_pos] == '=') {
                ++param_pos;

                // Skip whitespace after =
                while (param_pos < ext_str.size() &&
                       (ext_str[param_pos] == ' ' || ext_str[param_pos] == '\t')) {
                    ++param_pos;
                }

                // Parse value (may be quoted)
                if (param_pos < ext_str.size()) {
                    if (ext_str[param_pos] == '"') {
                        // Quoted string
                        ++param_pos;
                        size_t value_end = ext_str.find('"', param_pos);
                        if (value_end != std::string_view::npos) {
                            param.value = std::string(ext_str.substr(param_pos, value_end - param_pos));
                            param_pos = value_end + 1;
                        }
                    } else {
                        // Unquoted token
                        size_t value_end = param_pos;
                        while (value_end < ext_str.size() &&
                               ext_str[value_end] != ';' &&
                               ext_str[value_end] != ' ' &&
                               ext_str[value_end] != '\t') {
                            ++value_end;
                        }
                        param.value = std::string(ext_str.substr(param_pos, value_end - param_pos));
                        param_pos = value_end;
                    }
                }
            }

            if (!param.name.empty()) {
                offer.params.push_back(std::move(param));
            }
        }

        if (!offer.name.empty()) {
            offers.push_back(std::move(offer));
        }

        pos = ext_end + 1;
    }

    return offers;
}

/// Format extension offer as header value
[[nodiscard]] inline std::string format_extension_header(const ExtensionOffer& offer) {
    std::string result = offer.name;

    for (const auto& param : offer.params) {
        result += "; ";
        result += param.name;
        if (param.has_value()) {
            result += "=";
            // Quote if needed
            bool needs_quote = param.value.find_first_of(" \t;,") != std::string::npos;
            if (needs_quote) {
                result += '"';
                result += param.value;
                result += '"';
            } else {
                result += param.value;
            }
        }
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// Extension Chain
// ═══════════════════════════════════════════════════════════════════════════

/// Chain of extensions for processing messages
class ExtensionChain {
public:
    /// Add extension to chain
    void add(std::unique_ptr<WsExtension> ext) {
        extensions_.push_back(std::move(ext));
    }

    /// Generate combined extension offer header
    [[nodiscard]] std::string generate_offer() const {
        std::string result;
        for (const auto& ext : extensions_) {
            if (!result.empty()) result += ", ";
            result += ext->generate_offer();
        }
        return result;
    }

    /// Configure all extensions from server response
    [[nodiscard]] tl::expected<void, Error>
    configure(std::string_view response_header) {
        auto offers = parse_extension_header(response_header);

        // Match each response to an extension
        for (const auto& offer : offers) {
            auto it = std::find_if(extensions_.begin(), extensions_.end(),
                [&offer](const auto& ext) { return ext->name() == offer.name; });

            if (it != extensions_.end()) {
                auto result = (*it)->configure(offer);
                if (!result) {
                    return tl::unexpected(result.error());
                }
            }
        }

        return {};
    }

    /// Process outgoing message through extension chain
    [[nodiscard]] tl::expected<ExtensionResult, Error>
    process_outgoing(std::span<const std::byte> data, bool is_text) {
        ExtensionResult result;
        result.data.assign(data.begin(), data.end());

        for (auto& ext : extensions_) {
            auto ext_result = ext->process_outgoing(
                std::span<const std::byte>(result.data), is_text);
            if (!ext_result) {
                return tl::unexpected(ext_result.error());
            }
            result = std::move(*ext_result);
        }

        return result;
    }

    /// Process incoming message through extension chain (reverse order)
    [[nodiscard]] tl::expected<std::vector<std::byte>, Error>
    process_incoming(std::span<const std::byte> data, bool rsv1, bool is_text) {
        std::vector<std::byte> result(data.begin(), data.end());

        for (auto it = extensions_.rbegin(); it != extensions_.rend(); ++it) {
            auto ext_result = (*it)->process_incoming(
                std::span<const std::byte>(result), rsv1, is_text);
            if (!ext_result) {
                return tl::unexpected(ext_result.error());
            }
            result = std::move(*ext_result);
        }

        return result;
    }

    /// Check if any extension uses RSV1
    [[nodiscard]] bool uses_rsv1() const noexcept {
        return std::any_of(extensions_.begin(), extensions_.end(),
            [](const auto& ext) { return ext->uses_rsv1(); });
    }

    /// Check if any extension uses RSV2
    [[nodiscard]] bool uses_rsv2() const noexcept {
        return std::any_of(extensions_.begin(), extensions_.end(),
            [](const auto& ext) { return ext->uses_rsv2(); });
    }

    /// Check if any extension uses RSV3
    [[nodiscard]] bool uses_rsv3() const noexcept {
        return std::any_of(extensions_.begin(), extensions_.end(),
            [](const auto& ext) { return ext->uses_rsv3(); });
    }

    /// Reset all extensions
    void reset() {
        for (auto& ext : extensions_) {
            ext->reset();
        }
    }

    /// Check if chain has any extensions
    [[nodiscard]] bool empty() const noexcept {
        return extensions_.empty();
    }

    /// Get number of extensions
    [[nodiscard]] size_t size() const noexcept {
        return extensions_.size();
    }

private:
    std::vector<std::unique_ptr<WsExtension>> extensions_;
};

// ═══════════════════════════════════════════════════════════════════════════
// No-op Extension (for testing)
// ═══════════════════════════════════════════════════════════════════════════

/// Null extension that passes data through unchanged
class NoopExtension : public WsExtension {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "x-noop";
    }

    [[nodiscard]] std::string generate_offer() const override {
        return "x-noop";
    }

    [[nodiscard]] tl::expected<void, Error>
    configure(const ExtensionOffer& /*response*/) override {
        return {};
    }

    [[nodiscard]] tl::expected<ExtensionResult, Error>
    process_outgoing(std::span<const std::byte> data, bool /*is_text*/) override {
        return ExtensionResult::success(
            std::vector<std::byte>(data.begin(), data.end()));
    }

    [[nodiscard]] tl::expected<std::vector<std::byte>, Error>
    process_incoming(std::span<const std::byte> data, bool /*rsv1*/, bool /*is_text*/) override {
        return std::vector<std::byte>(data.begin(), data.end());
    }

    void reset() override {}
};

}  // namespace signet

#endif  // SIGNET_WS_EXTENSION_HPP
