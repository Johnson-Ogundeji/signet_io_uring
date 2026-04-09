// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/net/address.hpp"

#include <netdb.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace signet {

/// Metric names for resolver operations
namespace metrics {
    constexpr const char* kDnsResolve = "dns.resolve";
    constexpr const char* kDnsCacheHit = "dns.cache_hit";
    constexpr const char* kDnsCacheMiss = "dns.cache_miss";
}  // namespace metrics

/// DNS resolver result
struct ResolveResult {
    std::string hostname;
    std::string service;
    std::vector<Endpoint> endpoints;

    [[nodiscard]] bool empty() const noexcept { return endpoints.empty(); }
    [[nodiscard]] size_t size() const noexcept { return endpoints.size(); }

    /// Get first IPv4 endpoint (or first endpoint if no v4)
    [[nodiscard]] std::optional<Endpoint> first_v4() const {
        for (const auto& ep : endpoints) {
            if (ep.is_v4()) return ep;
        }
        return std::nullopt;
    }

    /// Get first IPv6 endpoint (or first endpoint if no v6)
    [[nodiscard]] std::optional<Endpoint> first_v6() const {
        for (const auto& ep : endpoints) {
            if (ep.is_v6()) return ep;
        }
        return std::nullopt;
    }

    /// Get first endpoint (any family)
    [[nodiscard]] std::optional<Endpoint> first() const {
        if (endpoints.empty()) return std::nullopt;
        return endpoints.front();
    }
};

/// DNS resolver options
struct ResolverOptions {
    bool prefer_ipv4 = true;           // Prefer IPv4 addresses
    bool allow_ipv6 = true;            // Include IPv6 addresses
    bool use_cache = true;             // Use DNS cache
    int timeout_ms = 5000;             // Resolution timeout
    int max_entries = 100;             // Max endpoints to return
};

/// Simple DNS cache entry
struct DnsCacheEntry {
    ResolveResult result;
    std::chrono::steady_clock::time_point expires;
};

/// DNS resolver with caching
class Resolver {
public:
    explicit Resolver(ResolverOptions options = {})
        : options_(std::move(options)) {}

    /// Resolve hostname to endpoints
    [[nodiscard]] Expected<ResolveResult> resolve(
        std::string_view hostname,
        std::string_view service = "",
        uint16_t port = 0) {

        SIGNET_TIMER_SCOPE(metrics::kDnsResolve);

        std::string host_str{hostname};
        std::string service_str;

        // Use port if service not specified
        if (service.empty() && port > 0) {
            service_str = std::to_string(port);
        } else {
            service_str = std::string{service};
        }

        // Check cache first
        if (options_.use_cache) {
            auto cache_key = host_str + ":" + service_str;
            auto it = cache_.find(cache_key);
            if (it != cache_.end() && it->second.expires > std::chrono::steady_clock::now()) {
                SIGNET_COUNTER_INC(metrics::kDnsCacheHit);
                return it->second.result;
            }
            SIGNET_COUNTER_INC(metrics::kDnsCacheMiss);
        }

        // Setup hints
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (!options_.allow_ipv6) {
            hints.ai_family = AF_INET;
        }

        // Perform resolution
        addrinfo* result_raw = nullptr;
        int ret = getaddrinfo(host_str.c_str(),
                             service_str.empty() ? nullptr : service_str.c_str(),
                             &hints, &result_raw);

        if (ret != 0) {
            return unexpected(ErrorCode::DnsResolutionFailed,
                            gai_strerror(ret));
        }

        // RAII cleanup
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> result{result_raw, freeaddrinfo};

        // Build result
        ResolveResult resolve_result;
        resolve_result.hostname = host_str;
        resolve_result.service = service_str;

        int count = 0;
        for (addrinfo* rp = result.get(); rp != nullptr && count < options_.max_entries; rp = rp->ai_next) {
            Endpoint ep = Endpoint::from_sockaddr(rp->ai_addr);

            // Apply port if needed
            if (port > 0 && ep.port() == 0) {
                if (ep.is_v4()) {
                    ep = Endpoint{ep.address().to_v4(), port};
                } else {
                    ep = Endpoint{ep.address().to_v6(), port};
                }
            }

            resolve_result.endpoints.push_back(ep);
            ++count;
        }

        // Sort by preference (IPv4 first if preferred)
        if (options_.prefer_ipv4) {
            std::stable_partition(resolve_result.endpoints.begin(),
                                 resolve_result.endpoints.end(),
                                 [](const Endpoint& ep) { return ep.is_v4(); });
        }

        // Cache result
        if (options_.use_cache && !resolve_result.empty()) {
            auto cache_key = host_str + ":" + service_str;
            cache_[cache_key] = DnsCacheEntry{
                resolve_result,
                std::chrono::steady_clock::now() + std::chrono::minutes(5)
            };
        }

        return resolve_result;
    }

    /// Resolve hostname and port to single best endpoint
    [[nodiscard]] Expected<Endpoint> resolve_one(
        std::string_view hostname,
        uint16_t port) {

        auto result = resolve(hostname, "", port);
        if (!result) {
            return unexpected(result.error());
        }

        if (result->empty()) {
            return unexpected(ErrorCode::DnsResolutionFailed,
                            "No addresses found for " + std::string(hostname));
        }

        // Return preferred endpoint
        if (options_.prefer_ipv4) {
            if (auto ep = result->first_v4()) return *ep;
        }
        return *result->first();
    }

    /// Clear DNS cache
    void clear_cache() {
        cache_.clear();
    }

    /// Get cache size
    [[nodiscard]] size_t cache_size() const noexcept {
        return cache_.size();
    }

    /// Remove expired cache entries
    void prune_cache() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = cache_.begin(); it != cache_.end();) {
            if (it->second.expires <= now) {
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    ResolverOptions options_;
    std::unordered_map<std::string, DnsCacheEntry> cache_;
};

/// Parse URL-like string to get hostname and port
/// Supports formats: "host:port", "host", "https://host:port/path"
struct ParsedUrl {
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;
    bool is_secure = false;

    [[nodiscard]] static Expected<ParsedUrl> parse(std::string_view url) {
        ParsedUrl result;

        std::string_view remaining = url;

        // Check for scheme
        auto scheme_end = remaining.find("://");
        if (scheme_end != std::string_view::npos) {
            result.scheme = std::string{remaining.substr(0, scheme_end)};
            remaining = remaining.substr(scheme_end + 3);

            // Determine if secure based on scheme
            if (result.scheme == "https" || result.scheme == "wss") {
                result.is_secure = true;
                result.port = 443;  // Default
            } else if (result.scheme == "http" || result.scheme == "ws") {
                result.is_secure = false;
                result.port = 80;  // Default
            }
        }

        // Find path start
        auto path_start = remaining.find('/');
        std::string_view host_port;
        if (path_start != std::string_view::npos) {
            result.path = std::string{remaining.substr(path_start)};
            host_port = remaining.substr(0, path_start);
        } else {
            result.path = "/";
            host_port = remaining;
        }

        // Parse host and port
        // Handle IPv6 addresses like [::1]:8080
        if (!host_port.empty() && host_port[0] == '[') {
            auto bracket_end = host_port.find(']');
            if (bracket_end == std::string_view::npos) {
                return unexpected(ErrorCode::InvalidArgument, "Invalid IPv6 address");
            }
            result.host = std::string{host_port.substr(1, bracket_end - 1)};

            if (bracket_end + 1 < host_port.size() && host_port[bracket_end + 1] == ':') {
                auto port_str = host_port.substr(bracket_end + 2);
                result.port = static_cast<uint16_t>(std::stoul(std::string{port_str}));
            }
        } else {
            auto colon = host_port.rfind(':');
            if (colon != std::string_view::npos) {
                result.host = std::string{host_port.substr(0, colon)};
                auto port_str = host_port.substr(colon + 1);
                result.port = static_cast<uint16_t>(std::stoul(std::string{port_str}));
            } else {
                result.host = std::string{host_port};
            }
        }

        if (result.host.empty()) {
            return unexpected(ErrorCode::InvalidArgument, "Empty hostname");
        }

        return result;
    }
};

}  // namespace signet
