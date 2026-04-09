// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace signet {

/// IPv4 address wrapper
class IPv4Address {
public:
    IPv4Address() noexcept : addr_{} { addr_.s_addr = INADDR_ANY; }

    explicit IPv4Address(uint32_t addr) noexcept : addr_{} {
        addr_.s_addr = htonl(addr);
    }

    explicit IPv4Address(in_addr addr) noexcept : addr_(addr) {}

    static IPv4Address any() noexcept { return IPv4Address{}; }
    static IPv4Address loopback() noexcept { return IPv4Address{INADDR_LOOPBACK}; }

    /// Parse from string (e.g., "192.168.1.1")
    static std::optional<IPv4Address> from_string(std::string_view str) {
        in_addr addr{};
        std::string null_terminated{str};
        if (inet_pton(AF_INET, null_terminated.c_str(), &addr) == 1) {
            return IPv4Address{addr};
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string to_string() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_, buf, sizeof(buf));
        return std::string{buf};
    }

    [[nodiscard]] in_addr native() const noexcept { return addr_; }
    [[nodiscard]] uint32_t to_uint() const noexcept { return ntohl(addr_.s_addr); }

    bool operator==(const IPv4Address& other) const noexcept {
        return addr_.s_addr == other.addr_.s_addr;
    }

private:
    in_addr addr_;
};

/// IPv6 address wrapper
class IPv6Address {
public:
    IPv6Address() noexcept : addr_{} {}

    explicit IPv6Address(in6_addr addr) noexcept : addr_(addr) {}

    static IPv6Address any() noexcept {
        IPv6Address a;
        a.addr_ = in6addr_any;
        return a;
    }

    static IPv6Address loopback() noexcept {
        IPv6Address a;
        a.addr_ = in6addr_loopback;
        return a;
    }

    /// Parse from string (e.g., "::1" or "2001:db8::1")
    static std::optional<IPv6Address> from_string(std::string_view str) {
        in6_addr addr{};
        std::string null_terminated{str};
        if (inet_pton(AF_INET6, null_terminated.c_str(), &addr) == 1) {
            return IPv6Address{addr};
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string to_string() const {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_, buf, sizeof(buf));
        return std::string{buf};
    }

    [[nodiscard]] in6_addr native() const noexcept { return addr_; }

    bool operator==(const IPv6Address& other) const noexcept {
        return std::memcmp(&addr_, &other.addr_, sizeof(in6_addr)) == 0;
    }

private:
    in6_addr addr_;
};

/// IP address (either v4 or v6)
class IpAddress {
public:
    IpAddress() : addr_(IPv4Address::any()) {}
    IpAddress(IPv4Address addr) : addr_(addr) {}  // NOLINT(google-explicit-constructor)
    IpAddress(IPv6Address addr) : addr_(addr) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool is_v4() const noexcept {
        return std::holds_alternative<IPv4Address>(addr_);
    }

    [[nodiscard]] bool is_v6() const noexcept {
        return std::holds_alternative<IPv6Address>(addr_);
    }

    [[nodiscard]] const IPv4Address& to_v4() const {
        return std::get<IPv4Address>(addr_);
    }

    [[nodiscard]] const IPv6Address& to_v6() const {
        return std::get<IPv6Address>(addr_);
    }

    [[nodiscard]] std::string to_string() const {
        if (is_v4()) {
            return std::get<IPv4Address>(addr_).to_string();
        }
        return std::get<IPv6Address>(addr_).to_string();
    }

    /// Parse from string (auto-detects v4 vs v6)
    static std::optional<IpAddress> from_string(std::string_view str) {
        // Try IPv4 first
        if (auto v4 = IPv4Address::from_string(str)) {
            return IpAddress{*v4};
        }
        // Try IPv6
        if (auto v6 = IPv6Address::from_string(str)) {
            return IpAddress{*v6};
        }
        return std::nullopt;
    }

    bool operator==(const IpAddress& other) const noexcept {
        return addr_ == other.addr_;
    }

private:
    std::variant<IPv4Address, IPv6Address> addr_;
};

/// Network endpoint (IP address + port)
class Endpoint {
public:
    Endpoint() noexcept : addr_(), port_(0) {}

    Endpoint(IpAddress addr, uint16_t port) noexcept
        : addr_(addr), port_(port) {}

    Endpoint(IPv4Address addr, uint16_t port) noexcept
        : addr_(addr), port_(port) {}

    Endpoint(IPv6Address addr, uint16_t port) noexcept
        : addr_(addr), port_(port) {}

    /// Create from sockaddr
    static Endpoint from_sockaddr(const sockaddr* sa) {
        if (sa->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
            return Endpoint{IPv4Address{sin->sin_addr}, ntohs(sin->sin_port)};
        } else if (sa->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
            return Endpoint{IPv6Address{sin6->sin6_addr}, ntohs(sin6->sin6_port)};
        }
        return Endpoint{};
    }

    [[nodiscard]] const IpAddress& address() const noexcept { return addr_; }
    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    [[nodiscard]] bool is_v4() const noexcept { return addr_.is_v4(); }
    [[nodiscard]] bool is_v6() const noexcept { return addr_.is_v6(); }

    [[nodiscard]] std::string to_string() const {
        if (is_v6()) {
            return "[" + addr_.to_string() + "]:" + std::to_string(port_);
        }
        return addr_.to_string() + ":" + std::to_string(port_);
    }

    /// Fill sockaddr structure
    void to_sockaddr(sockaddr_storage* storage, socklen_t* len) const {
        std::memset(storage, 0, sizeof(sockaddr_storage));

        if (addr_.is_v4()) {
            auto* sin = reinterpret_cast<sockaddr_in*>(storage);
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port_);
            sin->sin_addr = addr_.to_v4().native();
            *len = sizeof(sockaddr_in);
        } else {
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(storage);
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port_);
            sin6->sin6_addr = addr_.to_v6().native();
            *len = sizeof(sockaddr_in6);
        }
    }

    /// Get address family
    [[nodiscard]] int family() const noexcept {
        return addr_.is_v4() ? AF_INET : AF_INET6;
    }

    bool operator==(const Endpoint& other) const noexcept {
        return addr_ == other.addr_ && port_ == other.port_;
    }

private:
    IpAddress addr_;
    uint16_t port_;
};

}  // namespace signet
