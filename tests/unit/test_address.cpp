// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <signet/net/address.hpp>
#include <gtest/gtest.h>

using namespace signet;

class AddressTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ═══════════════════════════════════════════════════════════════════════════
// IPv4Address Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(AddressTest, IPv4_Default_IsAny) {
    IPv4Address addr;
    EXPECT_EQ(addr.to_string(), "0.0.0.0");
}

TEST_F(AddressTest, IPv4_Any) {
    auto addr = IPv4Address::any();
    EXPECT_EQ(addr.to_string(), "0.0.0.0");
}

TEST_F(AddressTest, IPv4_Loopback) {
    auto addr = IPv4Address::loopback();
    EXPECT_EQ(addr.to_string(), "127.0.0.1");
}

TEST_F(AddressTest, IPv4_FromString_Valid) {
    auto addr = IPv4Address::from_string("192.168.1.1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->to_string(), "192.168.1.1");
}

TEST_F(AddressTest, IPv4_FromString_Invalid) {
    auto addr = IPv4Address::from_string("not.an.ip.address");
    EXPECT_FALSE(addr.has_value());
}

TEST_F(AddressTest, IPv4_FromString_InvalidFormat) {
    auto addr = IPv4Address::from_string("256.1.1.1");
    EXPECT_FALSE(addr.has_value());
}

TEST_F(AddressTest, IPv4_Equality) {
    auto addr1 = IPv4Address::from_string("10.0.0.1");
    auto addr2 = IPv4Address::from_string("10.0.0.1");
    auto addr3 = IPv4Address::from_string("10.0.0.2");

    ASSERT_TRUE(addr1.has_value());
    ASSERT_TRUE(addr2.has_value());
    ASSERT_TRUE(addr3.has_value());

    EXPECT_EQ(*addr1, *addr2);
    EXPECT_NE(*addr1, *addr3);
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv6Address Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(AddressTest, IPv6_Any) {
    auto addr = IPv6Address::any();
    EXPECT_EQ(addr.to_string(), "::");
}

TEST_F(AddressTest, IPv6_Loopback) {
    auto addr = IPv6Address::loopback();
    EXPECT_EQ(addr.to_string(), "::1");
}

TEST_F(AddressTest, IPv6_FromString_Valid) {
    auto addr = IPv6Address::from_string("2001:db8::1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->to_string(), "2001:db8::1");
}

TEST_F(AddressTest, IPv6_FromString_FullFormat) {
    auto addr = IPv6Address::from_string("2001:0db8:0000:0000:0000:0000:0000:0001");
    ASSERT_TRUE(addr.has_value());
    // Output should be compressed
    EXPECT_EQ(addr->to_string(), "2001:db8::1");
}

TEST_F(AddressTest, IPv6_FromString_Invalid) {
    auto addr = IPv6Address::from_string("not:an:ipv6");
    EXPECT_FALSE(addr.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// IpAddress Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(AddressTest, IpAddress_FromIPv4) {
    auto v4 = IPv4Address::from_string("1.2.3.4");
    ASSERT_TRUE(v4.has_value());

    IpAddress addr(*v4);
    EXPECT_TRUE(addr.is_v4());
    EXPECT_FALSE(addr.is_v6());
    EXPECT_EQ(addr.to_string(), "1.2.3.4");
}

TEST_F(AddressTest, IpAddress_FromIPv6) {
    auto v6 = IPv6Address::from_string("::1");
    ASSERT_TRUE(v6.has_value());

    IpAddress addr(*v6);
    EXPECT_FALSE(addr.is_v4());
    EXPECT_TRUE(addr.is_v6());
    EXPECT_EQ(addr.to_string(), "::1");
}

TEST_F(AddressTest, IpAddress_FromString_IPv4) {
    auto addr = IpAddress::from_string("192.168.0.1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_TRUE(addr->is_v4());
}

TEST_F(AddressTest, IpAddress_FromString_IPv6) {
    auto addr = IpAddress::from_string("fe80::1");
    ASSERT_TRUE(addr.has_value());
    EXPECT_TRUE(addr->is_v6());
}

// ═══════════════════════════════════════════════════════════════════════════
// Endpoint Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(AddressTest, Endpoint_IPv4) {
    auto v4 = IPv4Address::from_string("127.0.0.1");
    ASSERT_TRUE(v4.has_value());

    Endpoint ep(*v4, 8080);
    EXPECT_EQ(ep.port(), 8080);
    EXPECT_TRUE(ep.is_v4());
    EXPECT_EQ(ep.to_string(), "127.0.0.1:8080");
}

TEST_F(AddressTest, Endpoint_IPv6) {
    auto v6 = IPv6Address::from_string("::1");
    ASSERT_TRUE(v6.has_value());

    Endpoint ep(*v6, 443);
    EXPECT_EQ(ep.port(), 443);
    EXPECT_TRUE(ep.is_v6());
    EXPECT_EQ(ep.to_string(), "[::1]:443");
}

TEST_F(AddressTest, Endpoint_ToSockaddr_IPv4) {
    auto v4 = IPv4Address::from_string("10.0.0.1");
    ASSERT_TRUE(v4.has_value());

    Endpoint ep(*v4, 12345);

    sockaddr_storage storage{};
    socklen_t len;
    ep.to_sockaddr(&storage, &len);

    EXPECT_EQ(len, sizeof(sockaddr_in));
    EXPECT_EQ(storage.ss_family, AF_INET);

    auto* sin = reinterpret_cast<sockaddr_in*>(&storage);
    EXPECT_EQ(ntohs(sin->sin_port), 12345);
}

TEST_F(AddressTest, Endpoint_ToSockaddr_IPv6) {
    auto v6 = IPv6Address::from_string("::1");
    ASSERT_TRUE(v6.has_value());

    Endpoint ep(*v6, 54321);

    sockaddr_storage storage{};
    socklen_t len;
    ep.to_sockaddr(&storage, &len);

    EXPECT_EQ(len, sizeof(sockaddr_in6));
    EXPECT_EQ(storage.ss_family, AF_INET6);

    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&storage);
    EXPECT_EQ(ntohs(sin6->sin6_port), 54321);
}

TEST_F(AddressTest, Endpoint_FromSockaddr) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8000);
    inet_pton(AF_INET, "192.168.1.100", &sin.sin_addr);

    auto ep = Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&sin));
    EXPECT_TRUE(ep.is_v4());
    EXPECT_EQ(ep.port(), 8000);
    EXPECT_EQ(ep.address().to_string(), "192.168.1.100");
}

TEST_F(AddressTest, Endpoint_Family) {
    auto v4 = IPv4Address::from_string("1.2.3.4");
    Endpoint ep4(*v4, 80);
    EXPECT_EQ(ep4.family(), AF_INET);

    auto v6 = IPv6Address::from_string("::1");
    Endpoint ep6(*v6, 80);
    EXPECT_EQ(ep6.family(), AF_INET6);
}
