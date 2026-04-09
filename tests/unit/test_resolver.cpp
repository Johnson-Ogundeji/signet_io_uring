// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <signet/net/resolver.hpp>
#include <gtest/gtest.h>

using namespace signet;

class ResolverTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ═══════════════════════════════════════════════════════════════════════════
// Resolver Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(ResolverTest, Resolve_Localhost) {
    Resolver resolver;
    auto result = resolver.resolve("localhost", "", 80);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());
    EXPECT_EQ(result->hostname, "localhost");

    // Should have at least one endpoint
    auto first = result->first();
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->port(), 80);
}

TEST_F(ResolverTest, Resolve_IP_Direct) {
    Resolver resolver;
    auto result = resolver.resolve("127.0.0.1", "", 8080);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());

    auto first = result->first_v4();
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->address().to_string(), "127.0.0.1");
    EXPECT_EQ(first->port(), 8080);
}

TEST_F(ResolverTest, Resolve_WithService) {
    Resolver resolver;
    auto result = resolver.resolve("localhost", "http");

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->empty());

    // HTTP service should resolve to port 80
    auto first = result->first();
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->port(), 80);
}

TEST_F(ResolverTest, Resolve_Invalid) {
    Resolver resolver;
    auto result = resolver.resolve("this.hostname.does.not.exist.invalid");

    EXPECT_FALSE(result.has_value());
}

TEST_F(ResolverTest, ResolveOne_Success) {
    Resolver resolver;
    auto ep = resolver.resolve_one("localhost", 443);

    ASSERT_TRUE(ep.has_value());
    EXPECT_EQ(ep->port(), 443);
}

TEST_F(ResolverTest, Cache_Hit) {
    ResolverOptions opts;
    opts.use_cache = true;
    Resolver resolver(opts);

    // First resolution
    auto result1 = resolver.resolve("localhost", "", 80);
    ASSERT_TRUE(result1.has_value());
    EXPECT_EQ(resolver.cache_size(), 1);

    // Second resolution should hit cache
    auto result2 = resolver.resolve("localhost", "", 80);
    ASSERT_TRUE(result2.has_value());
    EXPECT_EQ(resolver.cache_size(), 1);
}

TEST_F(ResolverTest, Cache_Clear) {
    Resolver resolver;
    auto result = resolver.resolve("localhost", "", 80);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(resolver.cache_size(), 0);

    resolver.clear_cache();
    EXPECT_EQ(resolver.cache_size(), 0);
}

TEST_F(ResolverTest, PreferIPv4) {
    ResolverOptions opts;
    opts.prefer_ipv4 = true;
    opts.allow_ipv6 = true;
    Resolver resolver(opts);

    auto result = resolver.resolve("localhost", "", 80);
    ASSERT_TRUE(result.has_value());

    // First result should be IPv4 if available
    if (!result->empty() && result->first_v4().has_value()) {
        EXPECT_TRUE(result->endpoints.front().is_v4());
    }
}

TEST_F(ResolverTest, IPv4Only) {
    ResolverOptions opts;
    opts.allow_ipv6 = false;
    Resolver resolver(opts);

    auto result = resolver.resolve("localhost", "", 80);
    ASSERT_TRUE(result.has_value());

    // All results should be IPv4
    for (const auto& ep : result->endpoints) {
        EXPECT_TRUE(ep.is_v4());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ParsedUrl Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(ResolverTest, ParseUrl_SimpleHost) {
    auto result = ParsedUrl::parse("example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 0);
    EXPECT_EQ(result->path, "/");
    EXPECT_FALSE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_HostPort) {
    auto result = ParsedUrl::parse("example.com:8080");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 8080);
    EXPECT_EQ(result->path, "/");
}

TEST_F(ResolverTest, ParseUrl_HttpScheme) {
    auto result = ParsedUrl::parse("http://example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->scheme, "http");
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 80);
    EXPECT_FALSE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_HttpsScheme) {
    auto result = ParsedUrl::parse("https://example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->scheme, "https");
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 443);
    EXPECT_TRUE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_WsScheme) {
    auto result = ParsedUrl::parse("ws://example.com/socket");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->scheme, "ws");
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 80);
    EXPECT_EQ(result->path, "/socket");
    EXPECT_FALSE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_WssScheme) {
    auto result = ParsedUrl::parse("wss://example.com/socket");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->scheme, "wss");
    EXPECT_EQ(result->host, "example.com");
    EXPECT_EQ(result->port, 443);
    EXPECT_EQ(result->path, "/socket");
    EXPECT_TRUE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_FullUrl) {
    auto result = ParsedUrl::parse("https://api.example.com:8443/v1/data");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->scheme, "https");
    EXPECT_EQ(result->host, "api.example.com");
    EXPECT_EQ(result->port, 8443);
    EXPECT_EQ(result->path, "/v1/data");
    EXPECT_TRUE(result->is_secure);
}

TEST_F(ResolverTest, ParseUrl_IPv4) {
    auto result = ParsedUrl::parse("http://192.168.1.1:8080/api");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->host, "192.168.1.1");
    EXPECT_EQ(result->port, 8080);
    EXPECT_EQ(result->path, "/api");
}

TEST_F(ResolverTest, ParseUrl_IPv6) {
    auto result = ParsedUrl::parse("http://[::1]:8080/api");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->host, "::1");
    EXPECT_EQ(result->port, 8080);
    EXPECT_EQ(result->path, "/api");
}

TEST_F(ResolverTest, ParseUrl_IPv6_NoPort) {
    auto result = ParsedUrl::parse("http://[2001:db8::1]/api");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->host, "2001:db8::1");
    EXPECT_EQ(result->port, 80);  // Default HTTP port
}

TEST_F(ResolverTest, ParseUrl_Empty) {
    auto result = ParsedUrl::parse("");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ResolverTest, ParseUrl_SchemeOnly) {
    auto result = ParsedUrl::parse("https://");
    EXPECT_FALSE(result.has_value());
}
