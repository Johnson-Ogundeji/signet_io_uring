// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <signet/tls/tls_context.hpp>
#include <signet/tls/ktls.hpp>
#include <signet/tls/tls_connection.hpp>
#include <signet/net/resolver.hpp>
#include <gtest/gtest.h>

#include <csignal>

using namespace signet;

class TlsTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::signal(SIGPIPE, SIG_IGN);
    }
    void TearDown() override {}
};

// ═══════════════════════════════════════════════════════════════════════════
// TLS Context Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, CreateClientContext) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());
    EXPECT_TRUE(ctx->is_client());
    EXPECT_NE(ctx->native_handle(), nullptr);
}

TEST_F(TlsTest, CreateClientContext_WithConfig) {
    TlsContextConfig config;
    config.verify_mode = TlsVerifyMode::Peer;
    config.versions.min_version = TLS1_2_VERSION;
    config.versions.max_version = TLS1_3_VERSION;

    auto ctx = TlsContext::create_client(config);
    ASSERT_TRUE(ctx.has_value());
    EXPECT_EQ(ctx->config().verify_mode, TlsVerifyMode::Peer);
}

TEST_F(TlsTest, CreateClientContext_NoVerification) {
    TlsContextConfig config;
    config.verify_mode = TlsVerifyMode::None;

    auto ctx = TlsContext::create_client(config);
    ASSERT_TRUE(ctx.has_value());
}

TEST_F(TlsTest, CreateClientContext_WithALPN) {
    TlsContextConfig config;
    config.alpn_protocols = {"h2", "http/1.1"};

    auto ctx = TlsContext::create_client(config);
    ASSERT_TRUE(ctx.has_value());
}

TEST_F(TlsTest, CreateSsl) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto ssl = ctx->create_ssl();
    ASSERT_TRUE(ssl.has_value());
    EXPECT_NE(ssl->get(), nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// kTLS Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, CheckKtlsSupport) {
    KtlsSupport support = check_ktls_support();
    // Just verify the function runs without crashing
    // kTLS availability depends on kernel configuration
    EXPECT_TRUE(support == KtlsSupport::None ||
                support == KtlsSupport::SendOnly ||
                support == KtlsSupport::Full);
}

TEST_F(TlsTest, IsKtlsCompatibleCipher_Null) {
    EXPECT_FALSE(is_ktls_compatible_cipher(nullptr));
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS Connection State Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, TlsState_ToString) {
    EXPECT_EQ(std::string(to_string(TlsState::Disconnected)), "Disconnected");
    EXPECT_EQ(std::string(to_string(TlsState::Connecting)), "Connecting");
    EXPECT_EQ(std::string(to_string(TlsState::Handshaking)), "Handshaking");
    EXPECT_EQ(std::string(to_string(TlsState::Connected)), "Connected");
    EXPECT_EQ(std::string(to_string(TlsState::ShuttingDown)), "ShuttingDown");
    EXPECT_EQ(std::string(to_string(TlsState::Closed)), "Closed");
    EXPECT_EQ(std::string(to_string(TlsState::Error)), "Error");
}

// ═══════════════════════════════════════════════════════════════════════════
// SSL Error String Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, GetSslErrorString_NoError) {
    // Clear any existing errors
    ERR_clear_error();

    auto error = get_ssl_error_string();
    EXPECT_EQ(error, "No error");
}

TEST_F(TlsTest, GetSslErrorQueue_Empty) {
    ERR_clear_error();

    auto errors = get_ssl_error_queue();
    EXPECT_EQ(errors, "No error");
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS Connection Tests (without actual network)
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, TlsConnection_InitWithoutSocket) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    // Create unconnected socket
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);

    EXPECT_EQ(conn.state(), TlsState::Disconnected);
    EXPECT_FALSE(conn.is_connected());
    EXPECT_FALSE(conn.is_ktls_enabled());
}

TEST_F(TlsTest, TlsConnection_InitTls) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);

    // Init TLS should succeed even without connection
    auto result = conn.init_tls("example.com");
    EXPECT_TRUE(result.has_value());
    EXPECT_NE(conn.native_ssl(), nullptr);
}

TEST_F(TlsTest, TlsConnection_Stats) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);

    const auto& stats = conn.stats();
    EXPECT_EQ(stats.bytes_encrypted, 0);
    EXPECT_EQ(stats.bytes_decrypted, 0);
    EXPECT_FALSE(stats.ktls_enabled);
    EXPECT_FALSE(stats.session_reused);
}

TEST_F(TlsTest, TlsConnection_CloseSync) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);
    conn.close_sync();

    EXPECT_EQ(conn.state(), TlsState::Closed);
}

TEST_F(TlsTest, TlsConnection_ReadNotConnected) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);

    std::array<std::byte, 1024> buffer;
    auto result = conn.read(buffer);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidState);
}

TEST_F(TlsTest, TlsConnection_WriteNotConnected) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn(std::move(*sock), *ctx);

    auto result = conn.write("test data");

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidState);
}

TEST_F(TlsTest, TlsConnection_Move) {
    auto ctx = TlsContext::create_client();
    ASSERT_TRUE(ctx.has_value());

    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    TlsConnection conn1(std::move(*sock), *ctx);
    (void)conn1.init_tls("example.com");

    // Move construct
    TlsConnection conn2(std::move(conn1));

    // conn1 should be closed after move
    EXPECT_EQ(conn1.state(), TlsState::Closed);

    // conn2 should have the SSL object
    EXPECT_NE(conn2.native_ssl(), nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS Version Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsTest, TlsVersions_Default) {
    TlsVersions versions;
    EXPECT_EQ(versions.min_version, TLS1_2_VERSION);
    EXPECT_EQ(versions.max_version, TLS1_3_VERSION);
}

TEST_F(TlsTest, TlsContextConfig_Default) {
    TlsContextConfig config;
    EXPECT_EQ(config.verify_mode, TlsVerifyMode::Peer);
    EXPECT_TRUE(config.verify_hostname);
    EXPECT_TRUE(config.enable_session_cache);
    EXPECT_EQ(config.session_cache_size, 1024);
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration Test (requires network, may be skipped in CI)
// ═══════════════════════════════════════════════════════════════════════════

// Note: This test requires actual network connectivity
// and may fail in restricted environments
TEST_F(TlsTest, DISABLED_IntegrationTest_ConnectToHttps) {
    // Create TLS context
    TlsContextConfig config;
    config.verify_mode = TlsVerifyMode::Peer;
    config.verify_hostname = true;

    auto ctx = TlsContext::create_client(config);
    ASSERT_TRUE(ctx.has_value());

    // Resolve hostname
    Resolver resolver;
    auto ep = resolver.resolve_one("www.google.com", 443);
    ASSERT_TRUE(ep.has_value());

    // Create TLS connection
    auto conn = create_tls_client(*ep, *ctx, "www.google.com");
    ASSERT_TRUE(conn.has_value());

    EXPECT_TRUE(conn->is_connected());
    EXPECT_FALSE(conn->get_cipher().empty());
    EXPECT_GE(conn->get_version(), TLS1_2_VERSION);

    // Send HTTP request
    auto write_result = conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    EXPECT_TRUE(write_result.has_value());
    EXPECT_GT(*write_result, 0);

    // Read response
    std::array<std::byte, 4096> buffer;
    auto read_result = conn->read(buffer);
    EXPECT_TRUE(read_result.has_value());
    EXPECT_GT(*read_result, 0);

    conn->close_sync();
}
