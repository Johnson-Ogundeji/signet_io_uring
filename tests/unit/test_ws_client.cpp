// Signet WebSocket Client Tests
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/ws/ws_client.hpp>

#include <string>
#include <string_view>

using namespace signet;

// ═══════════════════════════════════════════════════════════════════════════
// URL Parsing Tests (Internal)
// ═══════════════════════════════════════════════════════════════════════════

// Test URL parsing indirectly through connect error messages
class WsClientUrlTest : public ::testing::Test {
protected:
    WsClient client;
};

TEST_F(WsClientUrlTest, InvalidScheme) {
    auto result = client.connect("http://example.com");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidUrl);
}

TEST_F(WsClientUrlTest, ValidWsScheme) {
    // Connection will fail but URL parsing should succeed
    auto result = client.connect("ws://localhost:12345/test");
    // Expect connection failure, not URL parsing error
    if (!result) {
        EXPECT_NE(result.error().code(), ErrorCode::InvalidUrl);
    }
}

TEST_F(WsClientUrlTest, ValidWssScheme) {
    // Connection will fail but URL parsing should succeed
    auto result = client.connect("wss://localhost:12345/test");
    if (!result) {
        EXPECT_NE(result.error().code(), ErrorCode::InvalidUrl);
    }
}

TEST_F(WsClientUrlTest, EmptyHost) {
    auto result = client.connect("ws:///test");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidUrl);
}

// ═══════════════════════════════════════════════════════════════════════════
// Client Configuration Tests
// ═══════════════════════════════════════════════════════════════════════════

class WsClientConfigTest : public ::testing::Test {};

TEST_F(WsClientConfigTest, DefaultConfig) {
    WsClientConfig config;
    EXPECT_EQ(config.connect_timeout, std::chrono::milliseconds{10000});
    EXPECT_EQ(config.handshake_timeout, std::chrono::milliseconds{5000});
    EXPECT_EQ(config.ping_interval, std::chrono::milliseconds{30000});
    EXPECT_EQ(config.max_message_size, 16 * 1024 * 1024);
    EXPECT_TRUE(config.auto_reconnect);
    EXPECT_TRUE(config.enable_compression);
    EXPECT_TRUE(config.verify_certificates);
}

TEST_F(WsClientConfigTest, HftConfig) {
    auto config = WsClientConfig::hft();
    EXPECT_EQ(config.connect_timeout, std::chrono::milliseconds{5000});
    EXPECT_EQ(config.handshake_timeout, std::chrono::milliseconds{2000});
    EXPECT_EQ(config.ping_interval, std::chrono::milliseconds{15000});
    EXPECT_EQ(config.reconnect_delay_base, std::chrono::milliseconds{100});
    EXPECT_EQ(config.recv_buffer_size, 128 * 1024);
}

TEST_F(WsClientConfigTest, BandwidthOptimizedConfig) {
    auto config = WsClientConfig::bandwidth_optimized();
    EXPECT_TRUE(config.enable_compression);
    EXPECT_EQ(config.recv_buffer_size, 32 * 1024);
    EXPECT_EQ(config.send_buffer_size, 32 * 1024);
}

TEST_F(WsClientConfigTest, ExtraHeaders) {
    WsClientConfig config;
    config.extra_headers.push_back({"Authorization", "Bearer token123"});
    config.extra_headers.push_back({"X-Custom-Header", "value"});

    EXPECT_EQ(config.extra_headers.size(), 2);
    EXPECT_EQ(config.extra_headers[0].first, "Authorization");
    EXPECT_EQ(config.extra_headers[0].second, "Bearer token123");
}

TEST_F(WsClientConfigTest, Subprotocols) {
    WsClientConfig config;
    config.subprotocols.push_back("graphql-transport-ws");
    config.subprotocols.push_back("graphql-ws");

    EXPECT_EQ(config.subprotocols.size(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Client State Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClientStateTest, StateToString) {
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Disconnected), "Disconnected");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Connecting), "Connecting");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Handshaking), "Handshaking");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Connected), "Connected");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Closing), "Closing");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Reconnecting), "Reconnecting");
    EXPECT_EQ(ws_client_state_to_string(WsClientState::Failed), "Failed");
}

// ═══════════════════════════════════════════════════════════════════════════
// Client Message Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClientMessageTest, AsText) {
    WsClientMessage msg;
    msg.type = signet::WsMessageType::Text;
    std::string text = "Hello, World!";
    msg.data.assign(
        reinterpret_cast<const std::byte*>(text.data()),
        reinterpret_cast<const std::byte*>(text.data() + text.size()));

    EXPECT_EQ(msg.as_text(), "Hello, World!");
}

TEST(WsClientMessageTest, AsBinary) {
    WsClientMessage msg;
    msg.type = signet::WsMessageType::Binary;
    msg.data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

    auto binary = msg.as_binary();
    EXPECT_EQ(binary.size(), 3);
    EXPECT_EQ(binary[0], std::byte{0x01});
    EXPECT_EQ(binary[1], std::byte{0x02});
    EXPECT_EQ(binary[2], std::byte{0x03});
}

// ═══════════════════════════════════════════════════════════════════════════
// Client Statistics Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClientStatsTest, DefaultValues) {
    WsClientStats stats;
    EXPECT_EQ(stats.messages_sent, 0);
    EXPECT_EQ(stats.messages_received, 0);
    EXPECT_EQ(stats.bytes_sent, 0);
    EXPECT_EQ(stats.bytes_received, 0);
    EXPECT_EQ(stats.reconnect_count, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Client Instance Tests
// ═══════════════════════════════════════════════════════════════════════════

class WsClientInstanceTest : public ::testing::Test {
protected:
    std::unique_ptr<WsClient> client;

    void SetUp() override {
        client = std::make_unique<WsClient>();
    }
};

TEST_F(WsClientInstanceTest, InitialState) {
    EXPECT_EQ(client->state(), WsClientState::Disconnected);
    EXPECT_FALSE(client->is_connected());
}

TEST_F(WsClientInstanceTest, Stats) {
    auto stats = client->stats();
    EXPECT_EQ(stats.messages_sent, 0);
    EXPECT_EQ(stats.messages_received, 0);
}

TEST_F(WsClientInstanceTest, ResetStats) {
    client->reset_stats();
    auto stats = client->stats();
    EXPECT_EQ(stats.messages_sent, 0);
}

TEST_F(WsClientInstanceTest, Extensions) {
    // By default, compression is enabled
    EXPECT_TRUE(client->extensions().uses_rsv1());
}

TEST_F(WsClientInstanceTest, Subprotocol) {
    // Before connection, subprotocol is empty
    EXPECT_TRUE(client->subprotocol().empty());
}

TEST_F(WsClientInstanceTest, ConfigAccess) {
    auto& config = client->config();
    EXPECT_TRUE(config.auto_reconnect);
}

// ═══════════════════════════════════════════════════════════════════════════
// Callback Registration Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(WsClientInstanceTest, RegisterCallbacks) {
    bool connect_called = false;
    bool disconnect_called = false;
    bool message_called = false;
    bool error_called = false;
    bool ping_called = false;
    bool pong_called = false;
    bool state_change_called = false;

    client->on_connect([&connect_called]() {
        connect_called = true;
    });

    client->on_disconnect([&disconnect_called](CloseCode, std::string_view) {
        disconnect_called = true;
    });

    client->on_message([&message_called](const WsClientMessage&) {
        message_called = true;
    });

    client->on_error([&error_called](const Error&) {
        error_called = true;
    });

    client->on_ping([&ping_called](std::span<const std::byte>) {
        ping_called = true;
    });

    client->on_pong([&pong_called](std::span<const std::byte>) {
        pong_called = true;
    });

    client->on_state_change([&state_change_called](WsClientState, WsClientState) {
        state_change_called = true;
    });

    // Callbacks are registered but not called yet
    EXPECT_FALSE(connect_called);
    EXPECT_FALSE(disconnect_called);
    EXPECT_FALSE(message_called);
    EXPECT_FALSE(error_called);
    EXPECT_FALSE(ping_called);
    EXPECT_FALSE(pong_called);
    EXPECT_FALSE(state_change_called);
}

// ═══════════════════════════════════════════════════════════════════════════
// Disconnected Operations Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(WsClientInstanceTest, SendWhenDisconnected) {
    auto result = client->send("test");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::ConnectionClosed);
}

TEST_F(WsClientInstanceTest, SendBinaryWhenDisconnected) {
    std::array<std::byte, 3> data = {std::byte{1}, std::byte{2}, std::byte{3}};
    auto result = client->send(std::span<const std::byte>(data));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::ConnectionClosed);
}

TEST_F(WsClientInstanceTest, PingWhenDisconnected) {
    auto result = client->ping();
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::ConnectionClosed);
}

TEST_F(WsClientInstanceTest, PongWhenDisconnected) {
    auto result = client->pong();
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::ConnectionClosed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Factory Function Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClientFactoryTest, MakeWsClient) {
    auto client = make_ws_client();
    EXPECT_NE(client, nullptr);
    EXPECT_EQ(client->state(), WsClientState::Disconnected);
}

TEST(WsClientFactoryTest, MakeWsClientHft) {
    auto client = make_ws_client_hft();
    EXPECT_NE(client, nullptr);
    // HFT config has different timeouts
    EXPECT_EQ(client->config().connect_timeout, std::chrono::milliseconds{5000});
}

TEST(WsClientFactoryTest, MakeWsClientCustomConfig) {
    WsClientConfig config;
    config.auto_reconnect = false;
    config.enable_compression = false;

    auto client = make_ws_client(config);
    EXPECT_NE(client, nullptr);
    EXPECT_FALSE(client->config().auto_reconnect);
    EXPECT_FALSE(client->config().enable_compression);
}

// ═══════════════════════════════════════════════════════════════════════════
// Disconnect Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(WsClientInstanceTest, DisconnectWhenNotConnected) {
    // Should not crash or throw
    client->disconnect();
    EXPECT_EQ(client->state(), WsClientState::Disconnected);
}

TEST_F(WsClientInstanceTest, DisconnectWithCode) {
    client->disconnect(CloseCode::GoingAway, "bye");
    EXPECT_EQ(client->state(), WsClientState::Disconnected);
}

// ═══════════════════════════════════════════════════════════════════════════
// Poll Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(WsClientInstanceTest, PollWhenDisconnected) {
    // Should return false when disconnected
    bool result = client->poll_once();
    EXPECT_FALSE(result);
}

TEST_F(WsClientInstanceTest, RunForWhenDisconnected) {
    // Should return immediately
    auto events = client->run_for(std::chrono::milliseconds{100});
    EXPECT_EQ(events, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Configuration Change Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(WsClientInstanceTest, SetConfigWhenDisconnected) {
    WsClientConfig new_config;
    new_config.auto_reconnect = false;
    new_config.ping_interval = std::chrono::milliseconds{60000};

    client->set_config(new_config);

    EXPECT_FALSE(client->config().auto_reconnect);
    EXPECT_EQ(client->config().ping_interval, std::chrono::milliseconds{60000});
}

// ═══════════════════════════════════════════════════════════════════════════
// Extensions Test
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClientExtensionsTest, CompressionDisabled) {
    WsClientConfig config;
    config.enable_compression = false;

    WsClient client(config);
    EXPECT_FALSE(client.extensions().uses_rsv1());
    EXPECT_TRUE(client.extensions().empty());
}

TEST(WsClientExtensionsTest, CompressionEnabled) {
    WsClientConfig config;
    config.enable_compression = true;

    WsClient client(config);
    EXPECT_TRUE(client.extensions().uses_rsv1());
    EXPECT_EQ(client.extensions().size(), 1);
}
