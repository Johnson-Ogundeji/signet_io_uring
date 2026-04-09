// Signet WebSocket Extension Tests
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/ws/ws_extension.hpp>
#include <signet/ws/ws_deflate.hpp>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

using namespace signet;

// ═══════════════════════════════════════════════════════════════════════════
// Extension Parameter Tests
// ═══════════════════════════════════════════════════════════════════════════

class ExtensionParserTest : public ::testing::Test {};

TEST_F(ExtensionParserTest, ParseSingleExtension) {
    auto offers = parse_extension_header("permessage-deflate");
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers[0].name, "permessage-deflate");
    EXPECT_TRUE(offers[0].params.empty());
}

TEST_F(ExtensionParserTest, ParseWithParameters) {
    auto offers = parse_extension_header(
        "permessage-deflate; client_max_window_bits=10; server_no_context_takeover");
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers[0].name, "permessage-deflate");
    ASSERT_EQ(offers[0].params.size(), 2);
    EXPECT_EQ(offers[0].params[0].name, "client_max_window_bits");
    EXPECT_EQ(offers[0].params[0].value, "10");
    EXPECT_EQ(offers[0].params[1].name, "server_no_context_takeover");
    EXPECT_TRUE(offers[0].params[1].value.empty());
}

TEST_F(ExtensionParserTest, ParseMultipleExtensions) {
    auto offers = parse_extension_header(
        "permessage-deflate, x-webkit-deflate-frame");
    ASSERT_EQ(offers.size(), 2);
    EXPECT_EQ(offers[0].name, "permessage-deflate");
    EXPECT_EQ(offers[1].name, "x-webkit-deflate-frame");
}

TEST_F(ExtensionParserTest, ParseQuotedValue) {
    auto offers = parse_extension_header(
        "x-custom; param=\"value with spaces\"");
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers[0].name, "x-custom");
    ASSERT_EQ(offers[0].params.size(), 1);
    EXPECT_EQ(offers[0].params[0].name, "param");
    EXPECT_EQ(offers[0].params[0].value, "value with spaces");
}

TEST_F(ExtensionParserTest, EmptyHeader) {
    auto offers = parse_extension_header("");
    EXPECT_TRUE(offers.empty());
}

TEST_F(ExtensionParserTest, WhitespaceHandling) {
    auto offers = parse_extension_header(
        "  permessage-deflate  ;  client_max_window_bits = 10  ");
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers[0].name, "permessage-deflate");
    ASSERT_EQ(offers[0].params.size(), 1);
    EXPECT_EQ(offers[0].params[0].name, "client_max_window_bits");
    EXPECT_EQ(offers[0].params[0].value, "10");
}

// ═══════════════════════════════════════════════════════════════════════════
// Extension Offer Tests
// ═══════════════════════════════════════════════════════════════════════════

class ExtensionOfferTest : public ::testing::Test {
protected:
    ExtensionOffer offer;

    void SetUp() override {
        offer.name = "test-extension";
        offer.params.push_back({"param1", "value1"});
        offer.params.push_back({"param2", ""});
        offer.params.push_back({"param3", "42"});
    }
};

TEST_F(ExtensionOfferTest, HasParam) {
    EXPECT_TRUE(offer.has_param("param1"));
    EXPECT_TRUE(offer.has_param("param2"));
    EXPECT_TRUE(offer.has_param("param3"));
    EXPECT_FALSE(offer.has_param("param4"));
}

TEST_F(ExtensionOfferTest, GetParam) {
    EXPECT_EQ(offer.get_param("param1"), "value1");
    EXPECT_EQ(offer.get_param("param2"), "");
    EXPECT_EQ(offer.get_param("param3"), "42");
    EXPECT_EQ(offer.get_param("param4"), "");
}

TEST_F(ExtensionOfferTest, GetIntParam) {
    EXPECT_FALSE(offer.get_int_param("param1").has_value());  // Not numeric
    EXPECT_FALSE(offer.get_int_param("param2").has_value());  // Empty
    EXPECT_EQ(offer.get_int_param("param3"), 42);
    EXPECT_FALSE(offer.get_int_param("param4").has_value());  // Not found
}

// ═══════════════════════════════════════════════════════════════════════════
// Format Extension Header Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(FormatExtensionTest, SimpleExtension) {
    ExtensionOffer offer;
    offer.name = "permessage-deflate";
    EXPECT_EQ(format_extension_header(offer), "permessage-deflate");
}

TEST(FormatExtensionTest, WithParameters) {
    ExtensionOffer offer;
    offer.name = "permessage-deflate";
    offer.params.push_back({"client_max_window_bits", "10"});
    offer.params.push_back({"server_no_context_takeover", ""});

    std::string result = format_extension_header(offer);
    EXPECT_NE(result.find("permessage-deflate"), std::string::npos);
    EXPECT_NE(result.find("client_max_window_bits=10"), std::string::npos);
    EXPECT_NE(result.find("server_no_context_takeover"), std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Noop Extension Tests
// ═══════════════════════════════════════════════════════════════════════════

class NoopExtensionTest : public ::testing::Test {
protected:
    NoopExtension ext;
};

TEST_F(NoopExtensionTest, Name) {
    EXPECT_EQ(ext.name(), "x-noop");
}

TEST_F(NoopExtensionTest, GenerateOffer) {
    EXPECT_EQ(ext.generate_offer(), "x-noop");
}

TEST_F(NoopExtensionTest, Configure) {
    ExtensionOffer offer;
    offer.name = "x-noop";
    auto result = ext.configure(offer);
    EXPECT_TRUE(result.has_value());
}

TEST_F(NoopExtensionTest, ProcessOutgoing) {
    std::string data = "Hello, World!";
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto result = ext.process_outgoing(span, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data.size(), data.size());
    EXPECT_FALSE(result->rsv1);
}

TEST_F(NoopExtensionTest, ProcessIncoming) {
    std::string data = "Hello, World!";
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto result = ext.process_incoming(span, false, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), data.size());
}

// ═══════════════════════════════════════════════════════════════════════════
// Extension Chain Tests
// ═══════════════════════════════════════════════════════════════════════════

class ExtensionChainTest : public ::testing::Test {
protected:
    ExtensionChain chain;
};

TEST_F(ExtensionChainTest, Empty) {
    EXPECT_TRUE(chain.empty());
    EXPECT_EQ(chain.size(), 0);
}

TEST_F(ExtensionChainTest, AddExtension) {
    chain.add(std::make_unique<NoopExtension>());
    EXPECT_FALSE(chain.empty());
    EXPECT_EQ(chain.size(), 1);
}

TEST_F(ExtensionChainTest, GenerateOffer) {
    chain.add(std::make_unique<NoopExtension>());
    EXPECT_EQ(chain.generate_offer(), "x-noop");
}

TEST_F(ExtensionChainTest, ProcessOutgoing) {
    chain.add(std::make_unique<NoopExtension>());

    std::string data = "Test data";
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto result = chain.process_outgoing(span, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data.size(), data.size());
}

TEST_F(ExtensionChainTest, ProcessIncoming) {
    chain.add(std::make_unique<NoopExtension>());

    std::string data = "Test data";
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto result = chain.process_incoming(span, false, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), data.size());
}

TEST_F(ExtensionChainTest, RsvFlags) {
    chain.add(std::make_unique<NoopExtension>());
    EXPECT_FALSE(chain.uses_rsv1());
    EXPECT_FALSE(chain.uses_rsv2());
    EXPECT_FALSE(chain.uses_rsv3());
}

// ═══════════════════════════════════════════════════════════════════════════
// Deflate Config Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(DeflateConfigTest, DefaultConfig) {
    DeflateConfig config;
    EXPECT_EQ(config.compression_level, 6);
    EXPECT_EQ(config.mem_level, 8);
    EXPECT_EQ(config.client_max_window_bits, 15);
    EXPECT_EQ(config.server_max_window_bits, 15);
    EXPECT_FALSE(config.client_no_context_takeover);
    EXPECT_FALSE(config.server_no_context_takeover);
    EXPECT_EQ(config.min_compress_size, 64);
}

TEST(DeflateConfigTest, HftConfig) {
    auto config = DeflateConfig::hft();
    EXPECT_EQ(config.compression_level, 1);  // Fastest
    EXPECT_EQ(config.mem_level, 9);          // Max memory
    EXPECT_EQ(config.min_compress_size, 256);
}

TEST(DeflateConfigTest, BandwidthConfig) {
    auto config = DeflateConfig::bandwidth();
    EXPECT_EQ(config.compression_level, 6);
    EXPECT_EQ(config.mem_level, 8);
    EXPECT_EQ(config.min_compress_size, 64);
}

// ═══════════════════════════════════════════════════════════════════════════
// Permessage-Deflate Tests
// ═══════════════════════════════════════════════════════════════════════════

class PermessageDeflateTest : public ::testing::Test {
protected:
    std::unique_ptr<PermessageDeflate> deflate;

    void SetUp() override {
        DeflateConfig config;
        config.min_compress_size = 0;  // Compress everything for testing
        deflate = std::make_unique<PermessageDeflate>(config);
    }

    void configure() {
        ExtensionOffer response;
        response.name = "permessage-deflate";
        (void)deflate->configure(response);
    }
};

TEST_F(PermessageDeflateTest, Name) {
    EXPECT_EQ(deflate->name(), "permessage-deflate");
}

TEST_F(PermessageDeflateTest, UsesRsv1) {
    EXPECT_TRUE(deflate->uses_rsv1());
    EXPECT_FALSE(deflate->uses_rsv2());
    EXPECT_FALSE(deflate->uses_rsv3());
}

TEST_F(PermessageDeflateTest, GenerateOffer) {
    std::string offer = deflate->generate_offer();
    EXPECT_NE(offer.find("permessage-deflate"), std::string::npos);
}

TEST_F(PermessageDeflateTest, GenerateOfferWithParams) {
    DeflateConfig config;
    config.client_no_context_takeover = true;
    config.client_max_window_bits = 10;
    auto ext = std::make_unique<PermessageDeflate>(config);

    std::string offer = ext->generate_offer();
    EXPECT_NE(offer.find("client_no_context_takeover"), std::string::npos);
    EXPECT_NE(offer.find("client_max_window_bits=10"), std::string::npos);
}

TEST_F(PermessageDeflateTest, ConfigureBasic) {
    ExtensionOffer response;
    response.name = "permessage-deflate";
    auto result = deflate->configure(response);
    EXPECT_TRUE(result.has_value());
}

TEST_F(PermessageDeflateTest, ConfigureWithParams) {
    ExtensionOffer response;
    response.name = "permessage-deflate";
    response.params.push_back({"server_no_context_takeover", ""});
    response.params.push_back({"server_max_window_bits", "10"});
    auto result = deflate->configure(response);
    EXPECT_TRUE(result.has_value());
}

TEST_F(PermessageDeflateTest, ConfigureInvalidWindowBits) {
    ExtensionOffer response;
    response.name = "permessage-deflate";
    response.params.push_back({"server_max_window_bits", "20"});  // Invalid
    auto result = deflate->configure(response);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PermessageDeflateTest, CompressDecompressRoundtrip) {
    configure();

    // Create test data (repetitive data compresses well)
    std::string original(500, 'A');
    std::span<const std::byte> input(
        reinterpret_cast<const std::byte*>(original.data()), original.size());

    // Compress
    auto compressed = deflate->process_outgoing(input, true);
    ASSERT_TRUE(compressed.has_value());
    EXPECT_TRUE(compressed->rsv1);  // RSV1 set indicates compression
    EXPECT_LT(compressed->data.size(), original.size());  // Should be smaller

    // Decompress
    auto decompressed = deflate->process_incoming(
        std::span<const std::byte>(compressed->data), true, true);
    ASSERT_TRUE(decompressed.has_value());
    EXPECT_EQ(decompressed->size(), original.size());

    // Verify content
    std::string result(
        reinterpret_cast<const char*>(decompressed->data()),
        decompressed->size());
    EXPECT_EQ(result, original);
}

TEST_F(PermessageDeflateTest, PassthroughWhenNotCompressed) {
    configure();

    std::string original = "Short";
    std::span<const std::byte> input(
        reinterpret_cast<const std::byte*>(original.data()), original.size());

    // Process incoming without RSV1 (not compressed)
    auto result = deflate->process_incoming(input, false, true);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), original.size());
}

TEST_F(PermessageDeflateTest, NotConfiguredError) {
    // Don't configure, try to decompress compressed data
    std::array<std::byte, 10> fake_compressed{};
    std::span<const std::byte> input(fake_compressed);

    auto result = deflate->process_incoming(input, true, true);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PermessageDeflateTest, CompressVariousPatterns) {
    configure();

    // Test with JSON-like data (common in WebSocket)
    std::string json = R"({"type":"trade","symbol":"BTCUSDT","price":"50000.00","quantity":"0.001","timestamp":1234567890})";
    // Repeat to make it bigger for better compression
    std::string data;
    for (int i = 0; i < 10; ++i) {
        data += json;
    }

    std::span<const std::byte> input(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto compressed = deflate->process_outgoing(input, true);
    ASSERT_TRUE(compressed.has_value());
    EXPECT_LT(compressed->data.size(), data.size());

    // Roundtrip
    auto decompressed = deflate->process_incoming(
        std::span<const std::byte>(compressed->data), true, true);
    ASSERT_TRUE(decompressed.has_value());

    std::string result(
        reinterpret_cast<const char*>(decompressed->data()),
        decompressed->size());
    EXPECT_EQ(result, data);
}

// ═══════════════════════════════════════════════════════════════════════════
// Factory Function Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(DeflateFactoryTest, MakeDeflateExtension) {
    auto ext = make_deflate_extension();
    EXPECT_NE(ext, nullptr);
    EXPECT_EQ(ext->name(), "permessage-deflate");
}

TEST(DeflateFactoryTest, MakeDeflateExtensionHft) {
    auto ext = make_deflate_extension_hft();
    EXPECT_NE(ext, nullptr);
    EXPECT_EQ(ext->name(), "permessage-deflate");
}

TEST(DeflateFactoryTest, MakeDeflateExtensionBandwidth) {
    auto ext = make_deflate_extension_bandwidth();
    EXPECT_NE(ext, nullptr);
    EXPECT_EQ(ext->name(), "permessage-deflate");
}

// ═══════════════════════════════════════════════════════════════════════════
// Extension Chain with Deflate Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(ExtensionChainDeflateTest, WithDeflate) {
    ExtensionChain chain;
    chain.add(make_deflate_extension());
    EXPECT_TRUE(chain.uses_rsv1());
    EXPECT_EQ(chain.size(), 1);
}

TEST(ExtensionChainDeflateTest, ConfigureFromHeader) {
    ExtensionChain chain;
    chain.add(make_deflate_extension());

    auto result = chain.configure("permessage-deflate");
    EXPECT_TRUE(result.has_value());
}

TEST(ExtensionChainDeflateTest, RoundtripThroughChain) {
    ExtensionChain chain;

    DeflateConfig config;
    config.min_compress_size = 0;
    chain.add(std::make_unique<PermessageDeflate>(config));

    auto config_result = chain.configure("permessage-deflate");
    ASSERT_TRUE(config_result.has_value());

    // Test data
    std::string original(500, 'X');
    std::span<const std::byte> input(
        reinterpret_cast<const std::byte*>(original.data()), original.size());

    // Process outgoing
    auto compressed = chain.process_outgoing(input, true);
    ASSERT_TRUE(compressed.has_value());

    // Process incoming
    auto decompressed = chain.process_incoming(
        std::span<const std::byte>(compressed->data), compressed->rsv1, true);
    ASSERT_TRUE(decompressed.has_value());

    std::string result(
        reinterpret_cast<const char*>(decompressed->data()),
        decompressed->size());
    EXPECT_EQ(result, original);
}
