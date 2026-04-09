// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <signet/ws/ws_types.hpp>
#include <signet/ws/ws_frame.hpp>
#include <signet/ws/ws_handshake.hpp>
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

using namespace signet;

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Types Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsTypesTest, OpcodeClassification) {
    // Data frames
    EXPECT_TRUE(is_data_frame(WsOpcode::Continuation));
    EXPECT_TRUE(is_data_frame(WsOpcode::Text));
    EXPECT_TRUE(is_data_frame(WsOpcode::Binary));
    EXPECT_FALSE(is_data_frame(WsOpcode::Close));
    EXPECT_FALSE(is_data_frame(WsOpcode::Ping));
    EXPECT_FALSE(is_data_frame(WsOpcode::Pong));

    // Control frames
    EXPECT_FALSE(is_control_frame(WsOpcode::Continuation));
    EXPECT_FALSE(is_control_frame(WsOpcode::Text));
    EXPECT_FALSE(is_control_frame(WsOpcode::Binary));
    EXPECT_TRUE(is_control_frame(WsOpcode::Close));
    EXPECT_TRUE(is_control_frame(WsOpcode::Ping));
    EXPECT_TRUE(is_control_frame(WsOpcode::Pong));
}

TEST(WsTypesTest, OpcodeValidity) {
    // Valid opcodes
    EXPECT_TRUE(is_valid_opcode(0x0));  // Continuation
    EXPECT_TRUE(is_valid_opcode(0x1));  // Text
    EXPECT_TRUE(is_valid_opcode(0x2));  // Binary
    EXPECT_TRUE(is_valid_opcode(0x8));  // Close
    EXPECT_TRUE(is_valid_opcode(0x9));  // Ping
    EXPECT_TRUE(is_valid_opcode(0xA));  // Pong

    // Invalid opcodes
    EXPECT_FALSE(is_valid_opcode(0x3));  // Reserved
    EXPECT_FALSE(is_valid_opcode(0x7));  // Reserved
    EXPECT_FALSE(is_valid_opcode(0xB));  // Reserved
    EXPECT_FALSE(is_valid_opcode(0xF));  // Reserved
}

TEST(WsTypesTest, OpcodeName) {
    EXPECT_EQ(opcode_name(WsOpcode::Continuation), "Continuation");
    EXPECT_EQ(opcode_name(WsOpcode::Text), "Text");
    EXPECT_EQ(opcode_name(WsOpcode::Binary), "Binary");
    EXPECT_EQ(opcode_name(WsOpcode::Close), "Close");
    EXPECT_EQ(opcode_name(WsOpcode::Ping), "Ping");
    EXPECT_EQ(opcode_name(WsOpcode::Pong), "Pong");
}

TEST(WsTypesTest, CloseCodeValidity) {
    // Valid codes
    EXPECT_TRUE(is_valid_close_code(1000));  // Normal
    EXPECT_TRUE(is_valid_close_code(1001));  // Going away
    EXPECT_TRUE(is_valid_close_code(1002));  // Protocol error
    EXPECT_TRUE(is_valid_close_code(1003));  // Unsupported data
    EXPECT_TRUE(is_valid_close_code(1007));  // Invalid payload
    EXPECT_TRUE(is_valid_close_code(1008));  // Policy violation
    EXPECT_TRUE(is_valid_close_code(1009));  // Message too big
    EXPECT_TRUE(is_valid_close_code(1010));  // Missing extension
    EXPECT_TRUE(is_valid_close_code(1011));  // Internal error
    EXPECT_TRUE(is_valid_close_code(3000));  // Library codes start
    EXPECT_TRUE(is_valid_close_code(4000));  // Application codes start

    // Invalid/reserved codes
    EXPECT_FALSE(is_valid_close_code(0));
    EXPECT_FALSE(is_valid_close_code(999));
    EXPECT_FALSE(is_valid_close_code(1004));  // Reserved
    EXPECT_FALSE(is_valid_close_code(1005));  // No status (internal only)
    EXPECT_FALSE(is_valid_close_code(1006));  // Abnormal (internal only)
    EXPECT_FALSE(is_valid_close_code(1015));  // TLS handshake (internal only)
    EXPECT_FALSE(is_valid_close_code(1016));  // Reserved for future
    EXPECT_FALSE(is_valid_close_code(2999));  // Reserved
}

TEST(WsTypesTest, CloseCodeDescription) {
    EXPECT_EQ(close_code_description(WsCloseCode::Normal), "Normal closure");
    EXPECT_EQ(close_code_description(WsCloseCode::GoingAway), "Going away");
    EXPECT_EQ(close_code_description(WsCloseCode::ProtocolError), "Protocol error");
}

TEST(WsTypesTest, StateName) {
    EXPECT_EQ(state_name(WsState::Connecting), "Connecting");
    EXPECT_EQ(state_name(WsState::Open), "Open");
    EXPECT_EQ(state_name(WsState::Closing), "Closing");
    EXPECT_EQ(state_name(WsState::Closed), "Closed");
}

TEST(WsTypesTest, MessageTypeConversion) {
    EXPECT_EQ(opcode_to_message_type(WsOpcode::Text), WsMessageType::Text);
    EXPECT_EQ(opcode_to_message_type(WsOpcode::Binary), WsMessageType::Binary);
    EXPECT_EQ(opcode_to_message_type(WsOpcode::Ping), WsMessageType::Ping);
    EXPECT_EQ(opcode_to_message_type(WsOpcode::Pong), WsMessageType::Pong);
    EXPECT_EQ(opcode_to_message_type(WsOpcode::Close), WsMessageType::Close);

    EXPECT_EQ(message_type_to_opcode(WsMessageType::Text), WsOpcode::Text);
    EXPECT_EQ(message_type_to_opcode(WsMessageType::Binary), WsOpcode::Binary);
    EXPECT_EQ(message_type_to_opcode(WsMessageType::Ping), WsOpcode::Ping);
    EXPECT_EQ(message_type_to_opcode(WsMessageType::Pong), WsOpcode::Pong);
    EXPECT_EQ(message_type_to_opcode(WsMessageType::Close), WsOpcode::Close);
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame Parser Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsFrameParserTest, ParseMinimalFrame) {
    // FIN=1, opcode=1 (text), no mask, length=5, payload="Hello"
    std::array<uint8_t, 7> frame = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_TRUE(parser.header().fin);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Text);
    EXPECT_FALSE(parser.header().masked);
    EXPECT_EQ(parser.header().payload_length, 5);
    EXPECT_EQ(parser.header().header_size, 2);
}

TEST(WsFrameParserTest, ParseMaskedFrame) {
    // FIN=1, opcode=1 (text), mask=1, length=5, mask key=0x12345678
    std::array<uint8_t, 11> frame = {
        0x81, 0x85,                     // FIN, Text, Mask, Len=5
        0x12, 0x34, 0x56, 0x78,         // Mask key
        'H' ^ 0x12, 'e' ^ 0x34, 'l' ^ 0x56, 'l' ^ 0x78, 'o' ^ 0x12
    };
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_TRUE(parser.header().fin);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Text);
    EXPECT_TRUE(parser.header().masked);
    EXPECT_EQ(parser.header().payload_length, 5);
    EXPECT_EQ(parser.header().header_size, 6);
    EXPECT_EQ(parser.header().masking_key[0], 0x12);
    EXPECT_EQ(parser.header().masking_key[1], 0x34);
    EXPECT_EQ(parser.header().masking_key[2], 0x56);
    EXPECT_EQ(parser.header().masking_key[3], 0x78);
}

TEST(WsFrameParserTest, Parse16BitLength) {
    // Length = 256 (uses 16-bit extended length)
    std::array<uint8_t, 4> header = {
        0x82,       // FIN, Binary
        0x7E,       // Extended 16-bit length
        0x01, 0x00  // Length = 256 (big endian)
    };
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(header.data()), header.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Binary);
    EXPECT_EQ(parser.header().payload_length, 256);
    EXPECT_EQ(parser.header().header_size, 4);
}

TEST(WsFrameParserTest, Parse64BitLength) {
    // Length = 70000 (uses 64-bit extended length)
    std::array<uint8_t, 10> header = {
        0x82,       // FIN, Binary
        0x7F,       // Extended 64-bit length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70  // 70000 big endian
    };
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(header.data()), header.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_EQ(parser.header().payload_length, 70000);
    EXPECT_EQ(parser.header().header_size, 10);
}

TEST(WsFrameParserTest, ParseControlFrame) {
    // Ping frame with 5 bytes payload
    std::array<uint8_t, 7> frame = {0x89, 0x05, 'h', 'e', 'l', 'l', 'o'};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Ping);
    EXPECT_TRUE(parser.header().fin);
}

TEST(WsFrameParserTest, ParseContinuationFrame) {
    // FIN=0, opcode=0 (continuation)
    std::array<uint8_t, 5> frame = {0x00, 0x03, 'a', 'b', 'c'};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_FALSE(parser.header().fin);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Continuation);
}

TEST(WsFrameParserTest, NeedMoreData) {
    // Incomplete header
    std::array<uint8_t, 1> frame = {0x81};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::NeedMoreData);
}

TEST(WsFrameParserTest, InvalidOpcode) {
    // Invalid opcode 0x03
    std::array<uint8_t, 2> frame = {0x83, 0x00};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::InvalidOpcode);
}

TEST(WsFrameParserTest, ReservedBitSet) {
    // RSV1 set without extension
    std::array<uint8_t, 2> frame = {0xC1, 0x00};  // FIN=1, RSV1=1, Text
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::ReservedBitSet);
}

TEST(WsFrameParserTest, AllowReservedBit) {
    // RSV1 set with extension allowed
    std::array<uint8_t, 2> frame = {0xC1, 0x00};  // FIN=1, RSV1=1, Text
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    parser.allow_rsv_bits(true);
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::Complete);
    EXPECT_TRUE(parser.header().rsv1);
}

TEST(WsFrameParserTest, ControlFrameTooBig) {
    // Ping with 126 bytes (over 125 limit)
    std::array<uint8_t, 4> frame = {0x89, 0x7E, 0x00, 0x7E};  // Length=126
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::ControlFrameTooBig);
}

TEST(WsFrameParserTest, ControlFrameFragmented) {
    // Ping with FIN=0 (fragmented, not allowed)
    std::array<uint8_t, 2> frame = {0x09, 0x00};  // FIN=0, Ping
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    auto result = parser.parse_header(data);

    EXPECT_EQ(result, WsParseResult::ControlFrameFragmented);
}

TEST(WsFrameParserTest, Reset) {
    std::array<uint8_t, 2> frame = {0x81, 0x05};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(frame.data()), frame.size());

    WsFrameParser parser;
    parser.parse_header(data);
    parser.reset();

    EXPECT_EQ(parser.header().payload_length, 0);
    EXPECT_EQ(parser.header().opcode, WsOpcode::Continuation);
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame Builder Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsFrameBuilderTest, BuildMinimalHeader) {
    WsFrameBuilder builder;
    auto header = builder.build_header(WsOpcode::Text, 5, true, false);

    EXPECT_EQ(header.size(), 2);
    auto bytes = reinterpret_cast<const uint8_t*>(header.data());
    EXPECT_EQ(bytes[0], 0x81);  // FIN=1, Text
    EXPECT_EQ(bytes[1], 0x05);  // No mask, Length=5
}

TEST(WsFrameBuilderTest, BuildMaskedHeader) {
    WsFrameBuilder builder;
    std::array<uint8_t, 4> mask = {0x12, 0x34, 0x56, 0x78};
    auto header = builder.build_header(WsOpcode::Binary, 10, true, true, mask);

    EXPECT_EQ(header.size(), 6);
    auto bytes = reinterpret_cast<const uint8_t*>(header.data());
    EXPECT_EQ(bytes[0], 0x82);  // FIN=1, Binary
    EXPECT_EQ(bytes[1], 0x8A);  // Mask=1, Length=10
    EXPECT_EQ(bytes[2], 0x12);
    EXPECT_EQ(bytes[3], 0x34);
    EXPECT_EQ(bytes[4], 0x56);
    EXPECT_EQ(bytes[5], 0x78);
}

TEST(WsFrameBuilderTest, Build16BitLengthHeader) {
    WsFrameBuilder builder;
    auto header = builder.build_header(WsOpcode::Binary, 256, true, false);

    EXPECT_EQ(header.size(), 4);
    auto bytes = reinterpret_cast<const uint8_t*>(header.data());
    EXPECT_EQ(bytes[0], 0x82);  // FIN=1, Binary
    EXPECT_EQ(bytes[1], 0x7E);  // 16-bit length marker
    EXPECT_EQ(bytes[2], 0x01);  // 256 >> 8
    EXPECT_EQ(bytes[3], 0x00);  // 256 & 0xFF
}

TEST(WsFrameBuilderTest, Build64BitLengthHeader) {
    WsFrameBuilder builder;
    auto header = builder.build_header(WsOpcode::Binary, 70000, true, false);

    EXPECT_EQ(header.size(), 10);
    auto bytes = reinterpret_cast<const uint8_t*>(header.data());
    EXPECT_EQ(bytes[0], 0x82);  // FIN=1, Binary
    EXPECT_EQ(bytes[1], 0x7F);  // 64-bit length marker
}

TEST(WsFrameBuilderTest, BuildClosePayload) {
    WsFrameBuilder builder;
    auto payload = builder.build_close_payload(WsCloseCode::Normal, "goodbye");

    EXPECT_EQ(payload.size(), 9);  // 2 bytes code + 7 bytes reason
    auto bytes = reinterpret_cast<const uint8_t*>(payload.data());
    EXPECT_EQ(bytes[0], 0x03);  // 1000 >> 8
    EXPECT_EQ(bytes[1], 0xE8);  // 1000 & 0xFF
    EXPECT_EQ(bytes[2], 'g');
}

TEST(WsFrameBuilderTest, BuildCompleteFrame) {
    WsFrameBuilder builder;
    std::vector<std::byte> output(100);
    std::array<uint8_t, 4> mask = {0x00, 0x00, 0x00, 0x00};  // Zero mask for easy testing
    std::array<std::byte, 5> payload;
    std::memcpy(payload.data(), "Hello", 5);

    size_t written = builder.build_frame(output, WsOpcode::Text, payload, true, mask, true);

    EXPECT_EQ(written, 11);  // 2 + 4 (mask) + 5 (payload)
}

TEST(WsFrameBuilderTest, FrameSizeCalculation) {
    // Small payload without mask
    EXPECT_EQ(WsFrameBuilder::frame_size(100, false), 102);  // 2 + 100

    // Small payload with mask
    EXPECT_EQ(WsFrameBuilder::frame_size(100, true), 106);  // 2 + 4 + 100

    // Medium payload (16-bit length)
    EXPECT_EQ(WsFrameBuilder::frame_size(256, false), 260);  // 4 + 256

    // Large payload (64-bit length)
    EXPECT_EQ(WsFrameBuilder::frame_size(70000, false), 70010);  // 10 + 70000
}

// ═══════════════════════════════════════════════════════════════════════════
// Masking Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsMaskingTest, GenerateMaskKey) {
    auto key1 = generate_masking_key();
    auto key2 = generate_masking_key();

    // Keys should be different (with very high probability)
    EXPECT_NE(key1, key2);
}

TEST(WsMaskingTest, ApplyMaskInplace) {
    std::array<uint8_t, 4> mask = {0x12, 0x34, 0x56, 0x78};
    std::vector<std::byte> data(8);
    std::memset(data.data(), 0, data.size());

    apply_mask_inplace(data, mask);

    // After masking zeros, we should get the mask pattern repeated
    auto bytes = reinterpret_cast<uint8_t*>(data.data());
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0x56);
    EXPECT_EQ(bytes[3], 0x78);
    EXPECT_EQ(bytes[4], 0x12);
    EXPECT_EQ(bytes[5], 0x34);
    EXPECT_EQ(bytes[6], 0x56);
    EXPECT_EQ(bytes[7], 0x78);
}

TEST(WsMaskingTest, DoubleMaskRestoresOriginal) {
    std::array<uint8_t, 4> mask = {0xAB, 0xCD, 0xEF, 0x12};
    std::vector<std::byte> data(100);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(i);
    }

    auto original = data;

    // Mask and unmask
    apply_mask_inplace(data, mask);
    apply_mask_inplace(data, mask);

    EXPECT_EQ(data, original);
}

// ═══════════════════════════════════════════════════════════════════════════
// Close Payload Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsClosePayloadTest, ParseEmpty) {
    std::span<const std::byte> empty;
    auto info = parse_close_payload(empty);

    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.code, WsCloseCode::NoStatus);
    EXPECT_TRUE(info.reason.empty());
}

TEST(WsClosePayloadTest, ParseCodeOnly) {
    std::array<uint8_t, 2> payload = {0x03, 0xE8};  // 1000
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(payload.data()), payload.size());

    auto info = parse_close_payload(data);

    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.code, WsCloseCode::Normal);
    EXPECT_TRUE(info.reason.empty());
}

TEST(WsClosePayloadTest, ParseCodeAndReason) {
    std::array<uint8_t, 9> payload = {0x03, 0xE8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(payload.data()), payload.size());

    auto info = parse_close_payload(data);

    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.code, WsCloseCode::Normal);
    EXPECT_EQ(info.reason, "goodbye");
}

TEST(WsClosePayloadTest, ParseInvalidTooShort) {
    std::array<uint8_t, 1> payload = {0x03};
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(payload.data()), payload.size());

    auto info = parse_close_payload(data);

    EXPECT_FALSE(info.valid);
}

TEST(WsClosePayloadTest, ParseInvalidCode) {
    std::array<uint8_t, 2> payload = {0x03, 0xED};  // 1005 (reserved)
    std::span<const std::byte> data(reinterpret_cast<std::byte*>(payload.data()), payload.size());

    auto info = parse_close_payload(data);

    EXPECT_FALSE(info.valid);
}

// ═══════════════════════════════════════════════════════════════════════════
// Handshake Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsHandshakeTest, GenerateKey) {
    auto key1 = generate_websocket_key();
    auto key2 = generate_websocket_key();

    // Base64 encoded 16 bytes = 24 characters
    EXPECT_EQ(key1.size(), 24);
    EXPECT_EQ(key2.size(), 24);

    // Keys should be different
    EXPECT_NE(key1, key2);
}

TEST(WsHandshakeTest, ComputeAcceptKey) {
    // Test vector from RFC 6455 Section 1.2
    std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    std::string expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    auto accept = compute_accept_key(client_key);

    EXPECT_EQ(accept, expected);
}

TEST(WsHandshakeTest, BuildHandshakeRequest) {
    WsHandshakeConfig config;
    config.host = "example.com";
    config.path = "/ws";
    config.port = 443;
    config.subprotocols = {"graphql-ws"};

    std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
    auto request = build_handshake_request(config, key);

    EXPECT_TRUE(request.find("GET /ws HTTP/1.1\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Host: example.com\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Upgrade: websocket\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Connection: Upgrade\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Sec-WebSocket-Key: " + key + "\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Sec-WebSocket-Version: 13\r\n") != std::string::npos);
    EXPECT_TRUE(request.find("Sec-WebSocket-Protocol: graphql-ws\r\n") != std::string::npos);
    EXPECT_TRUE(request.ends_with("\r\n\r\n"));
}

TEST(WsHandshakeTest, ParseHttpResponse) {
    std::string response_str =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "\r\n";

    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(response_str.data()),
        response_str.size());

    auto response = parse_http_response(data);

    EXPECT_TRUE(response.complete);
    EXPECT_EQ(response.status_code, 101);
    EXPECT_EQ(response.status_text, "Switching Protocols");
    EXPECT_EQ(response.headers.get("upgrade").value_or(""), "websocket");
    EXPECT_EQ(response.headers.get("connection").value_or(""), "Upgrade");
    EXPECT_EQ(response.headers.get("sec-websocket-accept").value_or(""),
              "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(WsHandshakeTest, ValidateHandshakeResponse) {
    HttpResponse response;
    response.status_code = 101;
    response.headers.add("Upgrade", "websocket");
    response.headers.add("Connection", "Upgrade");
    response.headers.add("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    auto result = validate_handshake_response(response, client_key);

    EXPECT_EQ(result, HandshakeResult::Success);
}

TEST(WsHandshakeTest, ValidateHandshakeNotHttp101) {
    HttpResponse response;
    response.status_code = 200;

    auto result = validate_handshake_response(response, "key");

    EXPECT_EQ(result, HandshakeResult::NotHttp101);
}

TEST(WsHandshakeTest, ValidateHandshakeMissingUpgrade) {
    HttpResponse response;
    response.status_code = 101;
    response.headers.add("Connection", "Upgrade");

    auto result = validate_handshake_response(response, "key");

    EXPECT_EQ(result, HandshakeResult::MissingUpgrade);
}

TEST(WsHandshakeTest, ValidateHandshakeInvalidAccept) {
    HttpResponse response;
    response.status_code = 101;
    response.headers.add("Upgrade", "websocket");
    response.headers.add("Connection", "Upgrade");
    response.headers.add("Sec-WebSocket-Accept", "wrong-value");

    auto result = validate_handshake_response(response, "dGhlIHNhbXBsZSBub25jZQ==");

    EXPECT_EQ(result, HandshakeResult::InvalidAccept);
}

TEST(WsHandshakeTest, HttpHeadersCaseInsensitive) {
    HttpHeaders headers;
    headers.add("Content-Type", "application/json");
    headers.add("X-Custom-Header", "value");

    EXPECT_EQ(headers.get("content-type").value_or(""), "application/json");
    EXPECT_EQ(headers.get("CONTENT-TYPE").value_or(""), "application/json");
    EXPECT_EQ(headers.get("Content-Type").value_or(""), "application/json");
    EXPECT_EQ(headers.get("x-custom-header").value_or(""), "value");
}

TEST(WsHandshakeTest, HttpHeadersContainsValue) {
    HttpHeaders headers;
    headers.add("Connection", "keep-alive, Upgrade");

    EXPECT_TRUE(headers.contains_value("Connection", "Upgrade"));
    EXPECT_TRUE(headers.contains_value("Connection", "keep-alive"));
    EXPECT_FALSE(headers.contains_value("Connection", "close"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Handshake State Machine Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(WsHandshakeStateMachineTest, InitAndGetRequest) {
    WsHandshakeConfig config;
    config.host = "echo.websocket.org";
    config.path = "/";
    config.port = 443;

    WsHandshake handshake;
    handshake.init(config);

    auto request = handshake.request();
    EXPECT_FALSE(request.empty());
    EXPECT_TRUE(request.find("GET / HTTP/1.1\r\n") != std::string::npos);
    EXPECT_FALSE(handshake.key().empty());
}

TEST(WsHandshakeStateMachineTest, FeedCompleteResponse) {
    WsHandshakeConfig config;
    config.host = "example.com";
    config.path = "/";

    WsHandshake handshake;
    handshake.init(config);

    // Get the key that was generated
    std::string key(handshake.key());

    // Build the expected accept value
    std::string accept = compute_accept_key(key);

    // Simulate server response
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "\r\n";

    handshake.request_sent();
    bool complete = handshake.feed({
        reinterpret_cast<const std::byte*>(response.data()),
        response.size()
    });

    EXPECT_TRUE(complete);
    EXPECT_TRUE(handshake.success());
    EXPECT_EQ(handshake.result(), HandshakeResult::Success);
}

TEST(WsHandshakeStateMachineTest, FeedIncrementalResponse) {
    WsHandshakeConfig config;
    config.host = "example.com";
    config.path = "/";

    WsHandshake handshake;
    handshake.init(config);

    std::string key(handshake.key());
    std::string accept = compute_accept_key(key);

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "\r\n";

    handshake.request_sent();

    // Feed in chunks
    bool complete = handshake.feed({
        reinterpret_cast<const std::byte*>(response.data()),
        20  // First 20 bytes
    });
    EXPECT_FALSE(complete);

    complete = handshake.feed({
        reinterpret_cast<const std::byte*>(response.data() + 20),
        response.size() - 20  // Rest
    });
    EXPECT_TRUE(complete);
    EXPECT_TRUE(handshake.success());
}

TEST(WsHandshakeStateMachineTest, RemainingDataAfterHandshake) {
    WsHandshakeConfig config;
    config.host = "example.com";
    config.path = "/";

    WsHandshake handshake;
    handshake.init(config);

    std::string key(handshake.key());
    std::string accept = compute_accept_key(key);

    // Response with some WebSocket data after headers
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "\r\n"
        "\x81\x05Hello";  // A WebSocket text frame

    handshake.request_sent();
    handshake.feed({
        reinterpret_cast<const std::byte*>(response.data()),
        response.size()
    });

    EXPECT_TRUE(handshake.success());

    auto remaining = handshake.remaining_data();
    EXPECT_EQ(remaining.size(), 7);  // The WebSocket frame
}
