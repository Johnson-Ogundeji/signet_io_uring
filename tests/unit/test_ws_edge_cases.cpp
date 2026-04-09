// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file test_ws_edge_cases.cpp
/// @brief Comprehensive tests for WebSocket edge cases
///
/// Tests all 11 critical edge cases:
/// 1. Fragmented messages
/// 2. Interleaved control frames
/// 3. Close handshake
/// 4. Ping/Pong handling
/// 5. UTF-8 validation
/// 6. Maximum message size
/// 7. Maximum frame size
/// 8. Reserved bits
/// 9. Masking validation
/// 10. Protocol violations
/// 11. Connection state management

#include <signet/ws/ws_validator.hpp>
#include <signet/ws/ws_frame.hpp>
#include <gtest/gtest.h>

#include <vector>
#include <string>

using namespace signet;

// ═══════════════════════════════════════════════════════════════════════════
// UTF-8 Validator Tests
// ═══════════════════════════════════════════════════════════════════════════

class Utf8ValidatorTest : public ::testing::Test {
protected:
    Utf8StreamValidator validator;
};

TEST_F(Utf8ValidatorTest, ValidAscii) {
    std::string text = "Hello, World!";
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(text.data()), text.size());

    EXPECT_TRUE(validator.validate(data));
    EXPECT_TRUE(validator.is_complete());
}

TEST_F(Utf8ValidatorTest, ValidMultibyte) {
    // "Hello" in various scripts
    std::string text = "Hello 世界 مرحبا Привет";
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(text.data()), text.size());

    EXPECT_TRUE(validator.validate(data));
    EXPECT_TRUE(validator.is_complete());
}

TEST_F(Utf8ValidatorTest, ValidEmoji) {
    std::string text = "Hello 🌍🎉👍";
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(text.data()), text.size());

    EXPECT_TRUE(validator.validate(data));
    EXPECT_TRUE(validator.is_complete());
}

TEST_F(Utf8ValidatorTest, Invalid_OverlongEncoding) {
    // Overlong encoding of 'A' (should be 0x41, not 0xC1 0x81)
    std::array<uint8_t, 2> data = {0xC0, 0x80};
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    EXPECT_FALSE(validator.validate(span));
}

TEST_F(Utf8ValidatorTest, Invalid_TruncatedSequence) {
    // Start of 3-byte sequence without continuation
    std::array<uint8_t, 1> data = {0xE0};
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    EXPECT_TRUE(validator.validate(span));  // Partial is ok
    EXPECT_FALSE(validator.is_complete());  // But not complete
}

TEST_F(Utf8ValidatorTest, Invalid_Surrogate) {
    // UTF-8 encoding of surrogate U+D800 (invalid)
    std::array<uint8_t, 3> data = {0xED, 0xA0, 0x80};
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    EXPECT_FALSE(validator.validate(span));
}

TEST_F(Utf8ValidatorTest, Invalid_BeyondUnicode) {
    // Encoding beyond U+10FFFF
    std::array<uint8_t, 4> data = {0xF4, 0x90, 0x80, 0x80};
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    EXPECT_FALSE(validator.validate(span));
}

TEST_F(Utf8ValidatorTest, Invalid_BadContinuation) {
    // Valid lead byte followed by invalid continuation
    std::array<uint8_t, 2> data = {0xC2, 0x00};  // 0x00 is not valid continuation
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    EXPECT_FALSE(validator.validate(span));
}

TEST_F(Utf8ValidatorTest, StreamingValidation) {
    // Validate in chunks
    std::string text = "Hello 世界";

    // Feed one byte at a time
    for (size_t i = 0; i < text.size(); ++i) {
        std::span<const std::byte> chunk(
            reinterpret_cast<const std::byte*>(text.data() + i), 1);
        EXPECT_TRUE(validator.validate(chunk)) << "Failed at byte " << i;
    }

    EXPECT_TRUE(validator.is_complete());
}

TEST_F(Utf8ValidatorTest, Reset) {
    // Start with truncated sequence
    std::array<uint8_t, 1> data = {0xE0};
    std::span<const std::byte> span(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    (void)validator.validate(span);
    EXPECT_FALSE(validator.is_complete());

    validator.reset();
    EXPECT_TRUE(validator.is_complete());
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame Validator Tests
// ═══════════════════════════════════════════════════════════════════════════

class FrameValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default client configuration
        WsValidatorConfig config;
        config.is_client = true;
        validator = std::make_unique<WsFrameValidator>(config);
    }

    std::unique_ptr<WsFrameValidator> validator;
};

TEST_F(FrameValidatorTest, ValidTextFrame) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = false;  // Server to client
    header.payload_length = 100;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::None);
}

TEST_F(FrameValidatorTest, InvalidOpcode) {
    FrameHeader header;
    header.fin = true;
    header.opcode = static_cast<Opcode>(0x03);  // Reserved
    header.masked = false;
    header.payload_length = 0;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::InvalidOpcode);
}

TEST_F(FrameValidatorTest, ReservedBitWithoutExtension) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.rsv1 = true;  // RSV1 set
    header.masked = false;
    header.payload_length = 0;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::ReservedBitWithoutExtension);
}

TEST_F(FrameValidatorTest, ReservedBitWithExtension) {
    // Allow RSV bits
    WsValidatorConfig config;
    config.is_client = true;
    config.allow_rsv_bits = true;
    validator = std::make_unique<WsFrameValidator>(config);

    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.rsv1 = true;
    header.masked = false;
    header.payload_length = 0;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::None);
}

TEST_F(FrameValidatorTest, ServerMaskedFrame_Invalid) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = true;  // Server should NOT mask
    header.payload_length = 0;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::ServerFrameMasked);
}

TEST_F(FrameValidatorTest, ClientUnmaskedFrame_Invalid) {
    // Configure as server
    WsValidatorConfig config;
    config.is_client = false;  // We are server
    validator = std::make_unique<WsFrameValidator>(config);

    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = false;  // Client MUST mask
    header.payload_length = 0;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::ClientFrameUnmasked);
}

TEST_F(FrameValidatorTest, ControlFrameTooBig) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Ping;
    header.masked = false;
    header.payload_length = 126;  // > 125 limit

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::ControlFrameTooBig);
}

TEST_F(FrameValidatorTest, FragmentedControlFrame) {
    FrameHeader header;
    header.fin = false;  // Control frame MUST have FIN
    header.opcode = Opcode::Ping;
    header.masked = false;
    header.payload_length = 10;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::FragmentedControlFrame);
}

TEST_F(FrameValidatorTest, ContinuationWithoutStart) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Continuation;
    header.masked = false;
    header.payload_length = 10;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::ContinuationWithoutStart);
}

TEST_F(FrameValidatorTest, FragmentedMessage_Valid) {
    // First fragment
    FrameHeader header1;
    header1.fin = false;  // Not final
    header1.opcode = Opcode::Text;
    header1.masked = false;
    header1.payload_length = 100;

    auto v1 = validator->validate_header(header1);
    EXPECT_EQ(v1, WsViolation::None);
    validator->update_fragment_state(header1);

    EXPECT_TRUE(validator->in_fragment());

    // Continuation
    FrameHeader header2;
    header2.fin = false;
    header2.opcode = Opcode::Continuation;
    header2.masked = false;
    header2.payload_length = 100;

    auto v2 = validator->validate_header(header2);
    EXPECT_EQ(v2, WsViolation::None);
    validator->update_fragment_state(header2);

    // Final fragment
    FrameHeader header3;
    header3.fin = true;
    header3.opcode = Opcode::Continuation;
    header3.masked = false;
    header3.payload_length = 100;

    auto v3 = validator->validate_header(header3);
    EXPECT_EQ(v3, WsViolation::None);
    validator->update_fragment_state(header3);

    EXPECT_FALSE(validator->in_fragment());
}

TEST_F(FrameValidatorTest, InterleavedControlFrame) {
    // Start fragmented text message
    FrameHeader text1;
    text1.fin = false;
    text1.opcode = Opcode::Text;
    text1.masked = false;
    text1.payload_length = 100;

    (void)validator->validate_header(text1);
    validator->update_fragment_state(text1);

    // Control frame in the middle (valid!)
    FrameHeader ping;
    ping.fin = true;
    ping.opcode = Opcode::Ping;
    ping.masked = false;
    ping.payload_length = 5;

    auto v = validator->validate_header(ping);
    EXPECT_EQ(v, WsViolation::None);
    validator->update_fragment_state(ping);

    // Fragment state should be unchanged
    EXPECT_TRUE(validator->in_fragment());
    EXPECT_EQ(validator->fragment_opcode(), Opcode::Text);

    // Continue with text
    FrameHeader text2;
    text2.fin = true;
    text2.opcode = Opcode::Continuation;
    text2.masked = false;
    text2.payload_length = 100;

    auto v2 = validator->validate_header(text2);
    EXPECT_EQ(v2, WsViolation::None);
}

TEST_F(FrameValidatorTest, NewMessageDuringFragment) {
    // Start fragmented message
    FrameHeader text1;
    text1.fin = false;
    text1.opcode = Opcode::Text;
    text1.masked = false;
    text1.payload_length = 100;

    (void)validator->validate_header(text1);
    validator->update_fragment_state(text1);

    // Try to start new message (invalid!)
    FrameHeader binary;
    binary.fin = false;
    binary.opcode = Opcode::Binary;
    binary.masked = false;
    binary.payload_length = 100;

    auto v = validator->validate_header(binary);
    EXPECT_EQ(v, WsViolation::NewMessageDuringFragment);
}

TEST_F(FrameValidatorTest, FrameTooLarge) {
    WsValidatorConfig config;
    config.is_client = true;
    config.max_frame_size = 1000;
    validator = std::make_unique<WsFrameValidator>(config);

    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Binary;
    header.masked = false;
    header.payload_length = 1001;

    auto violation = validator->validate_header(header);
    EXPECT_EQ(violation, WsViolation::FrameTooLarge);
}

// ═══════════════════════════════════════════════════════════════════════════
// Close Validation Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(FrameValidatorTest, ValidClosePayload_Empty) {
    std::span<const std::byte> empty;
    auto v = validator->validate_close_payload(empty);
    EXPECT_EQ(v, WsViolation::None);
}

TEST_F(FrameValidatorTest, ValidClosePayload_CodeOnly) {
    std::array<uint8_t, 2> payload = {0x03, 0xE8};  // 1000
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());

    auto v = validator->validate_close_payload(data);
    EXPECT_EQ(v, WsViolation::None);
}

TEST_F(FrameValidatorTest, ValidClosePayload_WithReason) {
    std::vector<uint8_t> payload = {0x03, 0xE8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'};
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());

    auto v = validator->validate_close_payload(data);
    EXPECT_EQ(v, WsViolation::None);
}

TEST_F(FrameValidatorTest, InvalidClosePayload_TooShort) {
    std::array<uint8_t, 1> payload = {0x03};
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());

    auto v = validator->validate_close_payload(data);
    EXPECT_EQ(v, WsViolation::ClosePayloadTooShort);
}

TEST_F(FrameValidatorTest, InvalidClosePayload_ReservedCode) {
    std::array<uint8_t, 2> payload = {0x03, 0xED};  // 1005 - reserved
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());

    auto v = validator->validate_close_payload(data);
    EXPECT_EQ(v, WsViolation::InvalidCloseCode);
}

TEST_F(FrameValidatorTest, InvalidClosePayload_BadUtf8Reason) {
    std::vector<uint8_t> payload = {0x03, 0xE8, 0x80, 0x80};  // Invalid UTF-8
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(payload.data()), payload.size());

    auto v = validator->validate_close_payload(data);
    EXPECT_EQ(v, WsViolation::InvalidUtf8InCloseReason);
}

// ═══════════════════════════════════════════════════════════════════════════
// Close State Machine Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(CloseStateMachineTest, InitialState) {
    WsCloseStateMachine sm;

    EXPECT_EQ(sm.state(), CloseState::Open);
    EXPECT_TRUE(sm.can_send_data());
    EXPECT_TRUE(sm.can_receive_data());
    EXPECT_FALSE(sm.needs_close_response());
    EXPECT_FALSE(sm.is_closed());
}

TEST(CloseStateMachineTest, ClientInitiatedClose) {
    WsCloseStateMachine sm;

    // Client sends close
    sm.close_sent(CloseCode::Normal, "goodbye");
    EXPECT_EQ(sm.state(), CloseState::CloseSent);
    EXPECT_FALSE(sm.can_send_data());
    EXPECT_TRUE(sm.can_receive_data());  // Can still receive response

    // Server responds
    sm.close_received(CloseCode::Normal);
    EXPECT_EQ(sm.state(), CloseState::Closed);
    EXPECT_FALSE(sm.can_send_data());
    EXPECT_FALSE(sm.can_receive_data());
    EXPECT_TRUE(sm.is_closed());
}

TEST(CloseStateMachineTest, ServerInitiatedClose) {
    WsCloseStateMachine sm;

    // Server sends close
    sm.close_received(CloseCode::GoingAway, "server shutting down");
    EXPECT_EQ(sm.state(), CloseState::CloseReceived);
    EXPECT_TRUE(sm.needs_close_response());
    EXPECT_EQ(sm.received_code(), CloseCode::GoingAway);

    // Client responds
    sm.close_sent(CloseCode::GoingAway);
    EXPECT_EQ(sm.state(), CloseState::Closed);
    EXPECT_TRUE(sm.is_closed());
}

TEST(CloseStateMachineTest, Reset) {
    WsCloseStateMachine sm;

    sm.close_sent(CloseCode::Normal);
    sm.close_received(CloseCode::Normal);
    EXPECT_TRUE(sm.is_closed());

    sm.reset();
    EXPECT_EQ(sm.state(), CloseState::Open);
    EXPECT_TRUE(sm.can_send_data());
}

// ═══════════════════════════════════════════════════════════════════════════
// Protocol Validator Tests
// ═══════════════════════════════════════════════════════════════════════════

class ProtocolValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        WsValidatorConfig config;
        config.is_client = true;
        validator = std::make_unique<WsProtocolValidator>(config);
    }

    std::unique_ptr<WsProtocolValidator> validator;
};

TEST_F(ProtocolValidatorTest, ValidTextFrame) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = false;
    header.payload_length = 5;

    std::string text = "hello";
    std::span<const std::byte> payload(
        reinterpret_cast<const std::byte*>(text.data()), text.size());

    auto result = validator->validate_frame(header, payload);
    EXPECT_TRUE(result.ok());
}

TEST_F(ProtocolValidatorTest, InvalidUtf8Text) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = false;
    header.payload_length = 2;

    std::array<uint8_t, 2> invalid = {0x80, 0x80};  // Invalid UTF-8
    std::span<const std::byte> payload(
        reinterpret_cast<const std::byte*>(invalid.data()), invalid.size());

    auto result = validator->validate_frame(header, payload);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.violation, WsViolation::InvalidUtf8InTextFrame);
}

TEST_F(ProtocolValidatorTest, CloseFrame) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Close;
    header.masked = false;
    header.payload_length = 2;

    std::array<uint8_t, 2> close_payload = {0x03, 0xE8};  // 1000
    std::span<const std::byte> payload(
        reinterpret_cast<const std::byte*>(close_payload.data()), close_payload.size());

    auto result = validator->validate_frame(header, payload);
    EXPECT_TRUE(result.ok());
    EXPECT_TRUE(validator->needs_close_response());
    EXPECT_EQ(validator->received_close_code(), CloseCode::Normal);
}

TEST_F(ProtocolValidatorTest, DataAfterClose) {
    // Receive close
    FrameHeader close_header;
    close_header.fin = true;
    close_header.opcode = Opcode::Close;
    close_header.masked = false;
    close_header.payload_length = 0;

    (void)validator->validate_frame(close_header, {});

    // Send our close response
    validator->sending_close(CloseCode::Normal);
    EXPECT_TRUE(validator->is_closed());

    // Try to validate data frame after close
    FrameHeader data_header;
    data_header.fin = true;
    data_header.opcode = Opcode::Text;
    data_header.masked = false;
    data_header.payload_length = 0;

    auto result = validator->validate_frame(data_header, {});
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.violation, WsViolation::CloseAfterClose);
}

TEST_F(ProtocolValidatorTest, FragmentedTextWithUtf8) {
    // First fragment with incomplete UTF-8
    FrameHeader header1;
    header1.fin = false;
    header1.opcode = Opcode::Text;
    header1.masked = false;
    header1.payload_length = 4;

    // "Hel" + first byte of 2-byte UTF-8
    std::array<uint8_t, 4> frag1 = {'H', 'e', 'l', 0xC3};
    std::span<const std::byte> payload1(
        reinterpret_cast<const std::byte*>(frag1.data()), frag1.size());

    auto result1 = validator->validate_frame(header1, payload1);
    EXPECT_TRUE(result1.ok()) << result1.description;

    // Second fragment completing UTF-8
    FrameHeader header2;
    header2.fin = true;
    header2.opcode = Opcode::Continuation;
    header2.masked = false;
    header2.payload_length = 2;

    // Second byte of UTF-8 + 'o'
    std::array<uint8_t, 2> frag2 = {0xB3, 'o'};  // Completes 'ó'
    std::span<const std::byte> payload2(
        reinterpret_cast<const std::byte*>(frag2.data()), frag2.size());

    auto result2 = validator->validate_frame(header2, payload2);
    EXPECT_TRUE(result2.ok()) << result2.description;
}

TEST_F(ProtocolValidatorTest, TruncatedUtf8AtEnd) {
    FrameHeader header;
    header.fin = true;
    header.opcode = Opcode::Text;
    header.masked = false;
    header.payload_length = 4;

    // "Hel" + first byte of 2-byte UTF-8 (truncated!)
    std::array<uint8_t, 4> data = {'H', 'e', 'l', 0xC3};
    std::span<const std::byte> payload(
        reinterpret_cast<const std::byte*>(data.data()), data.size());

    auto result = validator->validate_frame(header, payload);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.violation, WsViolation::TruncatedUtf8Sequence);
}

// ═══════════════════════════════════════════════════════════════════════════
// Violation to Close Code Mapping Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(ViolationMappingTest, ProtocolErrors) {
    EXPECT_EQ(violation_to_close_code(WsViolation::InvalidOpcode), CloseCode::ProtocolError);
    EXPECT_EQ(violation_to_close_code(WsViolation::FragmentedControlFrame), CloseCode::ProtocolError);
    EXPECT_EQ(violation_to_close_code(WsViolation::ContinuationWithoutStart), CloseCode::ProtocolError);
}

TEST(ViolationMappingTest, InvalidPayload) {
    EXPECT_EQ(violation_to_close_code(WsViolation::InvalidUtf8InTextFrame), CloseCode::InvalidPayload);
    EXPECT_EQ(violation_to_close_code(WsViolation::InvalidUtf8InCloseReason), CloseCode::InvalidPayload);
    EXPECT_EQ(violation_to_close_code(WsViolation::TruncatedUtf8Sequence), CloseCode::InvalidPayload);
}

TEST(ViolationMappingTest, MessageTooBig) {
    EXPECT_EQ(violation_to_close_code(WsViolation::MessageTooLarge), CloseCode::MessageTooBig);
    EXPECT_EQ(violation_to_close_code(WsViolation::FrameTooLarge), CloseCode::MessageTooBig);
}

// ═══════════════════════════════════════════════════════════════════════════
// Message Size Validation Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(MessageSizeTest, WithinLimit) {
    WsValidatorConfig config;
    config.max_message_size = 1000;
    WsFrameValidator validator(config);

    EXPECT_EQ(validator.check_message_size(500), WsViolation::None);
    EXPECT_EQ(validator.check_message_size(1000), WsViolation::None);
}

TEST(MessageSizeTest, ExceedsLimit) {
    WsValidatorConfig config;
    config.max_message_size = 1000;
    WsFrameValidator validator(config);

    EXPECT_EQ(validator.check_message_size(1001), WsViolation::MessageTooLarge);
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation Result Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(ValidationResultTest, Success) {
    auto result = ValidationResult::success();
    EXPECT_TRUE(result.ok());
    EXPECT_TRUE(static_cast<bool>(result));
    EXPECT_EQ(result.violation, WsViolation::None);
}

TEST(ValidationResultTest, Failure) {
    auto result = ValidationResult::failure(WsViolation::InvalidOpcode);
    EXPECT_FALSE(result.ok());
    EXPECT_FALSE(static_cast<bool>(result));
    EXPECT_EQ(result.violation, WsViolation::InvalidOpcode);
    EXPECT_EQ(result.suggested_close_code, CloseCode::ProtocolError);
}
