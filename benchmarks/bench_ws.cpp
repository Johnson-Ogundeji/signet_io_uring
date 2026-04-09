// Signet WebSocket Benchmarks
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>
#include <signet/ws/ws_frame.hpp>
#include <signet/ws/ws_handshake.hpp>
#include <signet/ws/ws_validator.hpp>
#include <signet/ws/ws_extension.hpp>

#include <array>
#include <random>
#include <string>
#include <vector>

using namespace signet;

// Type alias for masking key
using MaskKey = std::array<uint8_t, 4>;

// ═══════════════════════════════════════════════════════════════════════════
// Frame Parsing Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Parse small text frame header (2 bytes)
static void BM_ParseSmallFrameHeader(benchmark::State& state) {
    // FIN + Text, length 13 (no mask)
    std::vector<std::byte> frame = {
        std::byte{0x81}, std::byte{0x0D}  // FIN=1, opcode=1, len=13
    };

    WsFrameParser parser;
    for (auto _ : state) {
        parser.reset();
        auto result = parser.parse_header(frame);
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseSmallFrameHeader);

// Parse medium frame header (4 bytes extended)
static void BM_ParseMediumFrameHeader(benchmark::State& state) {
    // FIN + Binary, length 1000 (16-bit extended)
    std::vector<std::byte> frame = {
        std::byte{0x82}, std::byte{0x7E},  // FIN=1, opcode=2, extended len
        std::byte{0x03}, std::byte{0xE8}   // 1000 in big-endian
    };

    WsFrameParser parser;
    for (auto _ : state) {
        parser.reset();
        auto result = parser.parse_header(frame);
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseMediumFrameHeader);

// Parse large frame header (10 bytes extended)
static void BM_ParseLargeFrameHeader(benchmark::State& state) {
    // FIN + Binary, length 100000 (64-bit extended)
    std::vector<std::byte> frame = {
        std::byte{0x82}, std::byte{0x7F},  // FIN=1, opcode=2, 64-bit len
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x86}, std::byte{0xA0}  // 100000
    };

    WsFrameParser parser;
    for (auto _ : state) {
        parser.reset();
        auto result = parser.parse_header(frame);
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseLargeFrameHeader);

// Parse masked client frame header
static void BM_ParseMaskedFrameHeader(benchmark::State& state) {
    std::vector<std::byte> frame = {
        std::byte{0x81}, std::byte{0x8D},  // FIN=1, opcode=1, MASK=1, len=13
        std::byte{0x37}, std::byte{0xFA}, std::byte{0x21}, std::byte{0x3D}  // masking key
    };

    WsFrameParser parser;
    for (auto _ : state) {
        parser.reset();
        auto result = parser.parse_header(frame);
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseMaskedFrameHeader);

// ═══════════════════════════════════════════════════════════════════════════
// Frame Building Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Build small text frame
static void BM_BuildSmallFrame(benchmark::State& state) {
    std::string payload = "Hello, World!";
    std::vector<std::byte> buffer(payload.size() + 14);
    WsFrameBuilder builder;
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        auto size = builder.build_frame(
            buffer, WsOpcode::Text,
            {reinterpret_cast<const std::byte*>(payload.data()), payload.size()},
            true, mask);
        benchmark::DoNotOptimize(size);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload.size()));
}
BENCHMARK(BM_BuildSmallFrame);

// Build medium frame (1KB)
static void BM_BuildMediumFrame(benchmark::State& state) {
    std::string payload(1024, 'X');
    std::vector<std::byte> buffer(payload.size() + 14);
    WsFrameBuilder builder;
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        auto size = builder.build_frame(
            buffer, WsOpcode::Binary,
            {reinterpret_cast<const std::byte*>(payload.data()), payload.size()},
            true, mask);
        benchmark::DoNotOptimize(size);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload.size()));
}
BENCHMARK(BM_BuildMediumFrame);

// Build large frame (64KB)
static void BM_BuildLargeFrame(benchmark::State& state) {
    std::string payload(65536, 'Y');
    std::vector<std::byte> buffer(payload.size() + 14);
    WsFrameBuilder builder;
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        auto size = builder.build_frame(
            buffer, WsOpcode::Binary,
            {reinterpret_cast<const std::byte*>(payload.data()), payload.size()},
            true, mask);
        benchmark::DoNotOptimize(size);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload.size()));
}
BENCHMARK(BM_BuildLargeFrame);

// Build unmasked server frame
static void BM_BuildUnmaskedFrame(benchmark::State& state) {
    std::string payload(1024, 'Z');
    std::vector<std::byte> buffer(payload.size() + 10);
    WsFrameBuilder builder;

    for (auto _ : state) {
        auto size = builder.build_frame(
            buffer, WsOpcode::Binary,
            {reinterpret_cast<const std::byte*>(payload.data()), payload.size()},
            false, {});  // No mask
        benchmark::DoNotOptimize(size);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload.size()));
}
BENCHMARK(BM_BuildUnmaskedFrame);

// ═══════════════════════════════════════════════════════════════════════════
// Masking Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Mask small payload
static void BM_MaskSmallPayload(benchmark::State& state) {
    std::vector<std::byte> data(128);
    std::fill(data.begin(), data.end(), std::byte{0x55});
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        apply_mask_inplace(data, mask);
        benchmark::DoNotOptimize(data[0]);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(data.size()));
}
BENCHMARK(BM_MaskSmallPayload);

// Mask medium payload (1KB)
static void BM_MaskMediumPayload(benchmark::State& state) {
    std::vector<std::byte> data(1024);
    std::fill(data.begin(), data.end(), std::byte{0x55});
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        apply_mask_inplace(data, mask);
        benchmark::DoNotOptimize(data[0]);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(data.size()));
}
BENCHMARK(BM_MaskMediumPayload);

// Mask large payload (64KB)
static void BM_MaskLargePayload(benchmark::State& state) {
    std::vector<std::byte> data(65536);
    std::fill(data.begin(), data.end(), std::byte{0x55});
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        apply_mask_inplace(data, mask);
        benchmark::DoNotOptimize(data[0]);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(data.size()));
}
BENCHMARK(BM_MaskLargePayload);

// Generate masking key
static void BM_GenerateMaskingKey(benchmark::State& state) {
    for (auto _ : state) {
        auto key = generate_masking_key();
        benchmark::DoNotOptimize(key);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GenerateMaskingKey);

// ═══════════════════════════════════════════════════════════════════════════
// Handshake Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Generate WebSocket key (uses OpenSSL RAND_bytes)
static void BM_GenerateWebSocketKey(benchmark::State& state) {
    for (auto _ : state) {
        auto key = generate_websocket_key();
        benchmark::DoNotOptimize(key);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GenerateWebSocketKey);

// Compute accept key (SHA-1 + base64)
static void BM_ComputeAcceptKey(benchmark::State& state) {
    std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";

    for (auto _ : state) {
        auto accept = compute_accept_key(client_key);
        benchmark::DoNotOptimize(accept);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ComputeAcceptKey);

// Build handshake request
static void BM_BuildHandshakeRequest(benchmark::State& state) {
    WsHandshakeConfig config;
    config.host = "example.com";
    config.path = "/ws/v1/stream";
    config.port = 443;
    config.subprotocols = {"json", "binary"};
    config.extensions = {"permessage-deflate"};

    std::string key = "dGhlIHNhbXBsZSBub25jZQ==";

    for (auto _ : state) {
        auto request = build_handshake_request(config, key);
        benchmark::DoNotOptimize(request);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_BuildHandshakeRequest);

// Parse HTTP response
static void BM_ParseHttpResponse(benchmark::State& state) {
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate\r\n"
        "\r\n";

    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(response.data()),
        response.size()
    };

    for (auto _ : state) {
        auto parsed = parse_http_response(data);
        benchmark::DoNotOptimize(parsed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseHttpResponse);

// ═══════════════════════════════════════════════════════════════════════════
// UTF-8 Validation Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Validate ASCII text
static void BM_ValidateUtf8Ascii(benchmark::State& state) {
    std::string text(1024, 'A');
    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(text.data()),
        text.size()
    };

    Utf8StreamValidator validator;
    for (auto _ : state) {
        validator.reset();
        (void)validator.validate(data);
        benchmark::DoNotOptimize(validator.is_complete());
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(text.size()));
}
BENCHMARK(BM_ValidateUtf8Ascii);

// Validate mixed UTF-8 (ASCII + emoji)
static void BM_ValidateUtf8Mixed(benchmark::State& state) {
    // Mix of ASCII and 4-byte emoji sequences
    std::string text;
    for (int i = 0; i < 256; ++i) {
        text += "Hello ";
        text += "\xF0\x9F\x98\x80";  // emoji (4 bytes)
    }

    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(text.data()),
        text.size()
    };

    Utf8StreamValidator validator;
    for (auto _ : state) {
        validator.reset();
        (void)validator.validate(data);
        benchmark::DoNotOptimize(validator.is_complete());
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(text.size()));
}
BENCHMARK(BM_ValidateUtf8Mixed);

// Validate CJK text (3-byte sequences)
static void BM_ValidateUtf8CJK(benchmark::State& state) {
    // Japanese text (3-byte sequences)
    std::string text;
    for (int i = 0; i < 341; ++i) {  // ~1KB of 3-byte chars
        text += "\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E";  // "Japanese" in Japanese
    }

    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(text.data()),
        text.size()
    };

    Utf8StreamValidator validator;
    for (auto _ : state) {
        validator.reset();
        (void)validator.validate(data);
        benchmark::DoNotOptimize(validator.is_complete());
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(text.size()));
}
BENCHMARK(BM_ValidateUtf8CJK);

// ═══════════════════════════════════════════════════════════════════════════
// Extension Parsing Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Parse extension header
static void BM_ParseExtensionHeader(benchmark::State& state) {
    std::string header = "permessage-deflate; client_max_window_bits=15; server_max_window_bits=15";

    for (auto _ : state) {
        auto offers = parse_extension_header(header);
        benchmark::DoNotOptimize(offers);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseExtensionHeader);

// Parse complex extension header
static void BM_ParseComplexExtensionHeader(benchmark::State& state) {
    std::string header =
        "permessage-deflate; client_max_window_bits=15; server_max_window_bits=15, "
        "x-webkit-deflate-frame; no_context_takeover, "
        "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

    for (auto _ : state) {
        auto offers = parse_extension_header(header);
        benchmark::DoNotOptimize(offers);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseComplexExtensionHeader);

// Format extension header
static void BM_FormatExtensionHeader(benchmark::State& state) {
    ExtensionOffer offer{"permessage-deflate", {{"client_max_window_bits", "15"}, {"server_max_window_bits", "15"}}};

    for (auto _ : state) {
        auto header = format_extension_header(offer);
        benchmark::DoNotOptimize(header);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_FormatExtensionHeader);

// ═══════════════════════════════════════════════════════════════════════════
// Close Frame Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Parse close payload
static void BM_ParseClosePayload(benchmark::State& state) {
    std::vector<std::byte> payload = {
        std::byte{0x03}, std::byte{0xE8},  // 1000 = Normal
        std::byte{'G'}, std::byte{'o'}, std::byte{'o'}, std::byte{'d'},
        std::byte{'b'}, std::byte{'y'}, std::byte{'e'}
    };

    for (auto _ : state) {
        auto info = parse_close_payload(payload);
        benchmark::DoNotOptimize(info);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ParseClosePayload);

// Build close payload
static void BM_BuildClosePayload(benchmark::State& state) {
    WsFrameBuilder builder;

    for (auto _ : state) {
        auto payload = builder.build_close_payload(CloseCode::Normal, "Goodbye");
        benchmark::DoNotOptimize(payload);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_BuildClosePayload);

// ═══════════════════════════════════════════════════════════════════════════
// End-to-End Benchmarks
// ═══════════════════════════════════════════════════════════════════════════

// Full frame roundtrip (build + parse)
static void BM_FrameRoundtrip(benchmark::State& state) {
    const auto payload_size = static_cast<size_t>(state.range(0));
    std::vector<std::byte> payload(payload_size);
    std::fill(payload.begin(), payload.end(), std::byte{0x42});

    std::vector<std::byte> buffer(payload_size + 14);
    WsFrameBuilder builder;
    WsFrameParser parser;
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    for (auto _ : state) {
        // Build frame
        auto frame_size = builder.build_frame(
            buffer, WsOpcode::Binary, payload, true, mask);

        // Parse frame
        parser.reset();
        auto result = parser.parse_header({buffer.data(), frame_size});
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(payload_size));
}
BENCHMARK(BM_FrameRoundtrip)->RangeMultiplier(4)->Range(64, 65536);

// Frame validation
static void BM_FrameValidation(benchmark::State& state) {
    // Build a test frame
    std::vector<std::byte> buffer(1024);
    WsFrameBuilder builder;
    MaskKey mask = {0x37, 0xFA, 0x21, 0x3D};

    std::string text = "Hello, WebSocket!";
    auto frame_size = builder.build_frame(
        buffer, WsOpcode::Text,
        {reinterpret_cast<const std::byte*>(text.data()), text.size()},
        true, mask);

    WsFrameValidator validator;

    for (auto _ : state) {
        validator.reset();

        // Parse header
        WsFrameParser parser;
        (void)parser.parse_header({buffer.data(), frame_size});

        // Validate frame header
        auto result = validator.validate_header(parser.header());
        benchmark::DoNotOptimize(result);
    }

    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_FrameValidation);

BENCHMARK_MAIN();
