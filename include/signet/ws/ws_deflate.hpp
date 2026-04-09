// Signet WebSocket permessage-deflate Extension
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0
//
// Implementation of RFC 7692 - Compression Extensions for WebSocket

#ifndef SIGNET_WS_DEFLATE_HPP
#define SIGNET_WS_DEFLATE_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <zlib.h>

#include "signet/core/error.hpp"
#include "signet/ws/ws_extension.hpp"

namespace signet {

// ═══════════════════════════════════════════════════════════════════════════
// Deflate Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for permessage-deflate extension
struct DeflateConfig {
    /// Compression level (1-9, higher = better compression, slower)
    int compression_level{6};

    /// Memory level (1-9, affects memory usage and speed)
    int mem_level{8};

    /// Maximum window bits for compression (8-15)
    int client_max_window_bits{15};

    /// Maximum window bits for decompression (8-15)
    int server_max_window_bits{15};

    /// Whether client can take over compression context
    bool client_no_context_takeover{false};

    /// Whether server can take over compression context
    bool server_no_context_takeover{false};

    /// Minimum message size to compress (bytes)
    size_t min_compress_size{64};

    /// Factory for default HFT-optimized config
    [[nodiscard]] static DeflateConfig hft() noexcept {
        DeflateConfig config;
        config.compression_level = 1;      // Fastest compression
        config.mem_level = 9;              // Max memory for speed
        config.min_compress_size = 256;    // Only compress larger messages
        return config;
    }

    /// Factory for bandwidth-optimized config
    [[nodiscard]] static DeflateConfig bandwidth() noexcept {
        DeflateConfig config;
        config.compression_level = 6;      // Balanced
        config.mem_level = 8;
        config.min_compress_size = 64;
        return config;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Deflate Context (RAII wrapper for zlib streams)
// ═══════════════════════════════════════════════════════════════════════════

/// RAII wrapper for zlib deflate stream
class DeflateContext {
public:
    explicit DeflateContext(const DeflateConfig& config)
        : config_(config) {
        std::memset(&stream_, 0, sizeof(stream_));
    }

    ~DeflateContext() {
        if (initialized_) {
            deflateEnd(&stream_);
        }
    }

    DeflateContext(const DeflateContext&) = delete;
    DeflateContext& operator=(const DeflateContext&) = delete;

    DeflateContext(DeflateContext&& other) noexcept
        : stream_(other.stream_)
        , config_(other.config_)
        , initialized_(other.initialized_) {
        other.initialized_ = false;
    }

    DeflateContext& operator=(DeflateContext&& other) noexcept {
        if (this != &other) {
            if (initialized_) {
                deflateEnd(&stream_);
            }
            stream_ = other.stream_;
            config_ = other.config_;
            initialized_ = other.initialized_;
            other.initialized_ = false;
        }
        return *this;
    }

    /// Initialize the deflate stream
    [[nodiscard]] tl::expected<void, Error> init(int window_bits) {
        if (initialized_) {
            return {};
        }

        // Use negative window bits for raw deflate (no zlib header)
        int ret = deflateInit2(
            &stream_,
            config_.compression_level,
            Z_DEFLATED,
            -window_bits,  // Negative = raw deflate
            config_.mem_level,
            Z_DEFAULT_STRATEGY
        );

        if (ret != Z_OK) {
            return tl::unexpected(Error{
                ErrorCode::CompressionFailed,
                "deflateInit2 failed: " + std::to_string(ret)
            });
        }

        initialized_ = true;
        return {};
    }

    /// Compress data
    [[nodiscard]] tl::expected<std::vector<std::byte>, Error>
    compress(std::span<const std::byte> input, bool no_context_takeover) {
        if (!initialized_) {
            auto init_result = init(config_.client_max_window_bits);
            if (!init_result) {
                return tl::unexpected(init_result.error());
            }
        }

        // SECURITY (HIGH #15): zlib's avail_in/avail_out are uInt (typically
        // 32-bit). A WebSocket message can be larger on a 64-bit host —
        // truncating the cast would silently corrupt the stream.
        if (input.size() > std::numeric_limits<uInt>::max()) {
            return tl::unexpected(Error{
                ErrorCode::MessageTooLarge,
                "Input exceeds zlib uInt limit"
            });
        }

        // Reset if no context takeover
        // SECURITY (HIGH #14): deflateReset can fail if stream state is corrupt.
        if (no_context_takeover) {
            int reset_ret = deflateReset(&stream_);
            if (reset_ret != Z_OK) {
                return tl::unexpected(Error{
                    ErrorCode::CompressionFailed,
                    "deflateReset failed: " + std::to_string(reset_ret)
                });
            }
        }

        // Allocate output buffer (worst case: slightly larger than input)
        // SECURITY (HIGH #12): deflateBound returns 0 if the stream isn't
        // properly initialized; treat that as an error rather than allocating
        // a zero-byte vector and proceeding.
        uLong bound = deflateBound(&stream_, static_cast<uLong>(input.size()));
        if (bound == 0 || bound > std::numeric_limits<uInt>::max()) {
            return tl::unexpected(Error{
                ErrorCode::CompressionFailed,
                "deflateBound returned invalid size"
            });
        }
        std::vector<std::byte> output;
        try {
            output.resize(static_cast<size_t>(bound));
        } catch (const std::bad_alloc&) {
            return tl::unexpected(Error{
                ErrorCode::OutOfMemory,
                "Failed to allocate compression output buffer"
            });
        }

        stream_.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data()));
        stream_.avail_in = static_cast<uInt>(input.size());
        stream_.next_out = reinterpret_cast<Bytef*>(output.data());
        stream_.avail_out = static_cast<uInt>(output.size());

        // Deflate with Z_SYNC_FLUSH to get complete output
        int ret = deflate(&stream_, Z_SYNC_FLUSH);

        // SECURITY (HIGH #13): Z_MEM_ERROR is fatal — zlib can no longer be
        // used and we must signal allocation failure to the caller.
        if (ret == Z_MEM_ERROR) {
            return tl::unexpected(Error{
                ErrorCode::OutOfMemory,
                "deflate Z_MEM_ERROR"
            });
        }

        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            return tl::unexpected(Error{
                ErrorCode::CompressionFailed,
                "deflate failed: " + std::to_string(ret)
            });
        }

        // Resize to actual output size
        size_t output_size = output.size() - stream_.avail_out;
        output.resize(output_size);

        // Remove trailing 0x00 0x00 0xff 0xff if present
        // (required by RFC 7692)
        if (output_size >= 4) {
            if (output[output_size - 4] == std::byte{0x00} &&
                output[output_size - 3] == std::byte{0x00} &&
                output[output_size - 2] == std::byte{0xff} &&
                output[output_size - 1] == std::byte{0xff}) {
                output.resize(output_size - 4);
            }
        }

        return output;
    }

    /// Reset the stream
    void reset() {
        if (initialized_) {
            deflateReset(&stream_);
        }
    }

private:
    z_stream stream_{};
    DeflateConfig config_;
    bool initialized_{false};
};

/// RAII wrapper for zlib inflate stream
class InflateContext {
public:
    InflateContext() {
        std::memset(&stream_, 0, sizeof(stream_));
    }

    ~InflateContext() {
        if (initialized_) {
            inflateEnd(&stream_);
        }
    }

    InflateContext(const InflateContext&) = delete;
    InflateContext& operator=(const InflateContext&) = delete;

    InflateContext(InflateContext&& other) noexcept
        : stream_(other.stream_)
        , initialized_(other.initialized_) {
        other.initialized_ = false;
    }

    InflateContext& operator=(InflateContext&& other) noexcept {
        if (this != &other) {
            if (initialized_) {
                inflateEnd(&stream_);
            }
            stream_ = other.stream_;
            initialized_ = other.initialized_;
            other.initialized_ = false;
        }
        return *this;
    }

    /// Initialize the inflate stream
    [[nodiscard]] tl::expected<void, Error> init(int window_bits) {
        if (initialized_) {
            return {};
        }

        // Use negative window bits for raw deflate (no zlib header)
        int ret = inflateInit2(&stream_, -window_bits);

        if (ret != Z_OK) {
            return tl::unexpected(Error{
                ErrorCode::DecompressionFailed,
                "inflateInit2 failed: " + std::to_string(ret)
            });
        }

        initialized_ = true;
        return {};
    }

    /// Decompress data
    [[nodiscard]] tl::expected<std::vector<std::byte>, Error>
    decompress(std::span<const std::byte> input, bool no_context_takeover,
               size_t max_output_size = 16 * 1024 * 1024) {
        if (!initialized_) {
            return tl::unexpected(Error{
                ErrorCode::DecompressionFailed,
                "Inflate context not initialized"
            });
        }

        // SECURITY (HIGH #16): zlib avail_in is uInt — refuse oversized input.
        // We'll be appending 4 trailing bytes, so check against UINT_MAX - 4.
        if (input.size() > std::numeric_limits<uInt>::max() - 4) {
            return tl::unexpected(Error{
                ErrorCode::MessageTooLarge,
                "Compressed input exceeds zlib uInt limit"
            });
        }

        // Reset if no context takeover
        // SECURITY (HIGH #14): inflateReset can fail.
        if (no_context_takeover) {
            int reset_ret = inflateReset(&stream_);
            if (reset_ret != Z_OK) {
                return tl::unexpected(Error{
                    ErrorCode::DecompressionFailed,
                    "inflateReset failed: " + std::to_string(reset_ret)
                });
            }
        }

        // Create input with trailing bytes (RFC 7692)
        std::vector<std::byte> full_input;
        try {
            full_input.reserve(input.size() + 4);
            full_input.assign(input.begin(), input.end());
            full_input.push_back(std::byte{0x00});
            full_input.push_back(std::byte{0x00});
            full_input.push_back(std::byte{0xff});
            full_input.push_back(std::byte{0xff});
        } catch (const std::bad_alloc&) {
            return tl::unexpected(Error{
                ErrorCode::OutOfMemory,
                "Failed to allocate decompression input buffer"
            });
        }

        // Output buffer (start with input size * 4, grow as needed)
        // SECURITY (HIGH #18): input.size() * 4 can overflow on huge inputs.
        size_t initial_output;
        if (input.size() > std::numeric_limits<size_t>::max() / 4) {
            initial_output = max_output_size;
        } else {
            initial_output = std::max(size_t{1024}, input.size() * 4);
            if (initial_output > max_output_size) {
                initial_output = max_output_size;
            }
        }
        std::vector<std::byte> output;
        try {
            output.resize(initial_output);
        } catch (const std::bad_alloc&) {
            return tl::unexpected(Error{
                ErrorCode::OutOfMemory,
                "Failed to allocate decompression output buffer"
            });
        }

        stream_.next_in = reinterpret_cast<Bytef*>(full_input.data());
        stream_.avail_in = static_cast<uInt>(full_input.size());

        size_t total_output = 0;

        while (stream_.avail_in > 0) {
            stream_.next_out = reinterpret_cast<Bytef*>(output.data() + total_output);
            // SECURITY (HIGH #17): avail_out cast to uInt — clamp the
            // remaining capacity so we never silently truncate a >4GB chunk.
            size_t remaining = output.size() - total_output;
            if (remaining > std::numeric_limits<uInt>::max()) {
                remaining = std::numeric_limits<uInt>::max();
            }
            stream_.avail_out = static_cast<uInt>(remaining);

            int ret = inflate(&stream_, Z_SYNC_FLUSH);

            if (ret == Z_STREAM_END) {
                // Decompress complete
                total_output = output.size() - stream_.avail_out;
                break;
            }

            // SECURITY (HIGH #13): Z_MEM_ERROR is fatal.
            if (ret == Z_MEM_ERROR) {
                return tl::unexpected(Error{
                    ErrorCode::OutOfMemory,
                    "inflate Z_MEM_ERROR"
                });
            }
            // SECURITY (HIGH #12): Z_DATA_ERROR means corrupt input —
            // distinguish from generic failure so callers can react.
            if (ret == Z_DATA_ERROR) {
                return tl::unexpected(Error{
                    ErrorCode::DecompressionFailed,
                    "inflate Z_DATA_ERROR (corrupt input)"
                });
            }

            if (ret != Z_OK && ret != Z_BUF_ERROR) {
                return tl::unexpected(Error{
                    ErrorCode::DecompressionFailed,
                    "inflate failed: " + std::to_string(ret)
                });
            }

            total_output = output.size() - stream_.avail_out;

            // Need more output space
            if (stream_.avail_out == 0) {
                if (output.size() >= max_output_size) {
                    return tl::unexpected(Error{
                        ErrorCode::MessageTooLarge,
                        "Decompressed message exceeds max size"
                    });
                }
                size_t new_size = output.size();
                if (new_size > std::numeric_limits<size_t>::max() / 2) {
                    new_size = max_output_size;
                } else {
                    new_size = std::min(new_size * 2, max_output_size);
                }
                try {
                    output.resize(new_size);
                } catch (const std::bad_alloc&) {
                    return tl::unexpected(Error{
                        ErrorCode::OutOfMemory,
                        "Failed to grow decompression output buffer"
                    });
                }
            }

            // If avail_in is 0 but we didn't get Z_STREAM_END, we're done
            if (stream_.avail_in == 0) {
                break;
            }
        }

        output.resize(total_output);
        return output;
    }

    /// Reset the stream
    void reset() {
        if (initialized_) {
            inflateReset(&stream_);
        }
    }

private:
    z_stream stream_{};
    bool initialized_{false};
};

// ═══════════════════════════════════════════════════════════════════════════
// permessage-deflate Extension
// ═══════════════════════════════════════════════════════════════════════════

/// RFC 7692 permessage-deflate WebSocket extension
class PermessageDeflate : public WsExtension {
public:
    explicit PermessageDeflate(DeflateConfig config = {})
        : config_(std::move(config))
        , deflate_ctx_(config_) {}

    [[nodiscard]] std::string_view name() const noexcept override {
        return "permessage-deflate";
    }

    [[nodiscard]] std::string generate_offer() const override {
        std::string offer = "permessage-deflate";

        if (config_.client_no_context_takeover) {
            offer += "; client_no_context_takeover";
        }

        if (config_.server_no_context_takeover) {
            offer += "; server_no_context_takeover";
        }

        if (config_.client_max_window_bits < 15) {
            offer += "; client_max_window_bits=";
            offer += std::to_string(config_.client_max_window_bits);
        }

        if (config_.server_max_window_bits < 15) {
            offer += "; server_max_window_bits=";
            offer += std::to_string(config_.server_max_window_bits);
        }

        return offer;
    }

    [[nodiscard]] tl::expected<void, Error>
    configure(const ExtensionOffer& response) override {
        if (response.name != "permessage-deflate") {
            return tl::unexpected(Error{
                ErrorCode::WebSocketHandshakeFailed,
                "Extension name mismatch"
            });
        }

        // Parse server response parameters
        if (response.has_param("server_no_context_takeover")) {
            server_no_context_takeover_ = true;
        }

        if (response.has_param("client_no_context_takeover")) {
            client_no_context_takeover_ = true;
        }

        auto server_bits = response.get_int_param("server_max_window_bits");
        if (server_bits) {
            if (*server_bits < 8 || *server_bits > 15) {
                return tl::unexpected(Error{
                    ErrorCode::WebSocketHandshakeFailed,
                    "Invalid server_max_window_bits"
                });
            }
            server_window_bits_ = *server_bits;
        }

        auto client_bits = response.get_int_param("client_max_window_bits");
        if (client_bits) {
            if (*client_bits < 8 || *client_bits > 15) {
                return tl::unexpected(Error{
                    ErrorCode::WebSocketHandshakeFailed,
                    "Invalid client_max_window_bits"
                });
            }
            client_window_bits_ = *client_bits;
        }

        // Initialize contexts
        auto deflate_result = deflate_ctx_.init(client_window_bits_);
        if (!deflate_result) {
            return tl::unexpected(deflate_result.error());
        }

        auto inflate_result = inflate_ctx_.init(server_window_bits_);
        if (!inflate_result) {
            return tl::unexpected(inflate_result.error());
        }

        configured_ = true;
        return {};
    }

    [[nodiscard]] tl::expected<ExtensionResult, Error>
    process_outgoing(std::span<const std::byte> data, bool /*is_text*/) override {
        // Pass through if not configured or message too small
        if (!configured_ || data.size() < config_.min_compress_size) {
            return ExtensionResult::success(
                std::vector<std::byte>(data.begin(), data.end()));
        }

        auto compressed = deflate_ctx_.compress(data, client_no_context_takeover_);
        if (!compressed) {
            return tl::unexpected(compressed.error());
        }

        // Only use compressed if it's actually smaller
        if (compressed->size() >= data.size()) {
            return ExtensionResult::success(
                std::vector<std::byte>(data.begin(), data.end()));
        }

        return ExtensionResult::with_rsv1(std::move(*compressed));
    }

    [[nodiscard]] tl::expected<std::vector<std::byte>, Error>
    process_incoming(std::span<const std::byte> data, bool rsv1, bool /*is_text*/) override {
        // Pass through if RSV1 not set (not compressed)
        if (!rsv1) {
            return std::vector<std::byte>(data.begin(), data.end());
        }

        if (!configured_) {
            return tl::unexpected(Error{
                ErrorCode::WebSocketProtocolError,
                "Received compressed frame but extension not configured"
            });
        }

        return inflate_ctx_.decompress(data, server_no_context_takeover_);
    }

    void reset() override {
        deflate_ctx_.reset();
        inflate_ctx_.reset();
        configured_ = false;
    }

    [[nodiscard]] bool uses_rsv1() const noexcept override {
        return true;
    }

    /// Get compression statistics
    [[nodiscard]] size_t bytes_compressed() const noexcept {
        return bytes_in_;
    }

    [[nodiscard]] size_t bytes_after_compression() const noexcept {
        return bytes_out_;
    }

    [[nodiscard]] double compression_ratio() const noexcept {
        return bytes_in_ > 0
            ? static_cast<double>(bytes_out_) / static_cast<double>(bytes_in_)
            : 1.0;
    }

private:
    DeflateConfig config_;
    DeflateContext deflate_ctx_;
    InflateContext inflate_ctx_;

    bool configured_{false};
    bool client_no_context_takeover_{false};
    bool server_no_context_takeover_{false};
    int client_window_bits_{15};
    int server_window_bits_{15};

    // Statistics
    size_t bytes_in_{0};
    size_t bytes_out_{0};
};

// ═══════════════════════════════════════════════════════════════════════════
// Factory Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Create permessage-deflate extension with default config
[[nodiscard]] inline std::unique_ptr<WsExtension> make_deflate_extension() {
    return std::make_unique<PermessageDeflate>();
}

/// Create permessage-deflate extension with HFT config
[[nodiscard]] inline std::unique_ptr<WsExtension> make_deflate_extension_hft() {
    return std::make_unique<PermessageDeflate>(DeflateConfig::hft());
}

/// Create permessage-deflate extension with bandwidth config
[[nodiscard]] inline std::unique_ptr<WsExtension> make_deflate_extension_bandwidth() {
    return std::make_unique<PermessageDeflate>(DeflateConfig::bandwidth());
}

}  // namespace signet

#endif  // SIGNET_WS_DEFLATE_HPP
