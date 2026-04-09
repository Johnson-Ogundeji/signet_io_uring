// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/types.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace signet {

/// Configuration for Signet WebSocket client/server
struct Config {
    // ═══════════════════════════════════════════════════════════════════════
    // io_uring Settings
    // ═══════════════════════════════════════════════════════════════════════

    /// Submission queue size (must be power of 2)
    uint32_t sq_entries = 256;

    /// Completion queue size (must be >= sq_entries)
    uint32_t cq_entries = 512;

    /// Enable SQPOLL mode (kernel-side polling, zero syscalls)
    /// Requires CAP_SYS_NICE or root
    bool enable_sqpoll = false;

    /// SQPOLL idle timeout in milliseconds (0 = never idle)
    uint32_t sqpoll_idle_ms = 1000;

    /// CPU to bind SQPOLL thread to (-1 = any)
    int sqpoll_cpu = -1;

    /// Enable multishot receive (kernel 5.19+)
    bool enable_multishot = true;

    /// Enable buffer ring for automatic buffer management (kernel 5.19+)
    bool enable_buffer_ring = true;

    /// Enable registered file descriptors
    bool enable_registered_fds = true;

    // ═══════════════════════════════════════════════════════════════════════
    // Buffer Pool Settings
    // ═══════════════════════════════════════════════════════════════════════

    /// Number of pre-allocated buffers
    size_t buffer_count = 64;

    /// Size of each buffer in bytes
    size_t buffer_size = 16384;

    /// Use huge pages (2MB) for buffer allocation
    bool use_huge_pages = false;

    /// Register buffers with io_uring for zero-copy I/O
    bool register_buffers = true;

    /// Buffer alignment (must be power of 2)
    size_t buffer_alignment = 4096;

    // ═══════════════════════════════════════════════════════════════════════
    // TLS Settings
    // ═══════════════════════════════════════════════════════════════════════

    /// Enable TLS (required for wss:// URLs)
    bool enable_tls = true;

    /// Enable kTLS kernel offload for TLS
    bool enable_ktls = true;

    /// Enable kTLS for TX (send)
    bool ktls_tx = true;

    /// Enable kTLS for RX (receive)
    bool ktls_rx = true;

    /// Verify peer certificate (client mode)
    bool verify_peer = true;

    /// Path to CA certificate file or directory
    std::string ca_path;

    /// Path to client certificate (for mutual TLS)
    std::string cert_path;

    /// Path to client private key (for mutual TLS)
    std::string key_path;

    /// ALPN protocols to offer
    std::vector<std::string> alpn;

    /// Minimum TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
    uint16_t min_tls_version = 0x0303;

    /// Enable TLS session resumption
    bool enable_session_cache = true;

    /// TLS session cache size
    size_t session_cache_size = 1000;

    // ═══════════════════════════════════════════════════════════════════════
    // WebSocket Protocol Settings
    // ═══════════════════════════════════════════════════════════════════════

    /// Maximum message size (0 = unlimited)
    size_t max_message_size = 16 * 1024 * 1024;  // 16MB

    /// Maximum frame size (0 = unlimited)
    size_t max_frame_size = 1 * 1024 * 1024;  // 1MB

    /// Auto-fragment large messages
    bool auto_fragment = true;

    /// Fragment threshold for auto-fragmentation
    size_t fragment_threshold = 65536;

    /// Validate UTF-8 in text frames
    bool validate_utf8 = true;

    /// Use SIMD for UTF-8 validation and masking
    bool enable_simd = true;

    /// Force specific SIMD level (None = auto-detect)
    SimdLevel simd_level = SimdLevel::None;

    // ═══════════════════════════════════════════════════════════════════════
    // Timing Settings
    // ═══════════════════════════════════════════════════════════════════════

    /// Connection timeout
    Milliseconds connect_timeout{5000};

    /// WebSocket handshake timeout
    Milliseconds handshake_timeout{5000};

    /// Close handshake timeout
    Milliseconds close_timeout{3000};

    /// Ping interval (0 = disabled)
    Milliseconds ping_interval{30000};

    /// Pong timeout (0 = disabled)
    Milliseconds pong_timeout{10000};

    /// Idle timeout (0 = disabled)
    Milliseconds idle_timeout{0};

    // ═══════════════════════════════════════════════════════════════════════
    // Performance Tuning
    // ═══════════════════════════════════════════════════════════════════════

    /// CPU cores to pin threads to (empty = no affinity)
    std::vector<int> cpu_affinity;

    /// NUMA node for memory allocation (-1 = any)
    int numa_node = -1;

    /// Busy poll duration in microseconds (0 = disabled)
    uint32_t busy_poll_us = 0;

    /// Batch size for io_uring submissions
    uint32_t batch_size = 32;

    /// Enable zero-copy send (requires registered buffers)
    bool zero_copy_send = true;

    // ═══════════════════════════════════════════════════════════════════════
    // Extensions
    // ═══════════════════════════════════════════════════════════════════════

    /// Enable permessage-deflate compression
    bool enable_compression = false;

    /// Compression level (1-9, higher = more compression)
    int compression_level = 6;

    /// Compression window bits (8-15)
    int compression_window_bits = 15;

    /// Memory level for compression (1-9)
    int compression_mem_level = 8;

    /// Client no context takeover
    bool client_no_context_takeover = false;

    /// Server no context takeover
    bool server_no_context_takeover = false;

    // ═══════════════════════════════════════════════════════════════════════
    // Metrics & Debugging
    // ═══════════════════════════════════════════════════════════════════════

    /// Enable metrics collection
    bool enable_metrics = false;

    /// Enable verbose logging
    bool verbose = false;
};

/// Configuration builder for fluent API
class ConfigBuilder {
public:
    ConfigBuilder() = default;

    ConfigBuilder& sqpoll(bool enable) { config_.enable_sqpoll = enable; return *this; }
    ConfigBuilder& sqpoll_cpu(int cpu) { config_.sqpoll_cpu = cpu; return *this; }
    ConfigBuilder& sqpoll_idle_ms(uint32_t ms) { config_.sqpoll_idle_ms = ms; return *this; }

    ConfigBuilder& multishot(bool enable) { config_.enable_multishot = enable; return *this; }
    ConfigBuilder& buffer_ring(bool enable) { config_.enable_buffer_ring = enable; return *this; }

    ConfigBuilder& buffer_count(size_t count) { config_.buffer_count = count; return *this; }
    ConfigBuilder& buffer_size(size_t size) { config_.buffer_size = size; return *this; }
    ConfigBuilder& huge_pages(bool enable) { config_.use_huge_pages = enable; return *this; }
    ConfigBuilder& register_buffers(bool enable) { config_.register_buffers = enable; return *this; }

    ConfigBuilder& ktls(bool enable) { config_.enable_ktls = enable; return *this; }
    ConfigBuilder& verify_peer(bool enable) { config_.verify_peer = enable; return *this; }
    ConfigBuilder& ca_path(std::string path) { config_.ca_path = std::move(path); return *this; }
    ConfigBuilder& cert_path(std::string path) { config_.cert_path = std::move(path); return *this; }
    ConfigBuilder& key_path(std::string path) { config_.key_path = std::move(path); return *this; }

    ConfigBuilder& max_message_size(size_t size) { config_.max_message_size = size; return *this; }
    ConfigBuilder& max_frame_size(size_t size) { config_.max_frame_size = size; return *this; }
    ConfigBuilder& validate_utf8(bool enable) { config_.validate_utf8 = enable; return *this; }
    ConfigBuilder& simd(bool enable) { config_.enable_simd = enable; return *this; }

    ConfigBuilder& connect_timeout(Milliseconds timeout) { config_.connect_timeout = timeout; return *this; }
    ConfigBuilder& handshake_timeout(Milliseconds timeout) { config_.handshake_timeout = timeout; return *this; }
    ConfigBuilder& ping_interval(Milliseconds interval) { config_.ping_interval = interval; return *this; }

    ConfigBuilder& cpu_affinity(std::vector<int> cpus) { config_.cpu_affinity = std::move(cpus); return *this; }
    ConfigBuilder& busy_poll(uint32_t us) { config_.busy_poll_us = us; return *this; }

    ConfigBuilder& compression(bool enable) { config_.enable_compression = enable; return *this; }
    ConfigBuilder& metrics(bool enable) { config_.enable_metrics = enable; return *this; }

    [[nodiscard]] Config build() const { return config_; }

private:
    Config config_;
};

/// Preset configurations
namespace presets {

/// Low-latency configuration for HFT
[[nodiscard]] inline Config low_latency() {
    Config config;
    config.enable_sqpoll = true;
    config.sqpoll_idle_ms = 0;  // Never idle
    config.enable_ktls = true;
    config.enable_multishot = true;
    config.buffer_count = 32;
    config.buffer_size = 4096;  // Smaller for low latency
    config.use_huge_pages = true;
    config.register_buffers = true;
    config.busy_poll_us = 100;
    config.ping_interval = Milliseconds{60000};
    config.enable_compression = false;  // Compression adds latency
    return config;
}

/// High-throughput configuration
[[nodiscard]] inline Config high_throughput() {
    Config config;
    config.enable_sqpoll = true;
    config.sqpoll_idle_ms = 1000;
    config.enable_ktls = true;
    config.enable_multishot = true;
    config.buffer_count = 256;
    config.buffer_size = 65536;  // Larger for throughput
    config.use_huge_pages = true;
    config.register_buffers = true;
    config.sq_entries = 1024;
    config.cq_entries = 2048;
    config.batch_size = 64;
    return config;
}

/// Balanced configuration (default)
[[nodiscard]] inline Config balanced() {
    return Config{};  // Defaults are balanced
}

/// Minimal resource configuration
[[nodiscard]] inline Config minimal() {
    Config config;
    config.enable_sqpoll = false;  // Save CPU
    config.enable_ktls = true;
    config.enable_multishot = false;
    config.buffer_count = 16;
    config.buffer_size = 8192;
    config.use_huge_pages = false;
    config.sq_entries = 64;
    config.cq_entries = 128;
    return config;
}

}  // namespace presets

}  // namespace signet
