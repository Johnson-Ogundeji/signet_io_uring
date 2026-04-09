// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/clock.hpp"
#include "signet/core/histogram.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace signet {

/// Atomic counter for counting events
class Counter {
public:
    Counter() = default;

    void increment() noexcept {
        value_.fetch_add(1, std::memory_order_relaxed);
    }

    void increment(uint64_t delta) noexcept {
        value_.fetch_add(delta, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t value() const noexcept {
        return value_.load(std::memory_order_relaxed);
    }

    void reset() noexcept {
        value_.store(0, std::memory_order_relaxed);
    }

private:
    std::atomic<uint64_t> value_{0};
};

/// Atomic gauge for values that go up and down
class Gauge {
public:
    Gauge() = default;

    void set(int64_t value) noexcept {
        value_.store(value, std::memory_order_relaxed);
    }

    void increment() noexcept {
        value_.fetch_add(1, std::memory_order_relaxed);
    }

    void decrement() noexcept {
        value_.fetch_sub(1, std::memory_order_relaxed);
    }

    void add(int64_t delta) noexcept {
        value_.fetch_add(delta, std::memory_order_relaxed);
    }

    [[nodiscard]] int64_t value() const noexcept {
        return value_.load(std::memory_order_relaxed);
    }

private:
    std::atomic<int64_t> value_{0};
};

/// Timer that automatically records to a histogram
class Timer {
public:
    explicit Timer(LatencyHistogram& histogram) : histogram_(histogram) {}

    /// Start timing (returns RAII guard that stops on destruction)
    class Scope {
    public:
        explicit Scope(LatencyHistogram& h) : histogram_(h), start_(Clock::now_fenced()) {}

        ~Scope() {
            if (!stopped_) {
                stop();
            }
        }

        uint64_t stop() noexcept {
            uint64_t elapsed = Clock::elapsed_ns(start_, Clock::now_fenced());
            histogram_.record(elapsed);
            stopped_ = true;
            return elapsed;
        }

        // Non-copyable, non-movable
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;
        Scope(Scope&&) = delete;
        Scope& operator=(Scope&&) = delete;

    private:
        LatencyHistogram& histogram_;
        uint64_t start_;
        bool stopped_ = false;
    };

    [[nodiscard]] Scope start() {
        return Scope(histogram_);
    }

    /// Record a pre-measured duration
    void record(uint64_t duration_ns) {
        histogram_.record(duration_ns);
    }

    /// Access underlying histogram
    [[nodiscard]] const LatencyHistogram& histogram() const { return histogram_; }
    [[nodiscard]] LatencyHistogram& histogram() { return histogram_; }

private:
    LatencyHistogram& histogram_;
};

/// Metrics registry - central collection point for all metrics
class MetricsRegistry {
public:
    MetricsRegistry() {
        Clock::initialize();
    }

    /// Get or create a counter
    Counter& counter(std::string_view name) {
        std::lock_guard lock(mutex_);
        auto it = counters_.find(std::string(name));
        if (it == counters_.end()) {
            it = counters_.emplace(std::string(name), std::make_unique<Counter>()).first;
        }
        return *it->second;
    }

    /// Get or create a gauge
    Gauge& gauge(std::string_view name) {
        std::lock_guard lock(mutex_);
        auto it = gauges_.find(std::string(name));
        if (it == gauges_.end()) {
            it = gauges_.emplace(std::string(name), std::make_unique<Gauge>()).first;
        }
        return *it->second;
    }

    /// Get or create a histogram
    LatencyHistogram& histogram(std::string_view name) {
        std::lock_guard lock(mutex_);
        auto it = histograms_.find(std::string(name));
        if (it == histograms_.end()) {
            it = histograms_.emplace(std::string(name), std::make_unique<LatencyHistogram>()).first;
        }
        return *it->second;
    }

    /// Get or create a timer (backed by histogram)
    Timer timer(std::string_view name) {
        return Timer(histogram(name));
    }

    /// Reset all metrics
    void reset() {
        std::lock_guard lock(mutex_);
        for (auto& [_, c] : counters_) c->reset();
        for (auto& [_, h] : histograms_) h->reset();
        // Gauges are not reset (they represent current state)
    }

    /// Export all metrics to JSON
    [[nodiscard]] std::string to_json() const {
        std::lock_guard lock(mutex_);

        std::string json = "{";

        // Counters
        json += "\"counters\":{";
        bool first = true;
        for (const auto& [name, counter] : counters_) {
            if (!first) json += ",";
            json += "\"" + name + "\":" + std::to_string(counter->value());
            first = false;
        }
        json += "},";

        // Gauges
        json += "\"gauges\":{";
        first = true;
        for (const auto& [name, gauge] : gauges_) {
            if (!first) json += ",";
            json += "\"" + name + "\":" + std::to_string(gauge->value());
            first = false;
        }
        json += "},";

        // Histograms
        json += "\"histograms\":{";
        first = true;
        for (const auto& [name, hist] : histograms_) {
            if (!first) json += ",";
            json += "\"" + name + "\":" + hist->to_json();
            first = false;
        }
        json += "}";

        json += "}";
        return json;
    }

    /// Get list of all metric names
    struct MetricNames {
        std::vector<std::string> counters;
        std::vector<std::string> gauges;
        std::vector<std::string> histograms;
    };

    [[nodiscard]] MetricNames names() const {
        std::lock_guard lock(mutex_);
        MetricNames result;
        for (const auto& [name, _] : counters_) result.counters.push_back(name);
        for (const auto& [name, _] : gauges_) result.gauges.push_back(name);
        for (const auto& [name, _] : histograms_) result.histograms.push_back(name);
        return result;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<Counter>> counters_;
    std::unordered_map<std::string, std::unique_ptr<Gauge>> gauges_;
    std::unordered_map<std::string, std::unique_ptr<LatencyHistogram>> histograms_;
};

/// Global metrics registry singleton
inline MetricsRegistry& global_metrics() {
    static MetricsRegistry instance;
    return instance;
}

/// Convenience functions for global metrics
inline Counter& counter(std::string_view name) {
    return global_metrics().counter(name);
}

inline Gauge& gauge(std::string_view name) {
    return global_metrics().gauge(name);
}

inline LatencyHistogram& histogram(std::string_view name) {
    return global_metrics().histogram(name);
}

inline Timer timer(std::string_view name) {
    return global_metrics().timer(name);
}

}  // namespace signet

// ============================================================================
// Zero-Overhead Instrumentation Macros
// ============================================================================
// When SIGNET_ENABLE_METRICS is not defined, all macros compile to nothing.
// This allows full instrumentation in benchmarks while having zero overhead
// in production builds.

#ifdef SIGNET_ENABLE_METRICS

/// Start a scoped timer that records to histogram on scope exit
#define SIGNET_TIMER_SCOPE(name) \
    auto SIGNET_CONCAT(__signet_timer_, __LINE__) = ::signet::timer(name).start()

/// Record a value to a histogram
#define SIGNET_HISTOGRAM_RECORD(name, value) \
    ::signet::histogram(name).record(value)

/// Increment a counter
#define SIGNET_COUNTER_INC(name) \
    ::signet::counter(name).increment()

/// Increment a counter by delta
#define SIGNET_COUNTER_ADD(name, delta) \
    ::signet::counter(name).increment(delta)

/// Set a gauge value
#define SIGNET_GAUGE_SET(name, value) \
    ::signet::gauge(name).set(value)

/// Increment a gauge
#define SIGNET_GAUGE_INC(name) \
    ::signet::gauge(name).increment()

/// Decrement a gauge
#define SIGNET_GAUGE_DEC(name) \
    ::signet::gauge(name).decrement()

/// Helper macro for unique variable names
#define SIGNET_CONCAT_IMPL(a, b) a##b
#define SIGNET_CONCAT(a, b) SIGNET_CONCAT_IMPL(a, b)

#else  // SIGNET_ENABLE_METRICS not defined

#define SIGNET_TIMER_SCOPE(name) ((void)0)
#define SIGNET_HISTOGRAM_RECORD(name, value) ((void)0)
#define SIGNET_COUNTER_INC(name) ((void)0)
#define SIGNET_COUNTER_ADD(name, delta) ((void)0)
#define SIGNET_GAUGE_SET(name, value) ((void)0)
#define SIGNET_GAUGE_INC(name) ((void)0)
#define SIGNET_GAUGE_DEC(name) ((void)0)

#endif  // SIGNET_ENABLE_METRICS

// ============================================================================
// Named Metrics (compile-time strings for faster lookup)
// ============================================================================

namespace signet::metrics {

// io_uring operations
constexpr const char* kSqeSubmit = "uring.sqe_submit";
constexpr const char* kCqeWait = "uring.cqe_wait";
constexpr const char* kCqeProcess = "uring.cqe_process";

// Buffer pool
constexpr const char* kBufferAcquire = "buffer.acquire";
constexpr const char* kBufferRelease = "buffer.release";
constexpr const char* kBufferPoolSize = "buffer.pool_size";
constexpr const char* kBufferInUse = "buffer.in_use";

// Network
constexpr const char* kConnectLatency = "net.connect";
constexpr const char* kSendLatency = "net.send";
constexpr const char* kRecvLatency = "net.recv";
constexpr const char* kBytesSent = "net.bytes_sent";
constexpr const char* kBytesRecv = "net.bytes_recv";

// TLS
constexpr const char* kTlsHandshake = "tls.handshake";
constexpr const char* kTlsHandshakeErrors = "tls.handshake_errors";
constexpr const char* kTlsSessionResume = "tls.session_resume";
constexpr const char* kTlsEncrypt = "tls.encrypt";
constexpr const char* kTlsDecrypt = "tls.decrypt";
constexpr const char* kKtlsActive = "tls.ktls_active";
constexpr const char* kKtlsEnabled = "tls.ktls_enabled";

// WebSocket
constexpr const char* kWsFrameParse = "ws.frame_parse";
constexpr const char* kWsFrameBuild = "ws.frame_build";
constexpr const char* kWsMaskApply = "ws.mask_apply";
constexpr const char* kWsUtf8Validate = "ws.utf8_validate";
constexpr const char* kWsMessageSend = "ws.message_send";
constexpr const char* kWsMessageRecv = "ws.message_recv";
constexpr const char* kWsMessagesSent = "ws.messages_sent";
constexpr const char* kWsMessagesRecv = "ws.messages_recv";

// Errors
constexpr const char* kErrors = "errors.total";
constexpr const char* kRetries = "errors.retries";

}  // namespace signet::metrics
