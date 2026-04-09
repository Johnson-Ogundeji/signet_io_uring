// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace signet {

/// Lock-free HDR (High Dynamic Range) histogram for latency tracking
///
/// Design goals:
/// - Zero allocation on hot path (record)
/// - Lock-free atomic updates
/// - Wide range: 1ns to 1 hour with <1% error
/// - Fast percentile calculation
///
/// Uses logarithmic bucketing with sub-buckets for precision.
/// Bucket index = log2(value) * sub_buckets + sub_bucket_index
template<size_t SubBucketBits = 7>  // 128 sub-buckets per power of 2
class Histogram {
public:
    static constexpr size_t kSubBuckets = 1ULL << SubBucketBits;
    static constexpr size_t kSubBucketMask = kSubBuckets - 1;

    // Support values from 1 to 2^40 (~1 trillion nanoseconds = ~17 minutes)
    static constexpr size_t kMaxBuckets = 40;
    static constexpr size_t kTotalBuckets = kMaxBuckets * kSubBuckets;

    Histogram() {
        reset();
    }

    /// Record a value (lock-free, zero allocation)
    void record(uint64_t value) noexcept {
        if (value == 0) value = 1;

        size_t index = bucket_index(value);
        if (index < kTotalBuckets) {
            counts_[index].fetch_add(1, std::memory_order_relaxed);
        } else {
            // Overflow bucket
            counts_[kTotalBuckets - 1].fetch_add(1, std::memory_order_relaxed);
        }

        // Update running stats (relaxed ordering is fine for stats)
        total_count_.fetch_add(1, std::memory_order_relaxed);
        total_sum_.fetch_add(value, std::memory_order_relaxed);

        // Update min/max with CAS loop
        uint64_t current_min = min_.load(std::memory_order_relaxed);
        while (value < current_min &&
               !min_.compare_exchange_weak(current_min, value, std::memory_order_relaxed)) {
            // Retry
        }

        uint64_t current_max = max_.load(std::memory_order_relaxed);
        while (value > current_max &&
               !max_.compare_exchange_weak(current_max, value, std::memory_order_relaxed)) {
            // Retry
        }
    }

    /// Record multiple values at once
    void record_n(uint64_t value, uint64_t count) noexcept {
        if (value == 0) value = 1;
        if (count == 0) return;

        size_t index = bucket_index(value);
        if (index < kTotalBuckets) {
            counts_[index].fetch_add(count, std::memory_order_relaxed);
        } else {
            counts_[kTotalBuckets - 1].fetch_add(count, std::memory_order_relaxed);
        }

        total_count_.fetch_add(count, std::memory_order_relaxed);
        total_sum_.fetch_add(value * count, std::memory_order_relaxed);

        // Min/max
        uint64_t current_min = min_.load(std::memory_order_relaxed);
        while (value < current_min &&
               !min_.compare_exchange_weak(current_min, value, std::memory_order_relaxed)) {}

        uint64_t current_max = max_.load(std::memory_order_relaxed);
        while (value > current_max &&
               !max_.compare_exchange_weak(current_max, value, std::memory_order_relaxed)) {}
    }

    /// Get percentile value (e.g., 0.99 for p99)
    [[nodiscard]] uint64_t percentile(double p) const noexcept {
        uint64_t count = total_count_.load(std::memory_order_relaxed);
        if (count == 0) return 0;

        uint64_t target = static_cast<uint64_t>(p * static_cast<double>(count));
        if (target == 0) target = 1;

        uint64_t cumulative = 0;
        for (size_t i = 0; i < kTotalBuckets; ++i) {
            cumulative += counts_[i].load(std::memory_order_relaxed);
            if (cumulative >= target) {
                return bucket_value(i);
            }
        }

        return max_.load(std::memory_order_relaxed);
    }

    /// Get common percentiles
    [[nodiscard]] uint64_t p50() const noexcept { return percentile(0.50); }
    [[nodiscard]] uint64_t p90() const noexcept { return percentile(0.90); }
    [[nodiscard]] uint64_t p95() const noexcept { return percentile(0.95); }
    [[nodiscard]] uint64_t p99() const noexcept { return percentile(0.99); }
    [[nodiscard]] uint64_t p999() const noexcept { return percentile(0.999); }
    [[nodiscard]] uint64_t p9999() const noexcept { return percentile(0.9999); }

    /// Get total count of recorded values
    [[nodiscard]] uint64_t count() const noexcept {
        return total_count_.load(std::memory_order_relaxed);
    }

    /// Get sum of all recorded values
    [[nodiscard]] uint64_t sum() const noexcept {
        return total_sum_.load(std::memory_order_relaxed);
    }

    /// Get mean value
    [[nodiscard]] double mean() const noexcept {
        uint64_t c = count();
        return c > 0 ? static_cast<double>(sum()) / static_cast<double>(c) : 0.0;
    }

    /// Get minimum recorded value
    [[nodiscard]] uint64_t min() const noexcept {
        return min_.load(std::memory_order_relaxed);
    }

    /// Get maximum recorded value
    [[nodiscard]] uint64_t max() const noexcept {
        return max_.load(std::memory_order_relaxed);
    }

    /// Reset all counters
    void reset() noexcept {
        for (auto& c : counts_) {
            c.store(0, std::memory_order_relaxed);
        }
        total_count_.store(0, std::memory_order_relaxed);
        total_sum_.store(0, std::memory_order_relaxed);
        min_.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
        max_.store(0, std::memory_order_relaxed);
    }

    /// Merge another histogram into this one
    void merge(const Histogram& other) noexcept {
        for (size_t i = 0; i < kTotalBuckets; ++i) {
            uint64_t other_count = other.counts_[i].load(std::memory_order_relaxed);
            if (other_count > 0) {
                counts_[i].fetch_add(other_count, std::memory_order_relaxed);
            }
        }
        total_count_.fetch_add(other.count(), std::memory_order_relaxed);
        total_sum_.fetch_add(other.sum(), std::memory_order_relaxed);

        // Merge min/max
        uint64_t other_min = other.min();
        uint64_t current_min = min_.load(std::memory_order_relaxed);
        while (other_min < current_min &&
               !min_.compare_exchange_weak(current_min, other_min, std::memory_order_relaxed)) {}

        uint64_t other_max = other.max();
        uint64_t current_max = max_.load(std::memory_order_relaxed);
        while (other_max > current_max &&
               !max_.compare_exchange_weak(current_max, other_max, std::memory_order_relaxed)) {}
    }

    /// Export to JSON string
    [[nodiscard]] std::string to_json() const {
        std::string json = "{";
        json += "\"count\":" + std::to_string(count()) + ",";
        json += "\"sum\":" + std::to_string(sum()) + ",";
        json += "\"mean\":" + std::to_string(mean()) + ",";
        json += "\"min\":" + std::to_string(min()) + ",";
        json += "\"max\":" + std::to_string(max()) + ",";
        json += "\"p50\":" + std::to_string(p50()) + ",";
        json += "\"p90\":" + std::to_string(p90()) + ",";
        json += "\"p95\":" + std::to_string(p95()) + ",";
        json += "\"p99\":" + std::to_string(p99()) + ",";
        json += "\"p999\":" + std::to_string(p999()) + ",";
        json += "\"p9999\":" + std::to_string(p9999());
        json += "}";
        return json;
    }

    /// Create snapshot for thread-safe iteration
    struct Snapshot {
        uint64_t count;
        uint64_t sum;
        uint64_t min_val;
        uint64_t max_val;
        std::array<uint64_t, kTotalBuckets> counts;
    };

    [[nodiscard]] Snapshot snapshot() const {
        Snapshot s;
        s.count = count();
        s.sum = sum();
        s.min_val = min();
        s.max_val = max();
        for (size_t i = 0; i < kTotalBuckets; ++i) {
            s.counts[i] = counts_[i].load(std::memory_order_relaxed);
        }
        return s;
    }

private:
    /// Calculate bucket index for a value
    [[nodiscard]] static constexpr size_t bucket_index(uint64_t value) noexcept {
        if (value == 0) return 0;

        // Find highest set bit (log2)
        size_t leading_zeros = static_cast<size_t>(__builtin_clzll(value));
        size_t significant_bits = 64 - leading_zeros;

        if (significant_bits <= SubBucketBits) {
            // Value fits in sub-bucket range
            return value - 1;
        }

        // Major bucket = log2(value) - SubBucketBits
        size_t bucket = significant_bits - SubBucketBits - 1;

        // Sub-bucket = top SubBucketBits of the value (after the leading 1)
        size_t shift = significant_bits - SubBucketBits - 1;
        size_t sub_bucket = (value >> shift) & kSubBucketMask;

        return (bucket * kSubBuckets) + sub_bucket + kSubBuckets - 1;
    }

    /// Calculate representative value for a bucket index
    [[nodiscard]] static constexpr uint64_t bucket_value(size_t index) noexcept {
        if (index < kSubBuckets - 1) {
            return index + 1;
        }

        size_t adjusted = index - (kSubBuckets - 1);
        size_t bucket = adjusted / kSubBuckets;
        size_t sub_bucket = adjusted % kSubBuckets;

        // Value = (sub_bucket + kSubBuckets) << bucket
        return (static_cast<uint64_t>(sub_bucket) + kSubBuckets) << bucket;
    }

    std::array<std::atomic<uint64_t>, kTotalBuckets> counts_;
    std::atomic<uint64_t> total_count_{0};
    std::atomic<uint64_t> total_sum_{0};
    std::atomic<uint64_t> min_{std::numeric_limits<uint64_t>::max()};
    std::atomic<uint64_t> max_{0};
};

/// Pre-configured histogram for latency measurements (nanoseconds)
using LatencyHistogram = Histogram<7>;  // 128 sub-buckets

/// Histogram with higher precision for microbenchmarks
using PrecisionHistogram = Histogram<10>;  // 1024 sub-buckets

}  // namespace signet
