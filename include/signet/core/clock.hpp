// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#include <cpuid.h>
#define SIGNET_HAS_RDTSC 1
#elif defined(__aarch64__)
#define SIGNET_HAS_RDTSC 0
#else
#define SIGNET_HAS_RDTSC 0
#endif

namespace signet {

/// High-resolution clock using RDTSC on x86_64
/// Falls back to std::chrono on other architectures
class Clock {
public:
    /// Initialize clock and calibrate TSC frequency
    static void initialize() {
        if (initialized_.load(std::memory_order_relaxed)) {
            return;
        }
        calibrate();
        initialized_.store(true, std::memory_order_release);
    }

    /// Read current timestamp in cycles (x86_64) or nanoseconds (other)
    [[nodiscard]] static inline uint64_t now() noexcept {
#if SIGNET_HAS_RDTSC
        // Use rdtscp for serializing read with processor ID
        unsigned int aux;
        return __rdtscp(&aux);
#else
        return static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
#endif
    }

    /// Read timestamp with memory fence for accurate measurements
    [[nodiscard]] static inline uint64_t now_fenced() noexcept {
#if SIGNET_HAS_RDTSC
        // lfence before to prevent reordering of prior instructions
        _mm_lfence();
        uint64_t tsc = now();
        // mfence after to prevent reordering with subsequent instructions
        _mm_mfence();
        return tsc;
#else
        return now();
#endif
    }

    /// Convert cycles to nanoseconds
    [[nodiscard]] static inline uint64_t cycles_to_ns(uint64_t cycles) noexcept {
#if SIGNET_HAS_RDTSC
        // Use fixed-point arithmetic for speed
        // cycles * 1e9 / frequency = cycles * ns_per_cycle_scaled >> 32
        return (cycles * ns_per_cycle_scaled_.load(std::memory_order_relaxed)) >> 32;
#else
        // Already in nanoseconds on non-x86
        return cycles;
#endif
    }

    /// Convert nanoseconds to cycles
    [[nodiscard]] static inline uint64_t ns_to_cycles(uint64_t ns) noexcept {
#if SIGNET_HAS_RDTSC
        return (ns * cycles_per_ns_scaled_.load(std::memory_order_relaxed)) >> 32;
#else
        return ns;
#endif
    }

    /// Get elapsed nanoseconds between two timestamps
    [[nodiscard]] static inline uint64_t elapsed_ns(uint64_t start, uint64_t end) noexcept {
        return cycles_to_ns(end - start);
    }

    /// Get TSC frequency in Hz (for diagnostics)
    [[nodiscard]] static uint64_t tsc_frequency() noexcept {
        return tsc_frequency_.load(std::memory_order_relaxed);
    }

    /// Check if TSC is invariant (constant frequency)
    [[nodiscard]] static bool is_invariant_tsc() noexcept {
        return invariant_tsc_.load(std::memory_order_relaxed);
    }

private:
    static void calibrate() {
#if SIGNET_HAS_RDTSC
        // Check for invariant TSC via CPUID
        check_invariant_tsc();

        // Calibrate TSC frequency by measuring against steady_clock
        constexpr int kCalibrationRuns = 5;
        constexpr auto kCalibrationDuration = std::chrono::milliseconds(10);

        uint64_t total_freq = 0;
        for (int i = 0; i < kCalibrationRuns; ++i) {
            auto start_time = std::chrono::steady_clock::now();
            uint64_t start_tsc = now_fenced();

            // Busy wait for calibration duration
            while (std::chrono::steady_clock::now() - start_time < kCalibrationDuration) {
                // Spin
            }

            uint64_t end_tsc = now_fenced();
            auto end_time = std::chrono::steady_clock::now();

            auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                end_time - start_time).count();
            uint64_t elapsed_cycles = end_tsc - start_tsc;

            // Frequency = cycles / seconds = cycles * 1e9 / nanoseconds
            uint64_t freq = (elapsed_cycles * 1'000'000'000ULL) / static_cast<uint64_t>(elapsed_ns);
            total_freq += freq;
        }

        uint64_t avg_freq = total_freq / kCalibrationRuns;
        tsc_frequency_.store(avg_freq, std::memory_order_relaxed);

        // Pre-compute scaled conversion factors for fast fixed-point math
        // ns_per_cycle = 1e9 / freq, scaled by 2^32
        // = (1e9 << 32) / freq
        uint64_t ns_scaled = (1'000'000'000ULL << 32) / avg_freq;
        ns_per_cycle_scaled_.store(ns_scaled, std::memory_order_relaxed);

        // cycles_per_ns = freq / 1e9, scaled by 2^32
        // = (freq << 32) / 1e9
        uint64_t cycles_scaled = (avg_freq << 32) / 1'000'000'000ULL;
        cycles_per_ns_scaled_.store(cycles_scaled, std::memory_order_relaxed);
#else
        tsc_frequency_.store(1'000'000'000ULL, std::memory_order_relaxed);  // 1 GHz (ns units)
        ns_per_cycle_scaled_.store(1ULL << 32, std::memory_order_relaxed);
        cycles_per_ns_scaled_.store(1ULL << 32, std::memory_order_relaxed);
#endif
    }

#if SIGNET_HAS_RDTSC
    static void check_invariant_tsc() {
        // CPUID leaf 0x80000007, EDX bit 8 indicates invariant TSC
        unsigned int eax, ebx, ecx, edx;
        __cpuid_count(0x80000007, 0, eax, ebx, ecx, edx);
        invariant_tsc_.store((edx & (1 << 8)) != 0, std::memory_order_relaxed);
    }
#endif

    static inline std::atomic<bool> initialized_{false};
    static inline std::atomic<bool> invariant_tsc_{false};
    static inline std::atomic<uint64_t> tsc_frequency_{0};
    static inline std::atomic<uint64_t> ns_per_cycle_scaled_{0};
    static inline std::atomic<uint64_t> cycles_per_ns_scaled_{0};
};

/// RAII timer for measuring elapsed time
class ScopedTimer {
public:
    explicit ScopedTimer() noexcept : start_(Clock::now_fenced()) {}

    /// Get elapsed nanoseconds without stopping
    [[nodiscard]] uint64_t elapsed_ns() const noexcept {
        return Clock::elapsed_ns(start_, Clock::now_fenced());
    }

    /// Stop and return elapsed nanoseconds
    [[nodiscard]] uint64_t stop() noexcept {
        return elapsed_ns();
    }

    /// Reset the timer
    void reset() noexcept {
        start_ = Clock::now_fenced();
    }

private:
    uint64_t start_;
};

}  // namespace signet
