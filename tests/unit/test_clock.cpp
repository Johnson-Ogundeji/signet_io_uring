// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/core/clock.hpp>

#include <thread>

namespace signet::test {

class ClockTest : public ::testing::Test {
protected:
    void SetUp() override {
        Clock::initialize();
    }
};

TEST_F(ClockTest, InitializeSucceeds) {
    // Should not throw
    Clock::initialize();
    // Second call should be idempotent
    Clock::initialize();
}

TEST_F(ClockTest, NowReturnsIncreasingValues) {
    uint64_t t1 = Clock::now();
    uint64_t t2 = Clock::now();
    EXPECT_GE(t2, t1);
}

TEST_F(ClockTest, NowFencedReturnsIncreasingValues) {
    uint64_t t1 = Clock::now_fenced();
    uint64_t t2 = Clock::now_fenced();
    EXPECT_GE(t2, t1);
}

TEST_F(ClockTest, CyclesToNsConversion) {
    // Get a known duration
    auto start = Clock::now_fenced();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto end = Clock::now_fenced();

    uint64_t elapsed_ns = Clock::elapsed_ns(start, end);

    // Should be approximately 10ms = 10,000,000 ns
    // Allow 50% tolerance for sleep variance
    EXPECT_GT(elapsed_ns, 5'000'000);
    EXPECT_LT(elapsed_ns, 50'000'000);
}

TEST_F(ClockTest, ScopedTimerBasic) {
    ScopedTimer timer;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t elapsed = timer.elapsed_ns();

    // Should be at least 1ms
    EXPECT_GT(elapsed, 500'000);
}

TEST_F(ClockTest, ScopedTimerReset) {
    ScopedTimer timer;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    timer.reset();
    uint64_t elapsed = timer.elapsed_ns();

    // After reset, should be very small
    EXPECT_LT(elapsed, 10'000'000);  // Less than 10ms
}

TEST_F(ClockTest, TscFrequencyIsReasonable) {
    uint64_t freq = Clock::tsc_frequency();

    // TSC frequency should be between 500MHz and 10GHz for modern CPUs
    // Or 1GHz if falling back to nanosecond timing
    EXPECT_GT(freq, 100'000'000);      // > 100 MHz
    EXPECT_LT(freq, 20'000'000'000);   // < 20 GHz
}

}  // namespace signet::test
