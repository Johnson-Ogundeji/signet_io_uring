// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/core/histogram.hpp>

#include <random>
#include <thread>
#include <vector>

namespace signet::test {

class HistogramTest : public ::testing::Test {
protected:
    LatencyHistogram hist;
};

TEST_F(HistogramTest, EmptyHistogram) {
    EXPECT_EQ(hist.count(), 0);
    EXPECT_EQ(hist.sum(), 0);
    EXPECT_EQ(hist.p50(), 0);
    EXPECT_EQ(hist.p99(), 0);
}

TEST_F(HistogramTest, SingleValue) {
    hist.record(1000);  // 1μs

    EXPECT_EQ(hist.count(), 1);
    EXPECT_EQ(hist.sum(), 1000);
    EXPECT_EQ(hist.min(), 1000);
    EXPECT_EQ(hist.max(), 1000);
}

TEST_F(HistogramTest, MultipleValues) {
    for (uint64_t i = 1; i <= 100; ++i) {
        hist.record(i * 1000);  // 1-100μs
    }

    EXPECT_EQ(hist.count(), 100);
    EXPECT_EQ(hist.min(), 1000);
    EXPECT_EQ(hist.max(), 100000);

    // p50 should be around 50μs
    EXPECT_GT(hist.p50(), 40000);
    EXPECT_LT(hist.p50(), 60000);
}

TEST_F(HistogramTest, PercentilesAreOrdered) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, 1000000);

    for (int i = 0; i < 10000; ++i) {
        hist.record(dis(gen));
    }

    EXPECT_LE(hist.min(), hist.p50());
    EXPECT_LE(hist.p50(), hist.p90());
    EXPECT_LE(hist.p90(), hist.p95());
    EXPECT_LE(hist.p95(), hist.p99());
    EXPECT_LE(hist.p99(), hist.p999());
    EXPECT_LE(hist.p999(), hist.max());
}

TEST_F(HistogramTest, Reset) {
    hist.record(1000);
    hist.record(2000);

    hist.reset();

    EXPECT_EQ(hist.count(), 0);
    EXPECT_EQ(hist.sum(), 0);
}

TEST_F(HistogramTest, RecordN) {
    hist.record_n(1000, 100);  // Record 1000 one hundred times

    EXPECT_EQ(hist.count(), 100);
    EXPECT_EQ(hist.sum(), 100000);
}

TEST_F(HistogramTest, Merge) {
    LatencyHistogram hist2;

    for (int i = 0; i < 100; ++i) {
        hist.record(1000);
        hist2.record(2000);
    }

    hist.merge(hist2);

    EXPECT_EQ(hist.count(), 200);
    EXPECT_EQ(hist.min(), 1000);
    EXPECT_EQ(hist.max(), 2000);
}

TEST_F(HistogramTest, ToJsonFormat) {
    hist.record(1000);
    hist.record(2000);
    hist.record(3000);

    std::string json = hist.to_json();

    EXPECT_NE(json.find("\"count\":3"), std::string::npos);
    EXPECT_NE(json.find("\"p50\":"), std::string::npos);
    EXPECT_NE(json.find("\"p99\":"), std::string::npos);
}

TEST_F(HistogramTest, LargeValues) {
    // Test with values in the billions (nanoseconds for seconds)
    hist.record(1'000'000'000);   // 1 second
    hist.record(60'000'000'000);  // 1 minute

    EXPECT_EQ(hist.count(), 2);
    EXPECT_EQ(hist.min(), 1'000'000'000);
    EXPECT_EQ(hist.max(), 60'000'000'000);
}

TEST_F(HistogramTest, ThreadSafety) {
    constexpr int kThreads = 4;
    constexpr int kIterations = 10000;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < kIterations; ++i) {
                hist.record(static_cast<uint64_t>((t + 1) * 1000 + i));
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(hist.count(), kThreads * kIterations);
}

TEST_F(HistogramTest, Snapshot) {
    hist.record(1000);
    hist.record(2000);
    hist.record(3000);

    auto snap = hist.snapshot();

    EXPECT_EQ(snap.count, 3);
    EXPECT_EQ(snap.min_val, 1000);
    EXPECT_EQ(snap.max_val, 3000);
}

}  // namespace signet::test
