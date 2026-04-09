// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/core/metrics.hpp>

namespace signet::test {

class MetricsTest : public ::testing::Test {
protected:
    void SetUp() override {
        Clock::initialize();
    }
};

TEST_F(MetricsTest, CounterBasic) {
    Counter counter;

    EXPECT_EQ(counter.value(), 0);

    counter.increment();
    EXPECT_EQ(counter.value(), 1);

    counter.increment(10);
    EXPECT_EQ(counter.value(), 11);

    counter.reset();
    EXPECT_EQ(counter.value(), 0);
}

TEST_F(MetricsTest, GaugeBasic) {
    Gauge gauge;

    EXPECT_EQ(gauge.value(), 0);

    gauge.set(100);
    EXPECT_EQ(gauge.value(), 100);

    gauge.increment();
    EXPECT_EQ(gauge.value(), 101);

    gauge.decrement();
    EXPECT_EQ(gauge.value(), 100);

    gauge.add(-50);
    EXPECT_EQ(gauge.value(), 50);
}

TEST_F(MetricsTest, TimerRecordsToHistogram) {
    LatencyHistogram hist;
    Timer timer(hist);

    {
        auto scope = timer.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_EQ(hist.count(), 1);
    EXPECT_GT(hist.p50(), 500000);  // > 0.5ms
}

TEST_F(MetricsTest, RegistryCreatesMetrics) {
    MetricsRegistry registry;

    auto& counter = registry.counter("test.counter");
    auto& gauge = registry.gauge("test.gauge");
    auto& hist = registry.histogram("test.histogram");

    counter.increment();
    gauge.set(42);
    hist.record(1000);

    EXPECT_EQ(registry.counter("test.counter").value(), 1);
    EXPECT_EQ(registry.gauge("test.gauge").value(), 42);
    EXPECT_EQ(registry.histogram("test.histogram").count(), 1);
}

TEST_F(MetricsTest, RegistryReturnsExisting) {
    MetricsRegistry registry;

    registry.counter("test").increment();
    registry.counter("test").increment();

    EXPECT_EQ(registry.counter("test").value(), 2);
}

TEST_F(MetricsTest, RegistryToJson) {
    MetricsRegistry registry;

    registry.counter("c1").increment();
    registry.gauge("g1").set(10);
    registry.histogram("h1").record(1000);

    std::string json = registry.to_json();

    EXPECT_NE(json.find("\"counters\""), std::string::npos);
    EXPECT_NE(json.find("\"gauges\""), std::string::npos);
    EXPECT_NE(json.find("\"histograms\""), std::string::npos);
    EXPECT_NE(json.find("\"c1\":1"), std::string::npos);
    EXPECT_NE(json.find("\"g1\":10"), std::string::npos);
}

TEST_F(MetricsTest, GlobalMetrics) {
    // Access global metrics
    auto& c = counter("global.test");
    auto& g = gauge("global.gauge");
    auto& h = histogram("global.hist");

    c.increment();
    g.set(5);
    h.record(100);

    EXPECT_EQ(counter("global.test").value(), 1);
    EXPECT_EQ(gauge("global.gauge").value(), 5);
    EXPECT_EQ(histogram("global.hist").count(), 1);
}

TEST_F(MetricsTest, InstrumentationMacros) {
    // These should compile and work when SIGNET_ENABLE_METRICS is defined
    SIGNET_COUNTER_INC("test.macro.counter");
    SIGNET_COUNTER_ADD("test.macro.counter2", 5);
    SIGNET_GAUGE_SET("test.macro.gauge", 42);
    SIGNET_GAUGE_INC("test.macro.gauge2");
    SIGNET_HISTOGRAM_RECORD("test.macro.hist", 1000);

    {
        SIGNET_TIMER_SCOPE("test.macro.timer");
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    // Verify they were recorded (metrics enabled in test build)
    EXPECT_EQ(counter("test.macro.counter").value(), 1);
    EXPECT_EQ(counter("test.macro.counter2").value(), 5);
    EXPECT_EQ(gauge("test.macro.gauge").value(), 42);
    EXPECT_EQ(histogram("test.macro.hist").count(), 1);
    EXPECT_GE(histogram("test.macro.timer").count(), 1);
}

}  // namespace signet::test
