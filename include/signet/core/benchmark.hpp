// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/clock.hpp"
#include "signet/core/histogram.hpp"
#include "signet/core/metrics.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace signet::benchmark {

/// Configuration for a benchmark run
struct Config {
    size_t warmup_iterations = 10000;
    size_t measurement_iterations = 1000000;
    std::chrono::milliseconds min_duration{1000};
    bool pin_cpu = false;
    int cpu_core = 0;
    bool disable_cpu_scaling = false;
    bool verbose = false;
};

/// Result of a single benchmark
struct Result {
    std::string name;
    size_t iterations;
    uint64_t total_ns;

    // Latency percentiles (nanoseconds)
    uint64_t p50;
    uint64_t p90;
    uint64_t p95;
    uint64_t p99;
    uint64_t p999;
    uint64_t p9999;
    uint64_t min;
    uint64_t max;
    double mean;
    double stddev;

    // Throughput
    double ops_per_sec;
    double ns_per_op;

    /// Export to JSON
    [[nodiscard]] std::string to_json() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << "{";
        oss << "\"name\":\"" << name << "\",";
        oss << "\"iterations\":" << iterations << ",";
        oss << "\"total_ns\":" << total_ns << ",";
        oss << "\"p50\":" << p50 << ",";
        oss << "\"p90\":" << p90 << ",";
        oss << "\"p95\":" << p95 << ",";
        oss << "\"p99\":" << p99 << ",";
        oss << "\"p999\":" << p999 << ",";
        oss << "\"p9999\":" << p9999 << ",";
        oss << "\"min\":" << min << ",";
        oss << "\"max\":" << max << ",";
        oss << "\"mean\":" << mean << ",";
        oss << "\"stddev\":" << stddev << ",";
        oss << "\"ops_per_sec\":" << ops_per_sec << ",";
        oss << "\"ns_per_op\":" << ns_per_op;
        oss << "}";
        return oss.str();
    }

    /// Format as human-readable string
    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << name << ":\n";
        oss << "  Iterations: " << iterations << "\n";
        oss << "  Latency (ns):\n";
        oss << "    p50:   " << std::setw(10) << p50 << "\n";
        oss << "    p90:   " << std::setw(10) << p90 << "\n";
        oss << "    p95:   " << std::setw(10) << p95 << "\n";
        oss << "    p99:   " << std::setw(10) << p99 << "\n";
        oss << "    p999:  " << std::setw(10) << p999 << "\n";
        oss << "    p9999: " << std::setw(10) << p9999 << "\n";
        oss << "    min:   " << std::setw(10) << min << "\n";
        oss << "    max:   " << std::setw(10) << max << "\n";
        oss << "    mean:  " << std::setw(10) << mean << "\n";
        oss << "    stddev:" << std::setw(10) << stddev << "\n";
        oss << "  Throughput: " << ops_per_sec << " ops/sec\n";
        return oss.str();
    }
};

/// Comparison result between two implementations
struct Comparison {
    Result baseline;
    Result candidate;

    // Improvement ratios (>1.0 means candidate is better)
    double p50_improvement;
    double p99_improvement;
    double p999_improvement;
    double throughput_improvement;

    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << "Comparison: " << baseline.name << " vs " << candidate.name << "\n";
        oss << "═══════════════════════════════════════════════════════════\n";
        oss << "Metric          │ " << std::setw(15) << baseline.name
            << " │ " << std::setw(15) << candidate.name << " │ Improvement\n";
        oss << "────────────────┼─────────────────┼─────────────────┼────────────\n";
        oss << "p50 (ns)        │ " << std::setw(15) << baseline.p50
            << " │ " << std::setw(15) << candidate.p50
            << " │ " << p50_improvement << "x\n";
        oss << "p99 (ns)        │ " << std::setw(15) << baseline.p99
            << " │ " << std::setw(15) << candidate.p99
            << " │ " << p99_improvement << "x\n";
        oss << "p999 (ns)       │ " << std::setw(15) << baseline.p999
            << " │ " << std::setw(15) << candidate.p999
            << " │ " << p999_improvement << "x\n";
        oss << "Throughput      │ " << std::setw(15) << baseline.ops_per_sec
            << " │ " << std::setw(15) << candidate.ops_per_sec
            << " │ " << throughput_improvement << "x\n";
        return oss.str();
    }

    [[nodiscard]] std::string to_json() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(4);
        oss << "{";
        oss << "\"baseline\":" << baseline.to_json() << ",";
        oss << "\"candidate\":" << candidate.to_json() << ",";
        oss << "\"p50_improvement\":" << p50_improvement << ",";
        oss << "\"p99_improvement\":" << p99_improvement << ",";
        oss << "\"p999_improvement\":" << p999_improvement << ",";
        oss << "\"throughput_improvement\":" << throughput_improvement;
        oss << "}";
        return oss.str();
    }
};

/// Interface for benchmarkable operations
class IBenchmarkable {
public:
    virtual ~IBenchmarkable() = default;

    /// Name of this implementation
    [[nodiscard]] virtual std::string name() const = 0;

    /// Setup before benchmark (not timed)
    virtual void setup() {}

    /// Teardown after benchmark (not timed)
    virtual void teardown() {}

    /// The operation to benchmark (timed)
    virtual void run() = 0;
};

/// Benchmark harness for running and comparing benchmarks
class Harness {
public:
    explicit Harness(Config config = {}) : config_(std::move(config)) {
        Clock::initialize();
    }

    /// Run a benchmark
    Result run(IBenchmarkable& bench) {
        // Setup
        bench.setup();

        // Warmup
        if (config_.verbose) {
            std::cout << "Warming up " << bench.name() << "...\n";
        }
        for (size_t i = 0; i < config_.warmup_iterations; ++i) {
            bench.run();
        }

        // Measurement
        if (config_.verbose) {
            std::cout << "Measuring " << bench.name() << "...\n";
        }

        LatencyHistogram hist;
        uint64_t total_start = Clock::now_fenced();

        for (size_t i = 0; i < config_.measurement_iterations; ++i) {
            uint64_t start = Clock::now_fenced();
            bench.run();
            uint64_t end = Clock::now_fenced();
            hist.record(Clock::elapsed_ns(start, end));
        }

        uint64_t total_end = Clock::now_fenced();
        uint64_t total_ns = Clock::elapsed_ns(total_start, total_end);

        // Teardown
        bench.teardown();

        // Build result
        Result result;
        result.name = bench.name();
        result.iterations = config_.measurement_iterations;
        result.total_ns = total_ns;
        result.p50 = hist.p50();
        result.p90 = hist.p90();
        result.p95 = hist.p95();
        result.p99 = hist.p99();
        result.p999 = hist.p999();
        result.p9999 = hist.p9999();
        result.min = hist.min();
        result.max = hist.max();
        result.mean = hist.mean();

        // Calculate stddev from histogram
        result.stddev = calculate_stddev(hist);

        // Throughput
        result.ns_per_op = static_cast<double>(total_ns) / static_cast<double>(config_.measurement_iterations);
        result.ops_per_sec = 1'000'000'000.0 / result.ns_per_op;

        return result;
    }

    /// Run a benchmark using a lambda
    template<typename F>
    Result run(std::string_view name, F&& func) {
        class LambdaBench : public IBenchmarkable {
        public:
            LambdaBench(std::string n, F f) : name_(std::move(n)), func_(std::move(f)) {}
            [[nodiscard]] std::string name() const override { return name_; }
            void run() override { func_(); }
        private:
            std::string name_;
            F func_;
        };

        LambdaBench bench(std::string(name), std::forward<F>(func));
        return run(bench);
    }

    /// Compare two implementations
    Comparison compare(IBenchmarkable& baseline, IBenchmarkable& candidate) {
        Result baseline_result = run(baseline);
        Result candidate_result = run(candidate);

        Comparison comp;
        comp.baseline = baseline_result;
        comp.candidate = candidate_result;

        // Calculate improvements (higher is better for candidate)
        comp.p50_improvement = static_cast<double>(baseline_result.p50) /
                              static_cast<double>(candidate_result.p50);
        comp.p99_improvement = static_cast<double>(baseline_result.p99) /
                              static_cast<double>(candidate_result.p99);
        comp.p999_improvement = static_cast<double>(baseline_result.p999) /
                               static_cast<double>(candidate_result.p999);
        comp.throughput_improvement = candidate_result.ops_per_sec /
                                      baseline_result.ops_per_sec;

        return comp;
    }

    /// Run multiple benchmarks and return all results
    std::vector<Result> run_all(std::vector<std::reference_wrapper<IBenchmarkable>> benchmarks) {
        std::vector<Result> results;
        results.reserve(benchmarks.size());
        for (auto& bench : benchmarks) {
            results.push_back(run(bench.get()));
        }
        return results;
    }

private:
    double calculate_stddev(const LatencyHistogram& hist) {
        // Approximate stddev from histogram
        double count = static_cast<double>(hist.count());
        if (count < 2) return 0.0;

        // Use p50 and p99 to estimate stddev
        // Assuming roughly normal distribution: stddev ≈ (p99 - p50) / 2.33
        double p99 = static_cast<double>(hist.p99());
        double p50 = static_cast<double>(hist.p50());
        return (p99 - p50) / 2.33;
    }

    Config config_;
};

/// Macro for defining benchmarks
#define SIGNET_BENCHMARK(name) \
    class Benchmark_##name : public ::signet::benchmark::IBenchmarkable { \
    public: \
        [[nodiscard]] std::string name() const override { return #name; } \
        void run() override; \
    }; \
    void Benchmark_##name::run()

/// Report generator for benchmark results
class ReportGenerator {
public:
    /// Generate Markdown report
    static std::string to_markdown(const std::vector<Result>& results) {
        std::ostringstream oss;
        oss << "# Benchmark Results\n\n";
        oss << "## Summary\n\n";
        oss << "| Benchmark | p50 (ns) | p99 (ns) | p999 (ns) | ops/sec |\n";
        oss << "|-----------|----------|----------|-----------|----------|\n";

        for (const auto& r : results) {
            oss << "| " << r.name
                << " | " << r.p50
                << " | " << r.p99
                << " | " << r.p999
                << " | " << std::fixed << std::setprecision(0) << r.ops_per_sec
                << " |\n";
        }

        oss << "\n## Detailed Results\n\n";
        for (const auto& r : results) {
            oss << r.to_string() << "\n";
        }

        return oss.str();
    }

    /// Generate JSON report
    static std::string to_json(const std::vector<Result>& results) {
        std::ostringstream oss;
        oss << "{\"results\":[";
        bool first = true;
        for (const auto& r : results) {
            if (!first) oss << ",";
            oss << r.to_json();
            first = false;
        }
        oss << "]}";
        return oss.str();
    }

    /// Generate comparison Markdown
    static std::string comparison_to_markdown(const Comparison& comp) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);

        oss << "# Performance Comparison\n\n";
        oss << "**" << comp.baseline.name << "** vs **" << comp.candidate.name << "**\n\n";

        oss << "## Latency Improvements\n\n";
        oss << "| Percentile | " << comp.baseline.name << " | "
            << comp.candidate.name << " | Improvement |\n";
        oss << "|------------|";
        for (int i = 0; i < 3; ++i) oss << "------------|";
        oss << "\n";

        oss << "| p50 | " << comp.baseline.p50 << "ns | "
            << comp.candidate.p50 << "ns | **" << comp.p50_improvement << "x** |\n";
        oss << "| p99 | " << comp.baseline.p99 << "ns | "
            << comp.candidate.p99 << "ns | **" << comp.p99_improvement << "x** |\n";
        oss << "| p999 | " << comp.baseline.p999 << "ns | "
            << comp.candidate.p999 << "ns | **" << comp.p999_improvement << "x** |\n";

        oss << "\n## Throughput\n\n";
        oss << "| Implementation | ops/sec | Improvement |\n";
        oss << "|----------------|---------|-------------|\n";
        oss << "| " << comp.baseline.name << " | "
            << static_cast<uint64_t>(comp.baseline.ops_per_sec) << " | - |\n";
        oss << "| " << comp.candidate.name << " | "
            << static_cast<uint64_t>(comp.candidate.ops_per_sec) << " | **"
            << comp.throughput_improvement << "x** |\n";

        return oss.str();
    }
};

}  // namespace signet::benchmark
