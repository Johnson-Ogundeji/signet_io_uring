// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

/// @file basic_benchmark.cpp
/// @brief Basic benchmark demonstrating Signet's performance measurement infrastructure

#include <signet/signet.hpp>

#include <iostream>
#include <vector>

using namespace signet;
using namespace signet::benchmark;

/// Benchmark: Buffer pool acquire/release
class BufferPoolBench : public IBenchmarkable {
public:
    explicit BufferPoolBench(size_t pool_size) : pool_size_(pool_size) {}

    [[nodiscard]] std::string name() const override {
        return "BufferPool(" + std::to_string(pool_size_) + ")";
    }

    void setup() override {
        BufferPoolConfig config;
        config.count = pool_size_;
        config.size = 4096;
        pool_ = std::make_unique<BufferPool>(config);
        (void)pool_->init();
    }

    void teardown() override {
        pool_.reset();
    }

    void run() override {
        auto handle = pool_->acquire();
        // Simulate some work
        handle.append("benchmark data");
        // Handle released on destruction
    }

private:
    size_t pool_size_;
    std::unique_ptr<BufferPool> pool_;
};

/// Benchmark: io_uring NOP operation
class IoUringNopBench : public IBenchmarkable {
public:
    [[nodiscard]] std::string name() const override {
        return "IoUring_NOP";
    }

    void setup() override {
        signet::Config config;
        config.sq_entries = 256;
        ring_ = std::make_unique<Ring>(config);
        (void)ring_->init();
    }

    void teardown() override {
        ring_.reset();
    }

    void run() override {
        ring_->prep_nop(nullptr);
        (void)ring_->submit();
        auto cqe = ring_->wait_cqe(1000);
        if (cqe) {
            ring_->seen_cqe(*cqe);
        }
    }

private:
    std::unique_ptr<Ring> ring_;
};

/// Benchmark: Histogram recording
class HistogramBench : public IBenchmarkable {
public:
    [[nodiscard]] std::string name() const override {
        return "Histogram_Record";
    }

    void setup() override {
        hist_ = std::make_unique<LatencyHistogram>();
        value_ = 1000;  // 1μs
    }

    void run() override {
        hist_->record(value_++);
    }

private:
    std::unique_ptr<LatencyHistogram> hist_;
    uint64_t value_ = 0;
};

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           Signet v" << version() << " Basic Benchmark                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n\n";

    // Initialize
    initialize();

    // Check system capabilities
    std::cout << "System Capabilities:\n";
    std::cout << "  io_uring supported: " << (is_iouring_supported() ? "Yes" : "No") << "\n";
    std::cout << "  kTLS supported:     " << (is_ktls_supported() ? "Yes" : "No") << "\n";
    std::cout << "  SIMD level:         ";
    switch (detect_simd_level()) {
        case SimdLevel::AVX512: std::cout << "AVX-512"; break;
        case SimdLevel::AVX2: std::cout << "AVX2"; break;
        case SimdLevel::SSE42: std::cout << "SSE 4.2"; break;
        case SimdLevel::NEON: std::cout << "NEON"; break;
        default: std::cout << "None"; break;
    }
    std::cout << "\n";
    std::cout << "  TSC frequency:      " << Clock::tsc_frequency() / 1'000'000 << " MHz\n";
    std::cout << "  Invariant TSC:      " << (Clock::is_invariant_tsc() ? "Yes" : "No") << "\n";
    std::cout << "\n";

    // Configure benchmark harness
    benchmark::Config bench_config;
    bench_config.warmup_iterations = 10000;
    bench_config.measurement_iterations = 100000;
    bench_config.verbose = true;

    Harness harness(bench_config);

    // Run benchmarks
    std::vector<Result> results;

    std::cout << "Running benchmarks...\n\n";

    // Buffer pool benchmarks
    BufferPoolBench bp16(16);
    BufferPoolBench bp64(64);
    BufferPoolBench bp256(256);

    results.push_back(harness.run(bp16));
    results.push_back(harness.run(bp64));
    results.push_back(harness.run(bp256));

    // Histogram benchmark
    HistogramBench hist_bench;
    results.push_back(harness.run(hist_bench));

    // io_uring NOP benchmark
    IoUringNopBench nop_bench;
    results.push_back(harness.run(nop_bench));

    // Print results
    std::cout << "\n" << ReportGenerator::to_markdown(results);

    // Print JSON (for automation)
    std::cout << "\nJSON Output:\n";
    std::cout << ReportGenerator::to_json(results) << "\n";

    // Print global metrics
    std::cout << "\nGlobal Metrics:\n";
    std::cout << global_metrics().to_json() << "\n";

    return 0;
}
