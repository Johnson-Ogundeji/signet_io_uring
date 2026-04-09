// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/core/buffer_pool.hpp>

#include <thread>
#include <vector>

namespace signet::test {

class BufferPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        Clock::initialize();
    }
};

TEST_F(BufferPoolTest, InitializeWithDefaults) {
    BufferPoolConfig config;
    config.count = 8;
    config.size = 1024;

    BufferPool pool(config);
    auto result = pool.init();

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(pool.is_initialized());
    EXPECT_EQ(pool.count(), 8);
    EXPECT_EQ(pool.buffer_size(), 1024);
}

TEST_F(BufferPoolTest, AcquireReturnsValidBuffer) {
    BufferPoolConfig config;
    config.count = 4;
    config.size = 512;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    auto buffer = pool.acquire();

    EXPECT_TRUE(buffer.valid());
    EXPECT_NE(buffer.data(), nullptr);
    EXPECT_EQ(buffer.capacity(), 512);
    EXPECT_EQ(buffer.size(), 0);
}

TEST_F(BufferPoolTest, BufferHandleOperations) {
    BufferPoolConfig config;
    config.count = 1;
    config.size = 256;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    auto buffer = pool.acquire();

    // Test append
    std::string_view data = "Hello, World!";
    size_t written = buffer.append(data);
    EXPECT_EQ(written, data.size());
    EXPECT_EQ(buffer.size(), data.size());

    // Test string_view
    EXPECT_EQ(buffer.string_view(), data);

    // Test resize
    buffer.resize(5);
    EXPECT_EQ(buffer.size(), 5);
    EXPECT_EQ(buffer.string_view(), "Hello");

    // Test clear
    buffer.clear();
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_TRUE(buffer.empty());
}

TEST_F(BufferPoolTest, ExhaustsPool) {
    BufferPoolConfig config;
    config.count = 4;
    config.size = 64;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    std::vector<BufferHandle> handles;

    // Acquire all buffers
    for (int i = 0; i < 4; ++i) {
        auto handle = pool.acquire();
        EXPECT_TRUE(handle.valid()) << "Failed to acquire buffer " << i;
        handles.push_back(std::move(handle));
    }

    // Next acquire should fail
    auto extra = pool.acquire();
    EXPECT_FALSE(extra.valid());

    // Check stats
    auto stats = pool.stats();
    EXPECT_EQ(stats.in_use_count, 4);
    EXPECT_EQ(stats.available_count, 0);
    EXPECT_EQ(stats.acquire_failures, 1);
}

TEST_F(BufferPoolTest, ReleaseReturnsToPool) {
    BufferPoolConfig config;
    config.count = 2;
    config.size = 64;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    {
        auto handle1 = pool.acquire();
        auto handle2 = pool.acquire();

        EXPECT_TRUE(handle1.valid());
        EXPECT_TRUE(handle2.valid());

        auto stats = pool.stats();
        EXPECT_EQ(stats.in_use_count, 2);
    }
    // Handles destroyed, buffers returned

    auto stats = pool.stats();
    EXPECT_EQ(stats.in_use_count, 0);
    EXPECT_EQ(stats.available_count, 2);

    // Should be able to acquire again
    auto handle = pool.acquire();
    EXPECT_TRUE(handle.valid());
}

TEST_F(BufferPoolTest, TryAcquire) {
    BufferPoolConfig config;
    config.count = 1;
    config.size = 64;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    auto opt1 = pool.try_acquire();
    EXPECT_TRUE(opt1.has_value());

    auto opt2 = pool.try_acquire();
    EXPECT_FALSE(opt2.has_value());
}

TEST_F(BufferPoolTest, BufferAlignment) {
    BufferPoolConfig config;
    config.count = 4;
    config.size = 4096;
    config.alignment = 4096;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    auto handle = pool.acquire();
    auto ptr = reinterpret_cast<uintptr_t>(handle.data());

    // Check alignment
    EXPECT_EQ(ptr % 4096, 0);
}

TEST_F(BufferPoolTest, BufferAtIndex) {
    BufferPoolConfig config;
    config.count = 4;
    config.size = 1024;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    // buffer_at should return consistent pointers
    auto* buf0 = pool.buffer_at(0);
    auto* buf1 = pool.buffer_at(1);

    EXPECT_NE(buf0, nullptr);
    EXPECT_NE(buf1, nullptr);
    EXPECT_NE(buf0, buf1);

    // Out of bounds should return nullptr
    EXPECT_EQ(pool.buffer_at(100), nullptr);
}

TEST_F(BufferPoolTest, ThreadSafety) {
    BufferPoolConfig config;
    config.count = 32;
    config.size = 256;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    constexpr int kThreads = 4;
    constexpr int kIterations = 1000;

    std::atomic<int> successful_acquires{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&pool, &successful_acquires]() {
            for (int i = 0; i < kIterations; ++i) {
                auto handle = pool.acquire();
                if (handle.valid()) {
                    successful_acquires.fetch_add(1);
                    // Simulate some work
                    handle.append("data");
                    std::this_thread::yield();
                    // Handle released on destruction
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    auto stats = pool.stats();

    // All buffers should be returned
    EXPECT_EQ(stats.in_use_count, 0);
    EXPECT_EQ(stats.available_count, 32);

    // Releases should equal successful acquires
    EXPECT_EQ(stats.total_releases, static_cast<uint64_t>(successful_acquires.load()));
}

TEST_F(BufferPoolTest, MoveSemantics) {
    BufferPoolConfig config;
    config.count = 2;
    config.size = 64;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    BufferHandle h1 = pool.acquire();
    EXPECT_TRUE(h1.valid());

    // Move construct
    BufferHandle h2 = std::move(h1);
    EXPECT_FALSE(h1.valid());
    EXPECT_TRUE(h2.valid());

    // Move assign
    BufferHandle h3;
    h3 = std::move(h2);
    EXPECT_FALSE(h2.valid());
    EXPECT_TRUE(h3.valid());
}

TEST_F(BufferPoolTest, Stats) {
    BufferPoolConfig config;
    config.count = 8;
    config.size = 128;

    BufferPool pool(config);
    ASSERT_TRUE(pool.init().has_value());

    auto stats = pool.stats();
    EXPECT_EQ(stats.total_count, 8);
    EXPECT_EQ(stats.buffer_size, 128);
    EXPECT_EQ(stats.available_count, 8);
    EXPECT_EQ(stats.in_use_count, 0);
    EXPECT_EQ(stats.total_acquires, 0);
    EXPECT_EQ(stats.total_releases, 0);

    {
        auto h1 = pool.acquire();
        auto h2 = pool.acquire();

        stats = pool.stats();
        EXPECT_EQ(stats.in_use_count, 2);
        EXPECT_EQ(stats.total_acquires, 2);
    }

    stats = pool.stats();
    EXPECT_EQ(stats.in_use_count, 0);
    EXPECT_EQ(stats.total_releases, 2);
}

}  // namespace signet::test
