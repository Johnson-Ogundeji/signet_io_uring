// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <signet/core/ring.hpp>

#include <cstring>
#include <sys/eventfd.h>
#include <unistd.h>

namespace signet::test {

class RingTest : public ::testing::Test {
protected:
    void SetUp() override {
        Clock::initialize();
    }
};

TEST_F(RingTest, InitializeWithDefaults) {
    Config config;
    config.sq_entries = 64;
    config.enable_sqpoll = false;

    Ring ring(config);
    auto result = ring.init();

    ASSERT_TRUE(result.has_value()) << result.error().to_string();
    EXPECT_TRUE(ring.is_initialized());
    EXPECT_FALSE(ring.is_sqpoll_active());
}

TEST_F(RingTest, DoubleInitFails) {
    Config config;
    Ring ring(config);

    ASSERT_TRUE(ring.init().has_value());

    auto result = ring.init();
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), ErrorCode::AlreadyExists);
}

TEST_F(RingTest, GetSqeReturnsNonNull) {
    Config config;
    config.sq_entries = 32;

    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    auto* sqe = ring.get_sqe();
    EXPECT_NE(sqe, nullptr);
}

TEST_F(RingTest, NopOperation) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    // Submit a NOP
    bool prepared = ring.prep_nop(reinterpret_cast<void*>(0x12345));
    EXPECT_TRUE(prepared);

    auto submit_result = ring.submit();
    ASSERT_TRUE(submit_result.has_value());
    EXPECT_EQ(*submit_result, 1);

    // Wait for completion
    auto cqe_result = ring.wait_cqe(1000);
    ASSERT_TRUE(cqe_result.has_value());

    auto* cqe = *cqe_result;
    EXPECT_EQ(cqe->res, 0);  // NOP always succeeds
    EXPECT_EQ(io_uring_cqe_get_data(cqe), reinterpret_cast<void*>(0x12345));

    ring.seen_cqe(cqe);
}

TEST_F(RingTest, ProcessCompletions) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    // Submit multiple NOPs
    for (int i = 0; i < 5; ++i) {
        ring.prep_nop(reinterpret_cast<void*>(static_cast<uintptr_t>(i)));
    }
    (void)ring.submit();

    // Wait for at least one
    (void)ring.wait_cqe(1000);

    // Process all
    int count = 0;
    ring.process_completions([&count](int32_t result, void* /*user_data*/) {
        EXPECT_EQ(result, 0);
        ++count;
    });

    EXPECT_EQ(count, 5);
}

TEST_F(RingTest, PeekCqeNonBlocking) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    // No pending completions
    auto* cqe = ring.peek_cqe();
    EXPECT_EQ(cqe, nullptr);

    // Submit NOP
    ring.prep_nop(nullptr);
    (void)ring.submit();

    // Wait then peek
    (void)ring.wait_cqe(1000);
    cqe = ring.peek_cqe();
    EXPECT_NE(cqe, nullptr);

    ring.seen_cqe(cqe);
}

TEST_F(RingTest, TimeoutOperation) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    struct __kernel_timespec ts{};
    ts.tv_sec = 0;
    ts.tv_nsec = 10'000'000;  // 10ms

    ring.prep_timeout(&ts, 0, reinterpret_cast<void*>(0x999));
    (void)ring.submit();

    auto result = ring.wait_cqe(1000);
    ASSERT_TRUE(result.has_value());

    auto* cqe = *result;
    // Timeout returns -ETIME
    EXPECT_EQ(cqe->res, -ETIME);

    ring.seen_cqe(cqe);
}

TEST_F(RingTest, ReadWriteWithEventfd) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    // Create eventfd for testing
    int efd = eventfd(0, EFD_NONBLOCK);
    ASSERT_GT(efd, 0);

    // Write to eventfd
    uint64_t write_val = 42;
    std::array<std::byte, 8> write_buf;
    std::memcpy(write_buf.data(), &write_val, 8);

    ring.prep_write(efd, write_buf, 0, reinterpret_cast<void*>(1));
    (void)ring.submit();

    auto result = ring.wait_cqe(1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)->res, 8);
    ring.seen_cqe(*result);

    // Read from eventfd
    std::array<std::byte, 8> read_buf{};
    ring.prep_read(efd, read_buf, 0, reinterpret_cast<void*>(2));
    (void)ring.submit();

    result = ring.wait_cqe(1000);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)->res, 8);
    ring.seen_cqe(*result);

    uint64_t read_val;
    std::memcpy(&read_val, read_buf.data(), 8);
    EXPECT_EQ(read_val, 42);

    close(efd);
}

TEST_F(RingTest, Statistics) {
    Config config;
    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    EXPECT_EQ(ring.total_submissions(), 0);
    EXPECT_EQ(ring.total_completions(), 0);

    // Submit some NOPs
    for (int i = 0; i < 3; ++i) {
        ring.prep_nop(nullptr);
    }
    (void)ring.submit();

    EXPECT_EQ(ring.total_submissions(), 3);

    // Process completions
    (void)ring.wait_cqe(1000);
    ring.process_completions([](int32_t, void*) {});

    EXPECT_EQ(ring.total_completions(), 3);
}

TEST_F(RingTest, SqSpaceTracking) {
    Config config;
    config.sq_entries = 16;

    Ring ring(config);
    ASSERT_TRUE(ring.init().has_value());

    // Initially should have space
    EXPECT_GT(ring.sq_space_left(), 0u);
    EXPECT_EQ(ring.sq_ready(), 0u);

    // Fill up some
    for (int i = 0; i < 8; ++i) {
        ring.prep_nop(nullptr);
    }

    EXPECT_EQ(ring.sq_ready(), 8u);

    // Submit clears ready
    (void)ring.submit();
    EXPECT_EQ(ring.sq_ready(), 0u);
}

TEST_F(RingTest, MoveSemantics) {
    Config config;
    Ring ring1(config);
    ASSERT_TRUE(ring1.init().has_value());

    // Move construct
    Ring ring2 = std::move(ring1);
    EXPECT_FALSE(ring1.is_initialized());
    EXPECT_TRUE(ring2.is_initialized());

    // Verify ring2 works
    ring2.prep_nop(nullptr);
    auto result = ring2.submit();
    EXPECT_TRUE(result.has_value());
}

// Skip SQPOLL test if not running as root
TEST_F(RingTest, DISABLED_SqpollMode) {
    Config config;
    config.enable_sqpoll = true;
    config.sqpoll_idle_ms = 1000;

    Ring ring(config);
    auto result = ring.init();

    if (!result.has_value()) {
        // May fail without CAP_SYS_NICE
        GTEST_SKIP() << "SQPOLL requires elevated privileges";
    }

    EXPECT_TRUE(ring.is_sqpoll_active());
}

}  // namespace signet::test
