// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/config.hpp"
#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/types.hpp"

#include <liburing.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <span>

namespace signet {

/// Completion callback for async operations
/// @param result Result code from CQE (positive = bytes, negative = -errno)
/// @param user_data User data associated with the operation
using CompletionCallback = std::function<void(int32_t result, void* user_data)>;

/// io_uring wrapper with zero-overhead instrumentation
class Ring {
public:
    /// Construct ring with configuration
    explicit Ring(const Config& config = {});

    /// Destructor - cleans up io_uring resources
    ~Ring();

    // Non-copyable
    Ring(const Ring&) = delete;
    Ring& operator=(const Ring&) = delete;

    // Movable
    Ring(Ring&& other) noexcept;
    Ring& operator=(Ring&& other) noexcept;

    /// Initialize the ring
    [[nodiscard]] Expected<void> init();

    /// Check if ring is initialized
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }

    /// Check if SQPOLL is active
    [[nodiscard]] bool is_sqpoll_active() const noexcept { return sqpoll_active_; }

    /// Get raw io_uring pointer (for advanced use)
    [[nodiscard]] struct io_uring* raw() noexcept { return &ring_; }

    // ═══════════════════════════════════════════════════════════════════════
    // Submission Queue Operations
    // ═══════════════════════════════════════════════════════════════════════

    /// Get a submission queue entry
    /// @return SQE pointer or nullptr if queue is full
    [[nodiscard]] struct io_uring_sqe* get_sqe() noexcept;

    /// Submit pending SQEs to the kernel
    /// @return Number of SQEs submitted or error
    [[nodiscard]] Expected<int> submit();

    /// Submit and wait for at least one completion
    /// @return Number of SQEs submitted or error
    [[nodiscard]] Expected<int> submit_and_wait(unsigned wait_nr = 1);

    // ═══════════════════════════════════════════════════════════════════════
    // Completion Queue Operations
    // ═══════════════════════════════════════════════════════════════════════

    /// Wait for at least one completion
    /// @param timeout_ms Timeout in milliseconds (0 = non-blocking, -1 = infinite)
    /// @return CQE or error
    [[nodiscard]] Expected<struct io_uring_cqe*> wait_cqe(int timeout_ms = -1);

    /// Peek for a completion (non-blocking)
    /// @return CQE or nullptr if none available
    [[nodiscard]] struct io_uring_cqe* peek_cqe() noexcept;

    /// Mark CQE as seen (must be called after processing)
    void seen_cqe(struct io_uring_cqe* cqe) noexcept;

    /// Process all available completions
    /// @param callback Called for each completion
    /// @return Number of completions processed
    size_t process_completions(const CompletionCallback& callback);

    // ═══════════════════════════════════════════════════════════════════════
    // Prepared I/O Operations
    // ═══════════════════════════════════════════════════════════════════════

    /// Prepare a read operation
    /// @return true if SQE was acquired
    bool prep_read(int fd, std::span<std::byte> buffer, uint64_t offset, void* user_data);

    /// Prepare a write operation
    /// @return true if SQE was acquired
    bool prep_write(int fd, std::span<const std::byte> buffer, uint64_t offset, void* user_data);

    /// Prepare a recv operation
    /// @return true if SQE was acquired
    bool prep_recv(int fd, std::span<std::byte> buffer, int flags, void* user_data);

    /// Prepare a send operation
    /// @return true if SQE was acquired
    bool prep_send(int fd, std::span<const std::byte> buffer, int flags, void* user_data);

    /// Prepare a multishot recv operation (kernel 5.19+)
    /// @return true if SQE was acquired
    bool prep_recv_multishot(int fd, void* user_data);

    /// Prepare a connect operation
    /// @return true if SQE was acquired
    bool prep_connect(int fd, const struct sockaddr* addr, socklen_t addrlen, void* user_data);

    /// Prepare a close operation
    /// @return true if SQE was acquired
    bool prep_close(int fd, void* user_data);

    /// Prepare a timeout operation
    /// @return true if SQE was acquired
    bool prep_timeout(struct __kernel_timespec* ts, unsigned count, void* user_data);

    /// Prepare a cancel operation
    /// @return true if SQE was acquired
    bool prep_cancel(void* user_data_to_cancel, void* user_data);

    /// Prepare a nop operation (for testing/synchronization)
    /// @return true if SQE was acquired
    bool prep_nop(void* user_data);

    // ═══════════════════════════════════════════════════════════════════════
    // Buffer Management
    // ═══════════════════════════════════════════════════════════════════════

    /// Register buffers with the kernel for zero-copy I/O
    /// @param buffers Array of buffer base addresses
    /// @param sizes Array of buffer sizes
    /// @return Success or error
    [[nodiscard]] Expected<void> register_buffers(
        std::span<void*> buffers,
        std::span<size_t> sizes);

    /// Unregister previously registered buffers
    [[nodiscard]] Expected<void> unregister_buffers();

    /// Check if buffers are registered
    [[nodiscard]] bool has_registered_buffers() const noexcept { return buffers_registered_; }

    /// Prepare a read using registered buffer
    bool prep_read_fixed(int fd, size_t buffer_index, size_t offset, size_t len,
                         uint64_t file_offset, void* user_data);

    /// Prepare a write using registered buffer
    bool prep_write_fixed(int fd, size_t buffer_index, size_t offset, size_t len,
                          uint64_t file_offset, void* user_data);

    // ═══════════════════════════════════════════════════════════════════════
    // File Descriptor Registration
    // ═══════════════════════════════════════════════════════════════════════

    /// Register file descriptors for direct access
    [[nodiscard]] Expected<void> register_files(std::span<int> fds);

    /// Update a registered file descriptor
    [[nodiscard]] Expected<void> update_file(size_t index, int fd);

    /// Unregister file descriptors
    [[nodiscard]] Expected<void> unregister_files();

    // ═══════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════

    /// Get number of SQEs currently in use
    [[nodiscard]] unsigned sq_ready() const noexcept;

    /// Get SQ space available
    [[nodiscard]] unsigned sq_space_left() const noexcept;

    /// Get number of CQEs available
    [[nodiscard]] unsigned cq_ready() const noexcept;

    /// Get total submissions
    [[nodiscard]] uint64_t total_submissions() const noexcept {
        return total_submissions_.load(std::memory_order_relaxed);
    }

    /// Get total completions
    [[nodiscard]] uint64_t total_completions() const noexcept {
        return total_completions_.load(std::memory_order_relaxed);
    }

private:
    struct io_uring ring_{};
    Config config_;
    bool initialized_ = false;
    bool sqpoll_active_ = false;
    bool buffers_registered_ = false;
    bool files_registered_ = false;

    // Statistics
    std::atomic<uint64_t> total_submissions_{0};
    std::atomic<uint64_t> total_completions_{0};

    // Registered buffer tracking
    std::vector<struct iovec> registered_iovecs_;
};

// ═══════════════════════════════════════════════════════════════════════════
// Implementation (header-only for inlining)
// ═══════════════════════════════════════════════════════════════════════════

inline Ring::Ring(const Config& config) : config_(config) {}

inline Ring::~Ring() {
    if (initialized_) {
        if (buffers_registered_) {
            io_uring_unregister_buffers(&ring_);
        }
        if (files_registered_) {
            io_uring_unregister_files(&ring_);
        }
        io_uring_queue_exit(&ring_);
    }
}

inline Ring::Ring(Ring&& other) noexcept
    : ring_(other.ring_)
    , config_(std::move(other.config_))
    , initialized_(other.initialized_)
    , sqpoll_active_(other.sqpoll_active_)
    , buffers_registered_(other.buffers_registered_)
    , files_registered_(other.files_registered_)
    , total_submissions_(other.total_submissions_.load())
    , total_completions_(other.total_completions_.load())
    , registered_iovecs_(std::move(other.registered_iovecs_))
{
    // SECURITY: Zero out the moved-from kernel state. Otherwise the
    // moved-from object's destructor (or accidental access) would call
    // io_uring_queue_exit() on the same kernel ring fd we now own,
    // double-freeing kernel resources.
    std::memset(&other.ring_, 0, sizeof(other.ring_));
    other.initialized_ = false;
    other.sqpoll_active_ = false;
    other.buffers_registered_ = false;
    other.files_registered_ = false;
}

inline Ring& Ring::operator=(Ring&& other) noexcept {
    if (this != &other) {
        // Tear down our current ring before adopting the new one,
        // mirroring the destructor logic to avoid leaking kernel state.
        if (initialized_) {
            if (buffers_registered_) {
                io_uring_unregister_buffers(&ring_);
            }
            if (files_registered_) {
                io_uring_unregister_files(&ring_);
            }
            io_uring_queue_exit(&ring_);
        }
        ring_ = other.ring_;
        config_ = std::move(other.config_);
        initialized_ = other.initialized_;
        sqpoll_active_ = other.sqpoll_active_;
        buffers_registered_ = other.buffers_registered_;
        files_registered_ = other.files_registered_;
        total_submissions_.store(other.total_submissions_.load());
        total_completions_.store(other.total_completions_.load());
        registered_iovecs_ = std::move(other.registered_iovecs_);

        // SECURITY: Zero moved-from kernel state to prevent double-free.
        std::memset(&other.ring_, 0, sizeof(other.ring_));
        other.initialized_ = false;
        other.sqpoll_active_ = false;
        other.buffers_registered_ = false;
        other.files_registered_ = false;
    }
    return *this;
}

inline Expected<void> Ring::init() {
    if (initialized_) {
        return unexpected(ErrorCode::AlreadyExists, "Ring already initialized");
    }

    struct io_uring_params params{};

    // Configure SQPOLL if requested
    if (config_.enable_sqpoll) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = config_.sqpoll_idle_ms;

        if (config_.sqpoll_cpu >= 0) {
            params.flags |= IORING_SETUP_SQ_AFF;
            params.sq_thread_cpu = static_cast<unsigned>(config_.sqpoll_cpu);
        }
    }

    // Setup io_uring
    int ret = io_uring_queue_init_params(config_.sq_entries, &ring_, &params);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSetupFailed, -ret);
    }

    initialized_ = true;
    sqpoll_active_ = (params.flags & IORING_SETUP_SQPOLL) != 0;

    return {};
}

inline struct io_uring_sqe* Ring::get_sqe() noexcept {
    SIGNET_TIMER_SCOPE(metrics::kSqeSubmit);
    return io_uring_get_sqe(&ring_);
}

inline Expected<int> Ring::submit() {
    SIGNET_TIMER_SCOPE(metrics::kSqeSubmit);

    int ret = io_uring_submit(&ring_);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSubmitFailed, -ret);
    }

    total_submissions_.fetch_add(static_cast<uint64_t>(ret), std::memory_order_relaxed);
    SIGNET_COUNTER_ADD(metrics::kSqeSubmit, ret);

    return ret;
}

inline Expected<int> Ring::submit_and_wait(unsigned wait_nr) {
    SIGNET_TIMER_SCOPE(metrics::kSqeSubmit);

    int ret = io_uring_submit_and_wait(&ring_, wait_nr);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSubmitFailed, -ret);
    }

    total_submissions_.fetch_add(static_cast<uint64_t>(ret), std::memory_order_relaxed);
    return ret;
}

inline Expected<struct io_uring_cqe*> Ring::wait_cqe(int timeout_ms) {
    SIGNET_TIMER_SCOPE(metrics::kCqeWait);

    struct io_uring_cqe* cqe = nullptr;
    int ret;

    if (timeout_ms < 0) {
        ret = io_uring_wait_cqe(&ring_, &cqe);
    } else if (timeout_ms == 0) {
        ret = io_uring_peek_cqe(&ring_, &cqe);
        if (ret == -EAGAIN) {
            return unexpected(ErrorCode::WouldBlock);
        }
    } else {
        struct __kernel_timespec ts{};
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        ret = io_uring_wait_cqe_timeout(&ring_, &cqe, &ts);
    }

    if (ret < 0) {
        if (ret == -ETIME || ret == -EAGAIN) {
            return unexpected(ErrorCode::Timeout);
        }
        return unexpected(ErrorCode::IoUringWaitFailed, -ret);
    }

    return cqe;
}

inline struct io_uring_cqe* Ring::peek_cqe() noexcept {
    struct io_uring_cqe* cqe = nullptr;
    io_uring_peek_cqe(&ring_, &cqe);
    return cqe;
}

inline void Ring::seen_cqe(struct io_uring_cqe* cqe) noexcept {
    SIGNET_TIMER_SCOPE(metrics::kCqeProcess);
    io_uring_cqe_seen(&ring_, cqe);
    total_completions_.fetch_add(1, std::memory_order_relaxed);
    SIGNET_COUNTER_INC(metrics::kCqeProcess);
}

inline size_t Ring::process_completions(const CompletionCallback& callback) {
    size_t count = 0;
    struct io_uring_cqe* cqe;

    while ((cqe = peek_cqe()) != nullptr) {
        SIGNET_TIMER_SCOPE(metrics::kCqeProcess);

        callback(cqe->res, io_uring_cqe_get_data(cqe));
        seen_cqe(cqe);
        ++count;
    }

    return count;
}

inline bool Ring::prep_read(int fd, std::span<std::byte> buffer, uint64_t offset, void* user_data) {
    // SECURITY: io_uring_prep_read takes `unsigned` length; reject buffers
    // larger than UINT_MAX rather than silently truncating.
    if (buffer.size() > std::numeric_limits<unsigned>::max()) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_read(sqe, fd, buffer.data(), static_cast<unsigned>(buffer.size()), offset);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_write(int fd, std::span<const std::byte> buffer, uint64_t offset, void* user_data) {
    // SECURITY: same length truncation guard as prep_read.
    if (buffer.size() > std::numeric_limits<unsigned>::max()) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_write(sqe, fd, buffer.data(), static_cast<unsigned>(buffer.size()), offset);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_recv(int fd, std::span<std::byte> buffer, int flags, void* user_data) {
    if (buffer.size() > std::numeric_limits<unsigned>::max()) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv(sqe, fd, buffer.data(), buffer.size(), flags);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_send(int fd, std::span<const std::byte> buffer, int flags, void* user_data) {
    if (buffer.size() > std::numeric_limits<unsigned>::max()) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_send(sqe, fd, buffer.data(), buffer.size(), flags);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_recv_multishot(int fd, void* user_data) {
    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_connect(int fd, const struct sockaddr* addr, socklen_t addrlen, void* user_data) {
    // SECURITY: Reject NULL/invalid sockaddr — passing nullptr to the kernel
    // results in undefined behavior and can crash the process.
    if (addr == nullptr || addrlen == 0) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_connect(sqe, fd, addr, addrlen);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_close(int fd, void* user_data) {
    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_timeout(struct __kernel_timespec* ts, unsigned count, void* user_data) {
    // SECURITY: NULL timespec would be dereferenced by the kernel.
    if (ts == nullptr) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_timeout(sqe, ts, count, 0);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_cancel(void* user_data_to_cancel, void* user_data) {
    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_cancel(sqe, user_data_to_cancel, 0);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_nop(void* user_data) {
    auto sqe = get_sqe();
    if (!sqe) return false;

    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline Expected<void> Ring::register_buffers(
    std::span<void*> buffers,
    std::span<size_t> sizes)
{
    if (buffers.size() != sizes.size()) {
        return unexpected(ErrorCode::InvalidArgument, "Buffer and size arrays must match");
    }

    registered_iovecs_.resize(buffers.size());
    for (size_t i = 0; i < buffers.size(); ++i) {
        registered_iovecs_[i].iov_base = buffers[i];
        registered_iovecs_[i].iov_len = sizes[i];
    }

    int ret = io_uring_register_buffers(&ring_, registered_iovecs_.data(),
                                        static_cast<unsigned>(registered_iovecs_.size()));
    if (ret < 0) {
        registered_iovecs_.clear();
        return unexpected(ErrorCode::IoUringBufferRegisterFailed, -ret);
    }

    buffers_registered_ = true;
    return {};
}

inline Expected<void> Ring::unregister_buffers() {
    if (!buffers_registered_) {
        return {};
    }

    int ret = io_uring_unregister_buffers(&ring_);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringBufferRegisterFailed, -ret);
    }

    registered_iovecs_.clear();
    buffers_registered_ = false;
    return {};
}

inline bool Ring::prep_read_fixed(int fd, size_t buffer_index, size_t offset, size_t len,
                                  uint64_t file_offset, void* user_data) {
    // SECURITY (CRITICAL #5): Validate ALL inputs BEFORE consuming an SQE.
    // get_sqe() advances the kernel submission queue head — leaving an
    // uninitialized SQE in the ring would cause undefined kernel behavior.
    if (buffer_index >= registered_iovecs_.size()) return false;
    if (len > std::numeric_limits<unsigned>::max()) return false;

    const auto& iov = registered_iovecs_[buffer_index];
    if (offset > iov.iov_len) return false;
    if (len > iov.iov_len - offset) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    auto* base = static_cast<uint8_t*>(iov.iov_base);
    io_uring_prep_read_fixed(sqe, fd, base + offset, static_cast<unsigned>(len),
                             file_offset, static_cast<int>(buffer_index));
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline bool Ring::prep_write_fixed(int fd, size_t buffer_index, size_t offset, size_t len,
                                   uint64_t file_offset, void* user_data) {
    // SECURITY (CRITICAL #5): Validate ALL inputs BEFORE consuming an SQE.
    if (buffer_index >= registered_iovecs_.size()) return false;
    if (len > std::numeric_limits<unsigned>::max()) return false;

    const auto& iov = registered_iovecs_[buffer_index];
    if (offset > iov.iov_len) return false;
    if (len > iov.iov_len - offset) return false;

    auto sqe = get_sqe();
    if (!sqe) return false;

    auto* base = static_cast<uint8_t*>(iov.iov_base);
    io_uring_prep_write_fixed(sqe, fd, base + offset, static_cast<unsigned>(len),
                              file_offset, static_cast<int>(buffer_index));
    io_uring_sqe_set_data(sqe, user_data);
    return true;
}

inline Expected<void> Ring::register_files(std::span<int> fds) {
    int ret = io_uring_register_files(&ring_, fds.data(), static_cast<unsigned>(fds.size()));
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSetupFailed, -ret);
    }
    files_registered_ = true;
    return {};
}

inline Expected<void> Ring::update_file(size_t index, int fd) {
    int ret = io_uring_register_files_update(&ring_, static_cast<unsigned>(index), &fd, 1);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSetupFailed, -ret);
    }
    return {};
}

inline Expected<void> Ring::unregister_files() {
    if (!files_registered_) {
        return {};
    }
    int ret = io_uring_unregister_files(&ring_);
    if (ret < 0) {
        return unexpected(ErrorCode::IoUringSetupFailed, -ret);
    }
    files_registered_ = false;
    return {};
}

inline unsigned Ring::sq_ready() const noexcept {
    return io_uring_sq_ready(const_cast<struct io_uring*>(&ring_));
}

inline unsigned Ring::sq_space_left() const noexcept {
    return io_uring_sq_space_left(const_cast<struct io_uring*>(&ring_));
}

inline unsigned Ring::cq_ready() const noexcept {
    return io_uring_cq_ready(const_cast<struct io_uring*>(&ring_));
}

}  // namespace signet
