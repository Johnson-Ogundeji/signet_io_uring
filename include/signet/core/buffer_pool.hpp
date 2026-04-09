// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "signet/core/config.hpp"
#include "signet/core/error.hpp"
#include "signet/core/metrics.hpp"
#include "signet/core/ring.hpp"

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <vector>

#ifdef __linux__
#include <sys/mman.h>
#endif

namespace signet {

/// Configuration for buffer pool
struct BufferPoolConfig {
    size_t count = kDefaultBufferCount;     // Number of buffers
    size_t size = kDefaultBufferSize;       // Size of each buffer
    size_t alignment = 4096;                // Memory alignment
    bool use_huge_pages = false;            // Use 2MB huge pages
    bool lock_memory = false;               // Lock memory (mlockall)
};

/// Handle to a buffer from the pool
/// RAII - automatically returns buffer to pool on destruction
class BufferHandle {
public:
    BufferHandle() = default;

    BufferHandle(std::byte* data, size_t capacity, size_t index,
                 class BufferPool* pool) noexcept
        : data_(data), capacity_(capacity), size_(0), index_(index), pool_(pool) {}

    ~BufferHandle() {
        release();
    }

    // Non-copyable
    BufferHandle(const BufferHandle&) = delete;
    BufferHandle& operator=(const BufferHandle&) = delete;

    // Movable
    BufferHandle(BufferHandle&& other) noexcept
        : data_(other.data_)
        , capacity_(other.capacity_)
        , size_(other.size_)
        , index_(other.index_)
        , pool_(other.pool_)
    {
        other.data_ = nullptr;
        other.pool_ = nullptr;
    }

    BufferHandle& operator=(BufferHandle&& other) noexcept {
        if (this != &other) {
            release();
            data_ = other.data_;
            capacity_ = other.capacity_;
            size_ = other.size_;
            index_ = other.index_;
            pool_ = other.pool_;
            other.data_ = nullptr;
            other.pool_ = nullptr;
        }
        return *this;
    }

    /// Check if handle is valid
    [[nodiscard]] bool valid() const noexcept { return data_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// Get raw data pointer
    [[nodiscard]] std::byte* data() noexcept { return data_; }
    [[nodiscard]] const std::byte* data() const noexcept { return data_; }

    /// Get as char pointer (for string operations)
    [[nodiscard]] char* char_data() noexcept {
        return reinterpret_cast<char*>(data_);
    }
    [[nodiscard]] const char* char_data() const noexcept {
        return reinterpret_cast<const char*>(data_);
    }

    /// Get as uint8_t pointer
    [[nodiscard]] uint8_t* uint8_data() noexcept {
        return reinterpret_cast<uint8_t*>(data_);
    }
    [[nodiscard]] const uint8_t* uint8_data() const noexcept {
        return reinterpret_cast<const uint8_t*>(data_);
    }

    /// Get buffer capacity
    [[nodiscard]] size_t capacity() const noexcept { return capacity_; }

    /// Get current used size
    [[nodiscard]] size_t size() const noexcept { return size_; }

    /// Set used size
    void set_size(size_t size) noexcept { size_ = std::min(size, capacity_); }

    /// Resize (set used size with bounds checking)
    void resize(size_t new_size) noexcept { set_size(new_size); }

    /// Reset size to zero
    void clear() noexcept { size_ = 0; }

    /// Get remaining space
    [[nodiscard]] size_t space_left() const noexcept { return capacity_ - size_; }

    /// Check if buffer is empty
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    /// Check if buffer is full
    [[nodiscard]] bool full() const noexcept { return size_ >= capacity_; }

    /// Get span of used data
    [[nodiscard]] std::span<std::byte> span() noexcept {
        return {data_, size_};
    }
    [[nodiscard]] std::span<const std::byte> span() const noexcept {
        return {data_, size_};
    }

    /// Get span of full capacity
    [[nodiscard]] std::span<std::byte> full_span() noexcept {
        return {data_, capacity_};
    }
    [[nodiscard]] std::span<const std::byte> full_span() const noexcept {
        return {data_, capacity_};
    }

    /// Get span of remaining space
    [[nodiscard]] std::span<std::byte> remaining_span() noexcept {
        return {data_ + size_, capacity_ - size_};
    }

    /// Get string_view of used data
    [[nodiscard]] std::string_view string_view() const noexcept {
        return {char_data(), size_};
    }

    /// Get buffer index (for io_uring registered buffers)
    [[nodiscard]] size_t index() const noexcept { return index_; }

    /// Append data to buffer
    /// @return Number of bytes actually appended
    size_t append(std::span<const std::byte> data) noexcept {
        size_t to_copy = std::min(data.size(), space_left());
        if (to_copy > 0) {
            std::memcpy(data_ + size_, data.data(), to_copy);
            size_ += to_copy;
        }
        return to_copy;
    }

    /// Append string to buffer
    size_t append(std::string_view str) noexcept {
        return append(std::as_bytes(std::span{str.data(), str.size()}));
    }

    /// Release buffer back to pool
    void release();

private:
    std::byte* data_ = nullptr;
    size_t capacity_ = 0;
    size_t size_ = 0;
    size_t index_ = 0;
    BufferPool* pool_ = nullptr;
};

/// Lock-free buffer pool for zero-allocation I/O
class BufferPool {
public:
    explicit BufferPool(BufferPoolConfig config = {});
    ~BufferPool();

    // Non-copyable, non-movable (due to atomic state)
    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;
    BufferPool(BufferPool&&) = delete;
    BufferPool& operator=(BufferPool&&) = delete;

    /// Initialize the pool
    [[nodiscard]] Expected<void> init();

    /// Acquire a buffer from the pool (lock-free)
    [[nodiscard]] BufferHandle acquire() noexcept;

    /// Try to acquire a buffer (non-blocking)
    [[nodiscard]] std::optional<BufferHandle> try_acquire() noexcept;

    /// Release a buffer back to the pool (lock-free)
    void release(size_t index) noexcept;

    /// Register buffers with io_uring for zero-copy I/O
    [[nodiscard]] Expected<void> register_with_ring(Ring& ring);

    /// Get pool statistics
    struct Stats {
        size_t total_count;         // Total buffers in pool
        size_t available_count;     // Currently available
        size_t in_use_count;        // Currently in use
        size_t buffer_size;         // Size of each buffer
        uint64_t total_acquires;    // Total acquire calls
        uint64_t total_releases;    // Total release calls
        uint64_t acquire_failures;  // Failed acquires (pool empty)
    };

    [[nodiscard]] Stats stats() const noexcept;

    /// Get buffer count
    [[nodiscard]] size_t count() const noexcept { return config_.count; }

    /// Get buffer size
    [[nodiscard]] size_t buffer_size() const noexcept { return config_.size; }

    /// Check if initialized
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }

    /// Get buffer by index (for io_uring fixed buffer operations)
    [[nodiscard]] std::byte* buffer_at(size_t index) noexcept {
        if (index >= config_.count) return nullptr;
        return buffers_[index];
    }

private:
    friend class BufferHandle;

    BufferPoolConfig config_;
    bool initialized_ = false;

    // Memory allocation
    void* memory_block_ = nullptr;
    size_t memory_size_ = 0;
    std::vector<std::byte*> buffers_;

    // Lock-free free list using atomic stack
    // Each slot stores the index of the next free buffer, or -1 if end
    std::unique_ptr<std::atomic<int64_t>[]> free_list_;
    std::atomic<int64_t> free_head_{-1};

    // Statistics
    std::atomic<uint64_t> total_acquires_{0};
    std::atomic<uint64_t> total_releases_{0};
    std::atomic<uint64_t> acquire_failures_{0};
    std::atomic<size_t> in_use_count_{0};

    void free_memory();
};

// ═══════════════════════════════════════════════════════════════════════════
// Implementation
// ═══════════════════════════════════════════════════════════════════════════

inline void BufferHandle::release() {
    if (pool_ && data_) {
        pool_->release(index_);
        data_ = nullptr;
        pool_ = nullptr;
    }
}

inline BufferPool::BufferPool(BufferPoolConfig config)
    : config_(std::move(config))
{
}

inline BufferPool::~BufferPool() {
    free_memory();
}

inline void BufferPool::free_memory() {
    if (memory_block_) {
#ifdef __linux__
        if (config_.use_huge_pages) {
            munmap(memory_block_, memory_size_);
        } else {
            std::free(memory_block_);
        }
#else
        std::free(memory_block_);
#endif
        memory_block_ = nullptr;
    }
}

inline Expected<void> BufferPool::init() {
    if (initialized_) {
        return unexpected(ErrorCode::AlreadyExists, "Buffer pool already initialized");
    }

    // SECURITY (CRITICAL #11): Validate config and guard against integer overflow.
    if (config_.size == 0 || config_.count == 0 || config_.alignment == 0) {
        return unexpected(ErrorCode::InvalidArgument,
            "Buffer pool size/count/alignment must all be > 0");
    }
    // Alignment must be a power of two for both std::aligned_alloc and the
    // round-up arithmetic below.
    if ((config_.alignment & (config_.alignment - 1)) != 0) {
        return unexpected(ErrorCode::InvalidArgument,
            "Buffer pool alignment must be a power of two");
    }
    // (size + alignment - 1) must not overflow
    if (config_.size > std::numeric_limits<size_t>::max() - (config_.alignment - 1)) {
        return unexpected(ErrorCode::InvalidArgument,
            "Buffer size + alignment overflows size_t");
    }
    size_t aligned_size = (config_.size + config_.alignment - 1) & ~(config_.alignment - 1);
    // aligned_size * count must not overflow
    if (aligned_size != 0 && config_.count > std::numeric_limits<size_t>::max() / aligned_size) {
        return unexpected(ErrorCode::InvalidArgument,
            "aligned_size * count overflows size_t");
    }
    memory_size_ = aligned_size * config_.count;

    // std::aligned_alloc requires the size to be a multiple of the alignment.
    // memory_size_ already satisfies this because aligned_size is a multiple
    // of alignment, but assert it for safety.
    if (memory_size_ % config_.alignment != 0) {
        return unexpected(ErrorCode::InvalidArgument,
            "Total memory size must be a multiple of alignment");
    }

    // Allocate memory
#ifdef __linux__
    bool huge_pages_used = false;
    if (config_.use_huge_pages) {
        memory_block_ = mmap(nullptr, memory_size_,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                            -1, 0);
        if (memory_block_ == MAP_FAILED) {
            memory_block_ = nullptr;
            // SECURITY (MEDIUM #44): silent fallback used to mask huge-page
            // configuration bugs. Log a counter so callers can detect this.
            SIGNET_COUNTER_INC("buffer_pool.huge_page_fallback");
        } else {
            huge_pages_used = true;
        }
    }
#endif

    if (!memory_block_) {
        // Use aligned allocation
        memory_block_ = std::aligned_alloc(config_.alignment, memory_size_);
        if (!memory_block_) {
            return unexpected(ErrorCode::OutOfMemory);
        }
    }

#ifdef __linux__
    if (config_.lock_memory) {
        // SECURITY (MEDIUM #45): mlock can fail (e.g. RLIMIT_MEMLOCK exceeded).
        // If the user explicitly asked us to lock memory, treat the failure as
        // a hard error — silently leaving pages pageable defeats the security
        // intent (e.g. preventing swap-out of crypto buffers).
        if (mlock(memory_block_, memory_size_) != 0) {
            int err = errno;
            // Free the allocation we just made before returning
            if (huge_pages_used) {
                munmap(memory_block_, memory_size_);
            } else {
                std::free(memory_block_);
            }
            memory_block_ = nullptr;
            return unexpected(ErrorCode::OutOfMemory,
                "mlock failed: " + std::string(std::strerror(err)));
        }
    }
#endif

    // Zero initialize
    std::memset(memory_block_, 0, memory_size_);

    // Setup buffer pointers
    buffers_.resize(config_.count);
    auto* base = static_cast<std::byte*>(memory_block_);
    for (size_t i = 0; i < config_.count; ++i) {
        buffers_[i] = base + (i * aligned_size);
    }

    // Setup free list (all buffers initially free)
    free_list_ = std::make_unique<std::atomic<int64_t>[]>(config_.count);
    for (size_t i = 0; i < config_.count - 1; ++i) {
        free_list_[i].store(static_cast<int64_t>(i + 1), std::memory_order_relaxed);
    }
    free_list_[config_.count - 1].store(-1, std::memory_order_relaxed);  // End of list
    free_head_.store(0, std::memory_order_release);

    initialized_ = true;

    SIGNET_GAUGE_SET(metrics::kBufferPoolSize, static_cast<int64_t>(config_.count));
    SIGNET_GAUGE_SET(metrics::kBufferInUse, 0);

    return {};
}

inline BufferHandle BufferPool::acquire() noexcept {
    SIGNET_TIMER_SCOPE(metrics::kBufferAcquire);

    total_acquires_.fetch_add(1, std::memory_order_relaxed);

    // Lock-free pop from stack
    int64_t head = free_head_.load(std::memory_order_acquire);

    while (head >= 0) {
        int64_t next = free_list_[static_cast<size_t>(head)].load(std::memory_order_relaxed);

        if (free_head_.compare_exchange_weak(head, next,
                                             std::memory_order_release,
                                             std::memory_order_acquire)) {
            // Successfully acquired buffer
            in_use_count_.fetch_add(1, std::memory_order_relaxed);
            SIGNET_GAUGE_INC(metrics::kBufferInUse);

            return BufferHandle(buffers_[static_cast<size_t>(head)],
                               config_.size,
                               static_cast<size_t>(head),
                               this);
        }
        // CAS failed, head was updated, retry
    }

    // Pool exhausted
    acquire_failures_.fetch_add(1, std::memory_order_relaxed);
    SIGNET_COUNTER_INC("buffer.acquire_failures");
    return BufferHandle();  // Invalid handle
}

inline std::optional<BufferHandle> BufferPool::try_acquire() noexcept {
    auto handle = acquire();
    if (handle.valid()) {
        return handle;  // NRVO applies
    }
    return std::nullopt;
}

inline void BufferPool::release(size_t index) noexcept {
    SIGNET_TIMER_SCOPE(metrics::kBufferRelease);

    if (index >= config_.count) return;

    total_releases_.fetch_add(1, std::memory_order_relaxed);
    in_use_count_.fetch_sub(1, std::memory_order_relaxed);
    SIGNET_GAUGE_DEC(metrics::kBufferInUse);

    // Lock-free push to stack
    int64_t old_head = free_head_.load(std::memory_order_relaxed);

    do {
        free_list_[index].store(old_head, std::memory_order_relaxed);
    } while (!free_head_.compare_exchange_weak(old_head, static_cast<int64_t>(index),
                                               std::memory_order_release,
                                               std::memory_order_relaxed));
}

inline Expected<void> BufferPool::register_with_ring(Ring& ring) {
    if (!initialized_) {
        return unexpected(ErrorCode::InvalidState, "Buffer pool not initialized");
    }

    std::vector<void*> ptrs(buffers_.size());
    std::vector<size_t> sizes(buffers_.size(), config_.size);

    for (size_t i = 0; i < buffers_.size(); ++i) {
        ptrs[i] = buffers_[i];
    }

    return ring.register_buffers(ptrs, sizes);
}

inline BufferPool::Stats BufferPool::stats() const noexcept {
    Stats s;
    s.total_count = config_.count;
    s.in_use_count = in_use_count_.load(std::memory_order_relaxed);
    s.available_count = s.total_count - s.in_use_count;
    s.buffer_size = config_.size;
    s.total_acquires = total_acquires_.load(std::memory_order_relaxed);
    s.total_releases = total_releases_.load(std::memory_order_relaxed);
    s.acquire_failures = acquire_failures_.load(std::memory_order_relaxed);
    return s;
}

}  // namespace signet
