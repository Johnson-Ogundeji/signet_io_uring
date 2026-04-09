// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0

#include <signet/net/socket.hpp>
#include <gtest/gtest.h>

#include <csignal>
#include <thread>
#include <atomic>

using namespace signet;

class SocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ignore SIGPIPE - common for network applications
        // Writing to closed/unconnected sockets would otherwise cause termination
        std::signal(SIGPIPE, SIG_IGN);
    }
    void TearDown() override {}
};

// ═══════════════════════════════════════════════════════════════════════════
// Socket Creation Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, Create_IPv4) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());
    EXPECT_TRUE(sock->is_open());
    EXPECT_GE(sock->fd(), 0);
}

TEST_F(SocketTest, Create_IPv6) {
    auto sock = Socket::create(AF_INET6);
    ASSERT_TRUE(sock.has_value());
    EXPECT_TRUE(sock->is_open());
}

TEST_F(SocketTest, Create_WithOptions) {
    SocketOptions opts;
    opts.tcp_nodelay = true;
    opts.reuse_addr = true;
    opts.non_blocking = true;

    auto sock = Socket::create(AF_INET, opts);
    ASSERT_TRUE(sock.has_value());
    EXPECT_TRUE(sock->is_open());
}

TEST_F(SocketTest, DefaultConstructor_NotOpen) {
    Socket sock;
    EXPECT_FALSE(sock.is_open());
    EXPECT_EQ(sock.fd(), -1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Socket Move Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, MoveConstruct) {
    auto sock1 = Socket::create(AF_INET);
    ASSERT_TRUE(sock1.has_value());

    int original_fd = sock1->fd();

    Socket sock2(std::move(*sock1));

    EXPECT_FALSE(sock1->is_open());  // Original should be invalid
    EXPECT_TRUE(sock2.is_open());
    EXPECT_EQ(sock2.fd(), original_fd);
}

TEST_F(SocketTest, MoveAssign) {
    auto sock1 = Socket::create(AF_INET);
    auto sock2 = Socket::create(AF_INET);
    ASSERT_TRUE(sock1.has_value());
    ASSERT_TRUE(sock2.has_value());

    int fd1 = sock1->fd();

    *sock2 = std::move(*sock1);

    EXPECT_FALSE(sock1->is_open());
    EXPECT_EQ(sock2->fd(), fd1);
}

TEST_F(SocketTest, Release) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    int fd = sock->release();
    EXPECT_GE(fd, 0);
    EXPECT_FALSE(sock->is_open());

    // Clean up manually
    ::close(fd);
}

// ═══════════════════════════════════════════════════════════════════════════
// Socket Options Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, ApplyOptions_TcpNodelay) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    SocketOptions opts;
    opts.tcp_nodelay = true;

    auto result = sock->apply_options(opts);
    EXPECT_TRUE(result.has_value());
}

TEST_F(SocketTest, ApplyOptions_BufferSizes) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    SocketOptions opts;
    opts.send_buffer_size = 65536;
    opts.recv_buffer_size = 65536;

    auto result = sock->apply_options(opts);
    EXPECT_TRUE(result.has_value());
}

TEST_F(SocketTest, ApplyOptions_NotOpen) {
    Socket sock;

    SocketOptions opts;
    auto result = sock.apply_options(opts);
    EXPECT_FALSE(result.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// Socket Close Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, CloseSync) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());
    EXPECT_TRUE(sock->is_open());

    sock->close_sync();
    EXPECT_FALSE(sock->is_open());
}

TEST_F(SocketTest, CloseSync_Idempotent) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    sock->close_sync();
    sock->close_sync();  // Should not crash
    EXPECT_FALSE(sock->is_open());
}

TEST_F(SocketTest, Shutdown) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    // Shutdown on unconnected socket fails, but shouldn't crash
    auto result = sock->shutdown(SHUT_RDWR);
    // Result may or may not be valid depending on socket state
}

// ═══════════════════════════════════════════════════════════════════════════
// Socket Read/Write Tests (require connected socket)
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, ReadSync_NotConnected) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    std::array<std::byte, 1024> buffer;
    auto result = sock->read_sync(buffer);

    // Reading from unconnected socket should fail or return 0
    // Behavior depends on implementation
}

TEST_F(SocketTest, WriteSync_NotConnected) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    std::array<std::byte, 4> data = {std::byte{'t'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}};
    auto result = sock->write_sync(data);

    // Writing to unconnected socket should fail
    EXPECT_FALSE(result.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// Socket Endpoint Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, LocalEndpoint_NotBound) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    // Getting local endpoint of unbound socket may fail or return any address
    auto ep = sock->local_endpoint();
    // Result depends on implementation
}

TEST_F(SocketTest, RemoteEndpoint_NotConnected) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    auto ep = sock->remote_endpoint();
    EXPECT_FALSE(ep.has_value());  // Should fail - not connected
}

TEST_F(SocketTest, GetError) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    auto err = sock->get_error();
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, 0);  // No error on fresh socket
}

// ═══════════════════════════════════════════════════════════════════════════
// SocketGuard Tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, SocketGuard_ClosesOnDestruction) {
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    {
        SocketGuard guard(*sock);
        EXPECT_TRUE(sock->is_open());
    }

    EXPECT_FALSE(sock->is_open());
}

// ═══════════════════════════════════════════════════════════════════════════
// Loopback Integration Test
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(SocketTest, LoopbackEchoTest) {
    // This test creates a simple loopback server-client pair
    // Server runs in a separate thread

    std::atomic<bool> server_ready{false};
    std::atomic<uint16_t> server_port{0};
    std::string received_data;

    // Server thread
    std::thread server_thread([&]() {
        // Create listening socket
        int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GE(listen_fd, 0);

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // Let OS assign port

        int ret = ::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ASSERT_EQ(ret, 0);

        socklen_t len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        server_port.store(ntohs(addr.sin_port));

        ret = ::listen(listen_fd, 1);
        ASSERT_EQ(ret, 0);

        server_ready.store(true);

        // Accept connection
        int client_fd = ::accept(listen_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            // Read data
            char buffer[256];
            ssize_t n = ::read(client_fd, buffer, sizeof(buffer));
            if (n > 0) {
                received_data = std::string(buffer, static_cast<size_t>(n));
            }
            ::close(client_fd);
        }
        ::close(listen_fd);
    });

    // Wait for server to be ready
    while (!server_ready.load()) {
        std::this_thread::yield();
    }

    // Client side - use our Socket class
    auto sock = Socket::create(AF_INET);
    ASSERT_TRUE(sock.has_value());

    // Make it blocking for this test
    SocketOptions opts;
    opts.non_blocking = false;
    opts.tcp_nodelay = true;
    sock->apply_options(opts);

    // Connect
    auto v4 = IPv4Address::loopback();
    Endpoint ep(v4, server_port.load());

    auto result = sock->connect_sync(ep);
    EXPECT_TRUE(result.has_value());

    // Send data
    std::string test_message = "Hello, Signet!";
    std::span<const std::byte> data{
        reinterpret_cast<const std::byte*>(test_message.data()),
        test_message.size()
    };

    auto write_result = sock->write_sync(data);
    EXPECT_TRUE(write_result.has_value());
    EXPECT_EQ(*write_result, test_message.size());

    sock->close_sync();
    server_thread.join();

    EXPECT_EQ(received_data, test_message);
}
