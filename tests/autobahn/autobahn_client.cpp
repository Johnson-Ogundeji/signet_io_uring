// Signet Autobahn Compliance Test Client
// Copyright 2026 Signet Authors
// SPDX-License-Identifier: Apache-2.0
//
// This client connects to the Autobahn|Testsuite fuzzing server
// and runs through all test cases to verify RFC 6455 compliance.
//
// Usage:
//   1. Start Autobahn fuzzing server:
//      docker run -it --rm -v $(pwd)/config:/config -v $(pwd)/reports:/reports \
//        -p 9001:9001 crossbario/autobahn-testsuite \
//        wstest -m fuzzingserver -s /config/fuzzingserver.json
//
//   2. Run this client:
//      ./signet_autobahn_client [server_url]
//
//   3. Check reports in ./reports/server/

#include <signet/ws/ws_client.hpp>
#include <signet/ws/ws_connection.hpp>
#include <signet/tls/tls_context.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

using namespace signet;

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

struct AutobahnConfig {
    std::string server_url = "ws://127.0.0.1:9001";
    std::string agent_name = "Signet/1.0";
    bool verbose = false;
};

// ═══════════════════════════════════════════════════════════════════════════
// Test Runner
// ═══════════════════════════════════════════════════════════════════════════

class AutobahnTestRunner {
public:
    explicit AutobahnTestRunner(AutobahnConfig config)
        : config_(std::move(config)) {}

    /// Get total number of test cases from server
    [[nodiscard]] int get_case_count() {
        auto url = config_.server_url + "/getCaseCount";

        // Create simple config without compression for control messages
        WsClientConfig ws_config;
        ws_config.enable_compression = false;
        ws_config.auto_reconnect = false;

        WsClient client(ws_config);
        int count = 0;

        client.on_message([&count](const WsClientMessage& msg) {
            try {
                count = std::stoi(std::string(msg.as_text()));
            } catch (...) {
                count = -1;
            }
        });

        auto result = client.connect(url);
        if (!result) {
            std::cerr << "Failed to get case count: " << result.error().to_string() << "\n";
            return -1;
        }

        // Wait for message
        client.run_for(std::chrono::milliseconds{5000});
        client.disconnect();

        return count;
    }

    /// Run a single test case
    [[nodiscard]] bool run_case(int case_num) {
        auto url = config_.server_url + "/runCase?case=" + std::to_string(case_num)
                 + "&agent=" + config_.agent_name;

        if (config_.verbose) {
            std::cout << "  Running case " << case_num << "...\n";
        }

        WsClientConfig ws_config;
        ws_config.enable_compression = true;  // Test with compression
        ws_config.auto_reconnect = false;
        ws_config.max_message_size = 64 * 1024 * 1024;  // 64MB for large message tests

        WsClient client(ws_config);
        bool success = true;
        bool done = false;

        client.on_message([&client, &done](const WsClientMessage& msg) {
            // Echo back the message (Autobahn test protocol)
            if (msg.type == WsMessageType::Text) {
                (void)client.send(msg.as_text());
            } else {
                (void)client.send(msg.as_binary());
            }
        });

        client.on_disconnect([&done](CloseCode, std::string_view) {
            done = true;
        });

        client.on_error([&success, &done, case_num](const Error& err) {
            // Some errors are expected for certain test cases
            if (err.code() != ErrorCode::ConnectionClosed) {
                std::cerr << "  Case " << case_num << " error: " << err.to_string() << "\n";
            }
            done = true;
        });

        auto result = client.connect(url);
        if (!result) {
            // Connection failures are valid for some test cases
            return true;
        }

        // Run until disconnected or timeout
        auto timeout = std::chrono::seconds{60};
        auto start = std::chrono::steady_clock::now();

        while (!done) {
            (void)client.poll_once();

            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > timeout) {
                std::cerr << "  Case " << case_num << " timed out\n";
                success = false;
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }

        return success;
    }

    /// Update reports on server
    void update_reports() {
        auto url = config_.server_url + "/updateReports?agent=" + config_.agent_name;

        WsClientConfig ws_config;
        ws_config.enable_compression = false;
        ws_config.auto_reconnect = false;

        WsClient client(ws_config);
        bool done = false;

        client.on_disconnect([&done](CloseCode, std::string_view) {
            done = true;
        });

        auto result = client.connect(url);
        if (!result) {
            std::cerr << "Failed to update reports: " << result.error().to_string() << "\n";
            return;
        }

        // Wait for server to close connection
        auto timeout = std::chrono::seconds{30};
        auto start = std::chrono::steady_clock::now();

        while (!done) {
            (void)client.poll_once();

            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > timeout) {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }

    /// Run all test cases
    [[nodiscard]] bool run_all() {
        std::cout << "Signet Autobahn Compliance Test\n";
        std::cout << "================================\n";
        std::cout << "Server: " << config_.server_url << "\n";
        std::cout << "Agent: " << config_.agent_name << "\n\n";

        // Get case count
        std::cout << "Getting test case count...\n";
        int case_count = get_case_count();
        if (case_count <= 0) {
            std::cerr << "Failed to get case count from server\n";
            return false;
        }
        std::cout << "Total test cases: " << case_count << "\n\n";

        // Run all cases
        std::cout << "Running test cases...\n";
        int passed = 0;
        int failed = 0;

        for (int i = 1; i <= case_count; ++i) {
            if (run_case(i)) {
                ++passed;
            } else {
                ++failed;
            }

            // Progress indicator
            if (i % 50 == 0 || i == case_count) {
                std::cout << "  Progress: " << i << "/" << case_count
                         << " (" << passed << " passed, " << failed << " failed)\n";
            }
        }

        // Update reports
        std::cout << "\nUpdating reports...\n";
        update_reports();

        // Summary
        std::cout << "\n================================\n";
        std::cout << "Results: " << passed << "/" << case_count << " passed\n";
        if (failed > 0) {
            std::cout << "         " << failed << " failed\n";
        }
        std::cout << "\nCheck reports at: ./reports/server/index.html\n";

        return failed == 0;
    }

private:
    AutobahnConfig config_;
};

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    AutobahnConfig config;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options] [server_url]\n"
                     << "\nOptions:\n"
                     << "  -v, --verbose    Show detailed progress\n"
                     << "  -h, --help       Show this help\n"
                     << "\nDefault server: ws://127.0.0.1:9001\n";
            return 0;
        } else if (!arg.starts_with("-")) {
            config.server_url = arg;
        }
    }

    AutobahnTestRunner runner(config);
    return runner.run_all() ? 0 : 1;
}
