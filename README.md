# Signet_io_uring

**A header-only C++20 WebSocket library built directly on Linux `io_uring` and `kTLS`.**

Signet_io_uring is a low-latency WebSocket client library aimed at workloads
where every microsecond on the wire matters: high-frequency trading market
data feeds, real-time pub/sub fan-out, financial telemetry, and exchange
order ingest. It does not wrap an event loop. It does not sit on top of
Boost.Asio. It talks to the Linux kernel through `io_uring` directly, hands
TLS off to the kernel via `kTLS` when the cipher suite allows, and walks
the WebSocket frame layer in-place over registered, page-aligned buffers.

| Field | Value |
| --- | --- |
| Status | `v0.1.0-alpha` — API may change, security audit complete |
| License | Apache 2.0 |
| Standard | C++20, header-only |
| Platform | Linux ≥ 5.15 (x86_64; AArch64 best-effort) |
| Tests | 302 unit tests across 13 files, all passing (2 network-dependent integration tests disabled) |
| Audit | 47 issues found, all critical/high/medium fixed (`docs/SECURITY_AUDIT.md`) |
| Benchmarks | 31 microbenchmarks ([see below](#performance)) |

---

## Why Signet_io_uring?

Most C++ WebSocket libraries are written against `epoll` or Boost.Asio.
That's fine for most applications — but it leaves a few microseconds on
the floor that an HFT-grade market data path cannot afford:

- **Syscall amortization.** Every Asio read is a `read()` syscall. Every
  Signet_io_uring read is an SQE submitted to a shared ring; the kernel
  drains a batch at a time without crossing the user/kernel boundary per
  message.
- **Zero-copy framing.** Frames are parsed in-place over a registered
  fixed-buffer pool. The bytes the kernel wrote into your page are the
  same bytes the WebSocket parser reads — no memcpy, no per-frame
  allocation.
- **kTLS hand-off.** After the OpenSSL handshake, the cipher state is
  pushed into the kernel via `setsockopt(TCP_ULP, "tls")`. From that
  point on, plaintext writes go to the socket directly and the kernel
  handles encryption — no userspace SSL_write loop, no double-buffering.
- **SIMD masking + UTF-8.** XOR-mask and UTF-8 streaming validators
  unroll over AVX2 / SSE4.2 when the build host supports them.
- **Lock-free buffer pool.** A bounded SPSC free-list backs the fixed
  buffers, so the hot path never touches a mutex.

If your application makes <1k WebSocket connections and processes
<10k messages/s per connection, **you do not need this library** —
use a higher-level abstraction. Signet_io_uring exists for the cases
where you do.

---

## Requirements

| Component | Minimum | Notes |
| --- | --- | --- |
| Linux kernel | 5.15 | for `io_uring` features and `kTLS` upper layer protocol |
| Compiler | GCC 11+ or Clang 14+ | `-std=c++20` required |
| `liburing` | 2.0+ | `pkg-config liburing` |
| OpenSSL | 3.0+ | TLS 1.2 / 1.3, kTLS-capable cipher suites |
| `zlib` | 1.2+ | for `permessage-deflate` (optional but on by default) |
| CMake | 3.16+ | `INTERFACE` library + export support |

On Debian / Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build pkg-config \
    liburing-dev libssl-dev zlib1g-dev
```

---

## Build

```bash
git clone https://github.com/Johnson-Ogundeji/signet_io_uring.git
cd signet_io_uring
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
ninja -C build
ctest --test-dir build --output-on-failure   # 302 tests
```

### Build options

| Option | Default | Purpose |
| --- | --- | --- |
| `SIGNET_BUILD_TESTS` | `ON` | GoogleTest unit suite |
| `SIGNET_BUILD_BENCHMARKS` | `OFF` | Google Benchmark microbenchmark suite |
| `SIGNET_BUILD_EXAMPLES` | `ON` | Echo client and minimal samples |
| `SIGNET_ENABLE_METRICS` | `OFF` | Compile-time enable counters and histograms |
| `SIGNET_ENABLE_SIMD` | `ON` | AVX2 / SSE4.2 hot paths when available |

---

## Use as a dependency

### CMake `FetchContent`

```cmake
include(FetchContent)
FetchContent_Declare(
    signet_io_uring
    GIT_REPOSITORY https://github.com/Johnson-Ogundeji/signet_io_uring.git
    GIT_TAG        v0.1.0-alpha
)
FetchContent_MakeAvailable(signet_io_uring)

target_link_libraries(your_target PRIVATE signet_io_uring::signet_io_uring)
```

### Git submodule

```bash
git submodule add https://github.com/Johnson-Ogundeji/signet_io_uring.git deps/signet_io_uring
```

```cmake
add_subdirectory(deps/signet_io_uring)
target_link_libraries(your_target PRIVATE signet_io_uring::signet_io_uring)
```

### Installed system package

```bash
cmake --install build --prefix /usr/local
```

```cmake
find_package(signet_io_uring 0.1 REQUIRED)
target_link_libraries(your_target PRIVATE signet_io_uring::signet_io_uring)
```

---

## Hello, Echo

```cpp
#include <signet/ws/ws_client.hpp>
#include <iostream>

int main() {
    auto tls = signet::TlsContext::create_client().value();

    auto ws = signet::connect_websocket("wss://echo.websocket.org/", tls).value();
    (void)ws.send_text("hello");

    auto msg = ws.read_message().value();
    if (msg) std::cout << msg->as_string() << '\n';
}
```

> **Note on naming.** The product name is **Signet_io_uring**, but for
> source-compatibility reasons the include path stays `<signet/...>` and the
> C++ namespace stays `signet::`. The CMake target is
> `signet_io_uring::signet_io_uring` (with `signet::signet` retained as a
> legacy alias).

---

## Architecture

```text
            ┌──────────────────────────────────────────────┐
            │              Your Application                │
            └──────────────────────────────────────────────┘
                                  │
            ┌──────────────────────────────────────────────┐
            │            signet::WsConnection              │
            │  RFC 6455 framing, masking, fragmentation,   │
            │  permessage-deflate (RFC 7692)               │
            └──────────────────────────────────────────────┘
                                  │
            ┌──────────────────────────────────────────────┐
            │            signet::TlsConnection             │
            │  OpenSSL 3 handshake → kTLS hand-off when    │
            │  cipher suite supports it                    │
            └──────────────────────────────────────────────┘
                                  │
            ┌──────────────────────────────────────────────┐
            │              signet::Ring                    │
            │  io_uring SQE submission, registered fixed   │
            │  buffers, lock-free buffer pool              │
            └──────────────────────────────────────────────┘
                                  │
                          ┌───────────────┐
                          │ Linux kernel  │
                          │  io_uring +   │
                          │     kTLS      │
                          └───────────────┘
```

### Repository layout

| Path | Contents |
| --- | --- |
| `include/signet/core/` | `Ring`, `BufferPool`, `Histogram`, `Metrics`, types |
| `include/signet/net/` | Address, socket, resolver, connection |
| `include/signet/tls/` | `TlsContext`, `TlsConnection`, `kTLS` hand-off |
| `include/signet/ws/` | Frames, handshake, validator, deflate, client |
| `tests/unit/` | 13 GoogleTest files (302 tests) |
| `tests/integration/` | Live-network integration harness |
| `tests/autobahn/` | Autobahn `fuzzingclient` runner |
| `examples/` | Minimal echo client / sample programs |
| `benchmarks/` | Google Benchmark microbenchmarks |
| `cmake/` | `find_package` config template |
| `docs/` | Edge cases, security audit |

---

## Performance

Microbenchmarks live under `benchmarks/bench_ws.cpp` and are built with
`-DSIGNET_BUILD_BENCHMARKS=ON`. The numbers below were captured on
2026-04-09 against `v0.1.0-alpha` on a deliberately modest 4-core
1.9 GHz x86_64 VM (no AVX2, 32 KiB L1d, 256 KiB L2, 6 MiB L3) running
under WSL2. **Production hardware with AVX2 and wider L2/L3 caches
typically runs 2–4× faster** — these are the floor, not the ceiling.

### Frame parsing (header only, in-place)

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Parse small frame header (2 B) | 186 ns | 4.86 M frames/s |
| Parse medium frame header (4 B) | 176 ns | 5.16 M frames/s |
| Parse large frame header (10 B) | 190 ns | 4.77 M frames/s |
| Parse masked frame header (6 B) | 174 ns | 5.20 M frames/s |
| Frame validation (full header) | 172 ns | 5.24 M frames/s |

### Frame building

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Build small frame (13 B "Hello") | 322 ns | 35 MiB/s |
| Build 1 KiB masked frame | 360 ns | 2.44 GiB/s |
| Build 64 KiB masked frame | 2.67 µs | 21.07 GiB/s |
| Build 1 KiB unmasked server frame | 177 ns | 4.96 GiB/s |

### XOR masking (RFC 6455 §5.3, SIMD-accelerated)

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Mask 128 B payload | 143 ns | 786 MiB/s |
| Mask 1 KiB payload | 133 ns | 6.63 GiB/s |
| Mask 64 KiB payload | 1.26 µs | 44.6 GiB/s |
| Generate 4-byte mask key | 1.93 ns | 478 M keys/s |

### Handshake

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Generate Sec-WebSocket-Key (RAND_bytes) | 1.53 µs | 603 k keys/s |
| Compute Sec-WebSocket-Accept (SHA-1) | 817 ns | 1.12 M ops/s |
| Build handshake request | 202 ns | 4.54 M req/s |
| Parse HTTP/1.1 101 response | 1.07 µs | 855 k resp/s |

### UTF-8 streaming validation

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Validate ASCII (1 KiB) | 1.08 µs | 830 MiB/s |
| Validate mixed ASCII + emoji (1 KiB) | 3.46 µs | 647 MiB/s |
| Validate CJK (1 KiB, 3-byte chars) | 6.93 µs | 387 MiB/s |

### Extension parsing (`permessage-deflate`)

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Parse simple extension header | 244 ns | 3.76 M ops/s |
| Parse complex extension header (3 ext) | 633 ns | 1.45 M ops/s |
| Format extension header | 114 ns | 8.00 M ops/s |

### Close frames

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Build close payload | 1.89 ns | 477 M ops/s |
| Parse close payload | 4.85 ns | 189 M ops/s |

### End-to-end frame roundtrip (build + parse, masked binary)

| Payload | Time | Throughput |
| --- | --- | --- |
| 64 B | 561 ns | 97.8 MiB/s |
| 256 B | 489 ns | 449 MiB/s |
| 1 KiB | 494 ns | 1.74 GiB/s |
| 4 KiB | 616 ns | 5.57 GiB/s |
| 16 KiB | 1.29 µs | 10.64 GiB/s |
| 64 KiB | 3.70 µs | 14.84 GiB/s |

To reproduce:

```bash
cmake -G Ninja -B build-bench -DCMAKE_BUILD_TYPE=Release \
    -DSIGNET_BUILD_BENCHMARKS=ON -DSIGNET_BUILD_TESTS=OFF
ninja -C build-bench signet_ws_bench
./build-bench/benchmarks/signet_ws_bench --benchmark_min_time=0.5s
```

---

## Security

The library has been audited end-to-end. The full report is in
[`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).

| Severity | Found | Fixed |
| --- | --- | --- |
| Critical | 11 | 11 |
| High | 18 | 18 |
| Medium | 14 | 14 |
| Low | 4 | 0 |

To report a vulnerability please follow the private disclosure process in
[`SECURITY.md`](SECURITY.md).

---

## Roadmap

- **0.1.x** — bug fixes, additional Autobahn compliance, CI matrix expansion
- **0.2.0** — server-side `WebSocketServer`, multi-shot recv, `IORING_OP_SEND_ZC`
- **0.3.0** — multi-message recv batching, NUMA-aware ring binding
- **1.0.0** — frozen API, semver guarantee, ABI stability promise

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build, test, and PR rules.
A summary:

- Linux only, C++20, header-only — no `.cpp` files outside `tests/`,
  `examples/`, `benchmarks/`.
- `tl::expected<T, signet::Error>` for errors. No exceptions on the hot path.
- Every behavior change ships with a unit test. Bug fixes ship with a
  regression test.
- Run `clang-format` (config in `.clang-format`) before submitting.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
