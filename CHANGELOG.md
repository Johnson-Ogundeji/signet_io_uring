# Changelog

All notable changes to **Signet_io_uring** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-04-09

Initial public alpha of **Signet_io_uring**. API is not yet stable — pin to a
commit for production use.

### Added

- Header-only C++20 WebSocket client built on `io_uring` and OpenSSL.
- RFC 6455 frame parser, builder, masking, fragmentation, control-frame interleave.
- RFC 7692 `permessage-deflate` extension (compression / decompression with context takeover).
- `signet::Ring` — `io_uring` SQE submission with registered buffers and lock-free buffer pool.
- `signet::TlsContext` / `signet::TlsConnection` — OpenSSL handshake with optional kTLS hand-off.
- `signet::WsConnection` — full WebSocket client with handshake, framing, ping/pong, close.
- SIMD-accelerated streaming UTF-8 validator (AVX2 / SSE4.2 fallback).
- `tests/unit` GoogleTest suite — 302 tests across 13 files (2 additional
  network-dependent integration tests deliberately disabled).
- `tests/integration` Autobahn test runner harness.
- `examples/basic_benchmark.cpp` — minimal echo client.
- `benchmarks/bench_ws.cpp` — Google Benchmark harness with 31 microbenchmarks
  covering frame parse/build, masking, handshake, UTF-8, extensions, close, and
  end-to-end roundtrip.
- CMake `INTERFACE` target `signet_io_uring::signet_io_uring` (legacy alias
  `signet::signet` retained for source compatibility) plus install/export
  support and `FetchContent` fallback for `tl::expected`.

### Performance baseline (2026-04-09, 4 × 1.9 GHz x86_64, no AVX2, Release)

Microbenchmarks captured from `benchmarks/bench_ws.cpp`. Hardware here is a
deliberately modest 4-core VM — production servers with AVX2 / wider caches
typically run 2-4× faster.

| Benchmark | Time | Throughput |
| --- | --- | --- |
| Parse small frame header (2 B) | 186 ns | 4.86 M frames/s |
| Parse masked frame header (6 B) | 174 ns | 5.20 M frames/s |
| Build 1 KiB masked frame | 360 ns | 2.44 GiB/s |
| Build 64 KiB masked frame | 2.67 µs | 21.07 GiB/s |
| XOR-mask 1 KiB payload | 133 ns | 6.63 GiB/s |
| XOR-mask 64 KiB payload | 1.26 µs | 44.6 GiB/s |
| Generate 4-byte mask key | 1.93 ns | 478 M keys/s |
| Generate WebSocket key (RAND_bytes) | 1.53 µs | 603 k keys/s |
| Compute Sec-WebSocket-Accept | 817 ns | 1.12 M ops/s |
| Build handshake request | 202 ns | 4.54 M req/s |
| Parse HTTP 101 response | 1.07 µs | 855 k resp/s |
| Validate UTF-8 ASCII (1 KiB) | 1.08 µs | 830 MiB/s |
| Validate UTF-8 mixed-emoji (1 KiB) | 3.46 µs | 647 MiB/s |
| Validate UTF-8 CJK (1 KiB) | 6.93 µs | 387 MiB/s |
| Roundtrip 1 KiB frame | 494 ns | 1.74 GiB/s |
| Roundtrip 4 KiB frame | 616 ns | 5.57 GiB/s |
| Roundtrip 16 KiB frame | 1.29 µs | 10.64 GiB/s |
| Roundtrip 64 KiB frame | 3.70 µs | 14.84 GiB/s |
| Build close payload | 1.89 ns | 477 M ops/s |
| Parse close payload | 4.85 ns | 189 M ops/s |

### Security

- Full security audit covering 47 issues across 8 components
  (`docs/SECURITY_AUDIT.md`). All 11 CRITICAL, 18 HIGH, and 14 MEDIUM
  issues fixed prior to 0.1.0-alpha:
  - Frame size and `build_frame()` integer-overflow guards.
  - `io_uring` move-constructor / move-assignment race fixed (kernel state zeroed).
  - SQE consumed only after bounds checks pass; NULL `addr` rejected in `prep_connect`.
  - TLS hostname verification enforced via `X509_VERIFY_PARAM_set1_host`; failures
    propagate as `TlsHandshakeResult::Error` instead of silent state changes.
  - WebSocket callback re-entrancy guarded by snapshot + post-callback state checks.
  - Fragment buffer cleared on every error path via `FragmentGuard` RAII.
  - Handshake response capped at 64 KiB.
  - Buffer pool validates alignment is a power of two and rejects `size * count`
    overflow; `mlock()` failure is fatal; huge-page fallback is counted.
  - `zlib` `Z_MEM_ERROR` / `Z_DATA_ERROR` handled distinctly; `deflateReset` /
    `inflateReset` return codes checked; `size_t → uInt` casts overflow-checked.
  - Private-key password wiped with `OPENSSL_cleanse()` after use.
- 302 / 302 enabled unit tests pass post-fix sweep.

[Unreleased]: https://github.com/Johnson-Ogundeji/signet_io_uring/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/Johnson-Ogundeji/signet_io_uring/releases/tag/v0.1.0-alpha
