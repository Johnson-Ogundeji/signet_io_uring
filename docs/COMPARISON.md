# Signet_io_uring vs Boost.Beast / Boost.Asio

This document is an honest, architecture-level comparison of
**Signet_io_uring** against the de-facto C++ WebSocket stack:
[Boost.Beast](https://github.com/boostorg/beast) — itself built on
[Boost.Asio](https://github.com/boostorg/asio).

It is **not** a benchmark shoot-out. Signet_io_uring's microbenchmarks are
real and reproducible (`benchmarks/bench_ws.cpp`), but a head-to-head
comparison under identical hardware/load is TBD — see
[§ 12 What we have NOT measured](#12-what-we-have-not-measured) below.
The purpose of this doc is to explain the **design choices** that should
give Signet_io_uring the edge in the workloads it targets, and to be
candid about where Beast is the better choice.

## TL;DR

| Dimension | Boost.Beast / Boost.Asio | Signet_io_uring |
| --- | --- | --- |
| Kernel I/O primitive | `epoll` (Linux reactor) | `io_uring` (Linux proactor) |
| Syscalls per read | 1 per `recv()` | 0 on the steady-state hot path (SQPOLL) |
| TLS termination | Userspace `SSL_read` / `SSL_write` loop | OpenSSL handshake → kernel `kTLS` hand-off |
| Frame buffer | Heap-allocated `flat_buffer` per stream | Page-aligned, `mlock`'d, kernel-registered fixed buffers |
| Read-path memcpy | OpenSSL → Asio buffer → user buffer | None — frame parsed in-place |
| Mask / UTF-8 | Scalar | AVX2 / SSE4.2 SIMD |
| Allocations on hot path | `shared_ptr`, completion-handler binders | None |
| Error handling | `error_code` + exceptions | `tl::expected<T, Error>` |
| Dependencies | Boost.System, Boost.Asio, Boost.Container, ... | `liburing`, OpenSSL, optionally `zlib` |
| Header code volume | Tens of thousands of LOC (Beast + Asio + Boost) | ~8 k LOC |
| Platforms | Linux, macOS, Windows, FreeBSD | Linux ≥ 5.15 only |
| Client | Yes | Yes |
| Server | Yes | **Roadmap (0.2.0)** |
| HTTP/1.1 | Full HTTP library | WebSocket Upgrade subset only |
| Maturity | 8+ years in production | Alpha (`v0.1.0-alpha`, audited) |

## 1. I/O model: reactor vs proactor

Boost.Asio is a **reactor**: on Linux it polls a set of file descriptors
with `epoll`, and when `epoll_wait()` returns "this fd is readable" the
caller still has to issue a `recv()` (or equivalent) syscall to actually
read the bytes. Every async read therefore costs:

```text
epoll_wait → recv → user callback
```

That is **one syscall per readable event** plus the wakeup.

io_uring is a **proactor**: the user submits a "read this many bytes
into this buffer" request as a Submission Queue Entry (SQE), the kernel
performs the read whenever data arrives, and the completion lands as a
Completion Queue Entry (CQE) the user reaps without a syscall. With
SQPOLL enabled, the kernel polls the submission queue on its own
worker thread, so the steady-state hot path is **zero syscalls**:

```text
[submitted SQE in shared ring] → kernel does the read → CQE in shared ring
```

This is the difference between "the kernel has to be asked permission
for every byte" and "the kernel can drain a batch of operations whenever
it likes". For a market-data WebSocket feed receiving 50 k messages/s,
that removes ~50 k context switches per second per connection.

**Why it matters for Signet_io_uring's target workloads.** HFT market
data feeds have to read frames as fast as the kernel can deliver them.
Removing the per-read syscall is not a marginal optimization — it
changes the slope of the latency vs throughput curve.

## 2. TLS termination: userspace loop vs kernel hand-off

`boost::asio::ssl::stream` wraps OpenSSL's `SSL_read` / `SSL_write` in
Asio's async interface. Every read therefore goes:

```text
kernel TCP buffer → OpenSSL decrypt (userspace) → Asio buffer → user buffer
```

That is **two memory copies plus a userspace AES round** per record.

Signet_io_uring runs the OpenSSL handshake exactly once, then calls
`setsockopt(sock, SOL_TCP, TCP_ULP, "tls")` and pushes the negotiated
cipher state into the kernel via `setsockopt(SOL_TLS, TLS_TX, ...)`.
After that, the socket *is* a TLS socket — userland writes plaintext,
the kernel encrypts inline using the same hardware AES path the kernel
uses for IPsec. The read path is symmetric.

```text
NIC → kernel decrypt (kTLS) → kernel-registered buffer → frame parser
```

There is no userspace SSL_read loop, no OpenSSL bounce buffer, and no
double-copy.

**Caveat.** kTLS only works with kernel-supported cipher suites:
`AES-128-GCM`, `AES-256-GCM`, and `ChaCha20-Poly1305`. If the negotiated
suite is not one of those, Signet_io_uring transparently falls back to
the userspace OpenSSL path (the same path Beast always takes), and the
TLS-side advantage disappears for that connection. The frame-layer
advantages below still apply.

## 3. Buffer management: heap churn vs registered fixed pool

Beast's stream types own a `flat_buffer` (or `multi_buffer`) per
connection. Each `async_read` grows that buffer if the incoming frame
doesn't fit, which means a heap allocation plus a `memcpy` of the
existing contents into the new region. For high-rate feeds with bursty
large frames this becomes the dominant cost.

Signet_io_uring registers a pool of page-aligned, `mlock`'d fixed
buffers with `io_uring_register_buffers()` at startup. The kernel
writes incoming bytes **directly into those pages** with no copy. The
WebSocket frame parser then runs over the same memory:

- No heap allocation per frame.
- No copy from OpenSSL to user buffer (kTLS writes plaintext into the
  same page).
- No copy from "I/O buffer" to "parse buffer" — there is only one
  buffer.
- Buffers are returned to a lock-free SPSC freelist, so the hot path
  never touches a mutex.

The `mlock()` step is important: it guarantees the kernel will never
page these buffers out, so the latency tail is bounded by the network,
not by the VM subsystem. Signet_io_uring also tries 2 MiB huge pages
first and falls back to 4 KiB pages, which reduces TLB pressure on
large pools.

## 4. Hot-path frame parsing and building

Beast's WebSocket frame layer is structured around its
`buffer_sequence` abstraction — frames may span multiple discontinuous
buffers, so the parser walks a `ConstBufferSequence`. This is general
and correct, but adds branch overhead per byte and prevents some
straight-line optimisations.

Signet_io_uring frames are always contiguous (because the buffer pool
is contiguous-per-frame), so the parser is a flat linear pass:

| Operation | Signet (this hardware) |
| --- | --- |
| Parse 2-byte header | 186 ns / 4.86 M frames/s |
| Parse 6-byte masked header | 174 ns / 5.20 M frames/s |
| Build 1 KiB masked frame | 360 ns / 2.44 GiB/s |
| Build 64 KiB masked frame | 2.67 µs / 21.07 GiB/s |
| Roundtrip 64 KiB frame | 3.70 µs / 14.84 GiB/s |

These are from `benchmarks/bench_ws.cpp` running on a 4-core 1.9 GHz VM
**with no AVX2**. Production hardware with wider L2/L3 typically runs
2–4× faster.

## 5. Masking and UTF-8 validation: scalar vs SIMD

RFC 6455 §5.3 mandates client-to-server XOR masking with a 4-byte key.
Beast's masker is a scalar loop. Signet_io_uring's masker unrolls into
AVX2 (32 B/iter) or SSE4.2 (16 B/iter) when the host supports it,
falling back to scalar on platforms that don't.

| Payload | Signet masker |
| --- | --- |
| 1 KiB | 133 ns / 6.63 GiB/s |
| 64 KiB | 1.26 µs / 44.6 GiB/s |

UTF-8 validation (required for text frames per RFC 6455 §8.1) is also
SIMD-accelerated using a streaming validator. ASCII paths peak at
~830 MiB/s on a single core of the test VM; mixed-emoji and CJK degrade
gracefully.

## 6. Memory and allocation discipline

Asio's idiomatic async model relies on `boost::asio::bind_executor`,
`std::shared_ptr<self>`-style completion handlers, and type-erased
function objects. Each async operation typically allocates a small
control block. For a connection sustaining 50 k frames/s this is
50 k allocations/s **per connection**, which trashes the allocator and
lengthens the tail-latency distribution.

Signet_io_uring's hot path is allocation-free:

- No `shared_ptr` on the hot path.
- No `std::function` / type erasure on the hot path — completions are
  reaped from the CQ ring directly.
- `tl::expected<T, signet::Error>` for return values, never exceptions.
- Zero `throw` from the WebSocket frame layer.

This means latency is dominated by the work itself, not by allocator
contention or exception-unwind cost.

## 7. Threading model

Asio's `io_context` has a thread pool with strands for serialization.
Strands are correct but they cost: every strand-bound completion has
to be enqueued under a mutex, and work-stealing across threads creates
cross-CPU cache traffic.

Signet_io_uring assumes a **shard-per-CPU** layout: one ring per
thread, one set of registered buffers per ring, no work stealing, no
strand. If you need 16 connections you create 16 rings, pin them to
16 cores, and the WebSocket parser never sees a cache line owned by
another core. The lock-free SPSC buffer pool fits this naturally.

## 8. Error handling

Beast surfaces errors via `boost::system::error_code` (out-parameter
overloads) **or** exceptions (throwing overloads). Mixing the two is
common, and the throwing overloads make latency unpredictable on the
unhappy path.

Signet_io_uring is consistent: every fallible operation returns
`tl::expected<T, signet::Error>`. There are no exceptions on the hot
path, ever.

## 9. Dependency footprint

| Library | Build dependencies | Header pulls |
| --- | --- | --- |
| Boost.Beast | Boost.System, Boost.Asio, Boost.Container, Boost.Core, Boost.Endian, Boost.Intrusive, Boost.Optional, ... | Hundreds of `boost/...` headers transitively |
| Signet_io_uring | `liburing`, OpenSSL 3, optionally `zlib` | ~30 `signet/...` headers |

If your project already uses Boost this is a wash. If it doesn't,
Signet_io_uring lets you stay Boost-free.

## 10. Where Boost.Beast wins

This document would be dishonest without this section. Beast is the
right choice when:

- **You need a server today.** Signet_io_uring `v0.1.0-alpha` is
  client-only. Server support is on the 0.2.0 roadmap.
- **You need cross-platform.** Beast runs on Linux, macOS, Windows,
  FreeBSD. Signet_io_uring is Linux-only and requires kernel ≥ 5.15.
- **You need full HTTP/1.1.** Beast is a complete HTTP library;
  Signet_io_uring implements only the HTTP/1.1 Upgrade handshake
  needed for WebSocket. If you want REST endpoints from the same
  library, use Beast.
- **You need battle-tested code.** Beast has been in production for
  8+ years across thousands of deployments. Signet_io_uring has a
  clean security audit but is `v0.1.0-alpha` and the API may change.
- **You are already using Asio.** Signet_io_uring does not interoperate
  with `io_context`. If your application is structured around Asio
  executors, ripping that out for one library is rarely worth it.
- **Your cipher suite is not kTLS-eligible.** If you must use a cipher
  the Linux kernel does not implement (anything that is not AES-GCM or
  ChaCha20-Poly1305), Signet_io_uring's kTLS path silently becomes the
  same userspace OpenSSL path Beast uses, and most of the TLS-side
  advantage disappears. The frame-layer wins still apply.
- **Your kernel is < 5.15.** No `io_uring` features Signet_io_uring
  relies on; no kTLS upper-layer protocol.

## 11. Where Signet_io_uring is intended to win

The set of workloads Signet_io_uring is built for:

- **High-frequency trading market-data feeds.** Tens of thousands of
  small frames per second, latency-bound, kernel ≥ 5.15 servers, AES
  ciphers, no need for HTTP/1.1.
- **Real-time pub/sub fan-out.** Many connections, mostly outbound,
  per-connection allocation cost dominates total cost.
- **Financial telemetry / order routing.** Tail latency matters more
  than throughput; eliminating allocator and exception-unwind from the
  hot path tightens the p99.9.
- **Exchange order ingest.** kTLS lets the kernel encrypt directly out
  of the same buffer the application wrote to, removing one full
  buffer copy on the send path.

For these workloads the architectural facts above translate into real
microseconds saved.

## 12. What we have NOT measured

- **Head-to-head Boost.Beast benchmarks on the same hardware.** This
  doc compares architectures. It does *not* claim "X times faster than
  Beast" because that comparison hasn't been run. Doing it cleanly
  requires identical Linux kernel, identical NIC, identical CPU,
  identical cipher suite, identical message-rate generator, and
  identical statistical methodology — and Signet_io_uring's microbench
  harness measures parsing/building/masking primitives, not full
  network round-trip.
- **Tail latency under load.** The numbers in this repo are
  steady-state median microbenchmarks. Long-running tail-latency
  characterization is `tests/integration/` future work.
- **Multi-connection scaling.** All current benchmarks are
  single-thread, single-connection. NUMA-aware ring binding and
  multi-shot recv are roadmap items for 0.2.0 and 0.3.0.

If you have a Boost.Beast workload and want to know the real delta on
your hardware, the right way is to build both, run them against the
same load generator, and compare. Pull requests publishing such
comparisons are welcome.

## 13. Summary

Signet_io_uring is not a Boost.Beast replacement. It is a **focused
alternative** for the narrow set of Linux workloads where the per-frame
overhead of a generic Asio-based stack is the bottleneck. Boost.Beast
is the right answer almost everywhere else, and is the right answer for
production code that ships *today* and needs server support, HTTP, or
non-Linux platforms.

The architectural choices — io_uring proactor, kTLS hand-off, registered
fixed buffers, SIMD masking, allocation-free hot path — are deliberate
and they each remove a specific cost that Beast pays per frame. Whether
the sum of those removed costs is worth giving up Beast's portability
and maturity is a decision only you can make for your workload.

---

*This document is part of the Signet_io_uring documentation suite.
See also [`README.md`](../README.md), [`CHANGELOG.md`](../CHANGELOG.md),
[`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md),
[`docs/EDGE_CASES.md`](EDGE_CASES.md).*
