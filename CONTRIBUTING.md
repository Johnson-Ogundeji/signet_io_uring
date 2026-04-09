# Contributing to Signet_io_uring

Thanks for taking the time to contribute. **Signet_io_uring** is a low-latency
systems library — correctness, memory safety, and a clean hot path matter more
here than they do in most C++ projects. The guidelines below exist to keep that
bar high.

## Ground rules

- **Linux only.** Signet_io_uring targets `io_uring` and kTLS. Patches that are
  conditional on other operating systems are out of scope.
- **C++20, header-only.** New code lives under `include/signet/` and must compile as
  part of an `INTERFACE` library. No `.cpp` files outside `tests/`, `examples/`, or
  `benchmarks/`.
- **No exceptions on the hot path.** Use `tl::expected<T, signet::Error>` for any
  function that can fail. Exceptions are tolerated only inside test code.
- **No raw `new` / `delete`.** Use RAII wrappers (`std::unique_ptr`, custom deleters,
  the buffer pool). Move semantics must zero out the moved-from state.
- **No silent errors.** Every error path either returns `unexpected(...)` or, in
  destructors, increments a metrics counter. Don't swallow `errno`.

## Development workflow

```bash
git clone https://github.com/Johnson-Ogundeji/signet_io_uring.git
cd signet_io_uring
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Debug \
    -DSIGNET_BUILD_TESTS=ON -DSIGNET_BUILD_EXAMPLES=ON
ninja -C build
ctest --test-dir build --output-on-failure
```

For a release-mode sanity check:

```bash
cmake -G Ninja -B build-rel -DCMAKE_BUILD_TYPE=Release
ninja -C build-rel
ctest --test-dir build-rel --output-on-failure
```

To run the benchmark suite:

```bash
cmake -G Ninja -B build-bench -DCMAKE_BUILD_TYPE=Release \
    -DSIGNET_BUILD_BENCHMARKS=ON -DSIGNET_BUILD_TESTS=OFF
ninja -C build-bench signet_ws_bench
./build-bench/benchmarks/signet_ws_bench --benchmark_min_time=0.5s
```

## Style

- Run `clang-format` (config in `.clang-format`) before committing. The repo uses
  Google base style with 4-space indentation and a 100-column limit.
- Public symbols are `snake_case` for functions/variables, `PascalCase` for types,
  `UPPER_SNAKE_CASE` for constants. Private members get a trailing underscore.
- Mark value-returning functions `[[nodiscard]]`.
- Prefer `std::span<const std::byte>` over raw pointer + length pairs at API
  boundaries.

## Tests

- Every behavior-changing PR must come with unit tests under `tests/unit/`.
- Bug fixes need a regression test that fails before the fix and passes after.
- If you change anything in `include/signet/core/ring.hpp`,
  `include/signet/tls/`, or `include/signet/ws/`, run the full Autobahn integration
  suite locally before opening the PR.

## Security fixes

If you find a vulnerability, **do not open a public issue or PR**. Follow the
private disclosure process described in [`SECURITY.md`](SECURITY.md) instead.

## Commit messages

- One logical change per commit. Don't bundle a refactor with a bug fix.
- First line is `<area>: <imperative summary>` (e.g. `ring: zero kernel state in move-ctor`),
  72 characters or fewer.
- Body explains *why*, not *what*. Reference the audit issue number when
  applicable (e.g. `Fixes audit #5.`).

## Pull requests

- PRs are squash-merged. Keep the description tidy — it becomes the merge commit
  body.
- Tick the boxes in the PR template before requesting review:
  - [ ] Builds clean with `-Wall -Wextra -Wpedantic`
  - [ ] `ctest` passes
  - [ ] No new warnings
  - [ ] `CHANGELOG.md` updated under `## [Unreleased]`
