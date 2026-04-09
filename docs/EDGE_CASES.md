# Signet_io_uring — Edge Cases and Boundary Conditions

This document catalogs edge cases, boundary conditions, and potential pitfalls discovered during development and testing. Each entry includes the bug, root cause, fix, and lessons learned.

---

## 1. Base64 Encoding Buffer Overflow (CRITICAL)

**Location:** `include/signet/ws/ws_handshake.hpp:generate_websocket_key()`

**Bug:** Segmentation fault when generating WebSocket keys.

**Root Cause:**
The base64 encoding loop processed data in 3-byte chunks but didn't account for the final partial chunk correctly:
```cpp
// BUGGY CODE:
for (size_t i = 0; i < 16; i += 3) {
    uint32_t triple = (random_bytes[i] << 16) |
                      (random_bytes[i + 1] << 8) |  // OOB when i=15
                      random_bytes[i + 2];          // OOB when i=15
}
```

When `i=15`, the code accessed `random_bytes[16]` and `random_bytes[17]` which don't exist in a 16-element array.

**Fix:**
```cpp
// Process complete triplets only (indices 0-14)
for (size_t i = 0; i < 15; i += 3) { ... }

// Handle remaining byte(s) separately with proper padding
uint32_t last = static_cast<uint32_t>(random_bytes[15]) << 16;
result += kBase64Chars[(last >> 18) & 0x3F];
result += kBase64Chars[(last >> 12) & 0x3F];
result += '=';  // Padding
result += '=';  // Padding
```

**Lesson:** Always verify loop bounds when processing data in chunks. For N bytes processed in K-byte chunks: `loop < N - (N % K)`, then handle `N % K` remaining bytes separately.

**Boundary Table for Base64:**
| Input Bytes | Complete Triplets | Remaining | Padding |
|-------------|-------------------|-----------|---------|
| 3n          | n                 | 0         | 0       |
| 3n + 1      | n                 | 1         | ==      |
| 3n + 2      | n                 | 2         | =       |

---

## 2. WebSocket Frame Length Encoding Boundaries

**Location:** `include/signet/ws/ws_frame.hpp`

**Boundaries (RFC 6455):**
| Payload Size | Length Field | Extended Length |
|--------------|--------------|-----------------|
| 0-125        | size (7 bits)| None            |
| 126-65535    | 126          | 16-bit BE       |
| 65536+       | 127          | 64-bit BE       |

**Edge Cases Tested:**
- `125` bytes: Last value using 7-bit encoding
- `126` bytes: First value requiring 16-bit extended
- `65535` bytes: Last value fitting in 16-bit
- `65536` bytes: First value requiring 64-bit extended
- `0` bytes: Empty payload (valid, used for pings)

**Potential Pitfall:** Off-by-one at boundary values. Test `125`, `126`, `65535`, `65536` explicitly.

---

## 3. UTF-8 Validation Streaming Edge Cases

**Location:** `include/signet/ws/ws_validator.hpp`

**Edge Cases:**
1. **Split multi-byte sequences**: UTF-8 character split across WebSocket frames
2. **Overlong encodings**: Rejected (e.g., `C0 80` for U+0000)
3. **Surrogate pairs**: U+D800-U+DFFF are invalid in UTF-8
4. **Truncated sequences**: Incomplete multi-byte character at end of frame

**Boundary Values:**
| Codepoint Range | Bytes | First Byte Pattern |
|-----------------|-------|-------------------|
| U+0000-U+007F   | 1     | 0xxxxxxx          |
| U+0080-U+07FF   | 2     | 110xxxxx          |
| U+0800-U+FFFF   | 3     | 1110xxxx          |
| U+10000-U+10FFFF| 4     | 11110xxx          |

**Critical Boundaries:**
- `U+007F` (127): Last single-byte character
- `U+0080` (128): First two-byte character
- `U+07FF`: Last two-byte character
- `U+0800`: First three-byte character
- `U+FFFF`: Last three-byte character
- `U+10000`: First four-byte character
- `U+10FFFF`: Maximum valid Unicode codepoint

---

## 4. WebSocket Close Code Validation

**Location:** `include/signet/ws/ws_types.hpp`

**Valid Close Codes (RFC 6455 Section 7.4.1):**
| Code | Meaning | Usage |
|------|---------|-------|
| 1000 | Normal | Connection completed successfully |
| 1001 | Going Away | Server shutting down |
| 1002 | Protocol Error | Invalid frame received |
| 1003 | Unsupported Data | Received data type not supported |
| 1007 | Invalid Payload | Message data not consistent with type |
| 1008 | Policy Violation | Generic policy violation |
| 1009 | Message Too Big | Message exceeds size limit |
| 1010 | Mandatory Extension | Client expected extension |
| 1011 | Internal Error | Server encountered unexpected condition |

**Reserved/Invalid Codes:**
- `0-999`: Reserved, never use
- `1004`: Reserved
- `1005`: No Status (never sent on wire)
- `1006`: Abnormal Closure (never sent on wire)
- `1015`: TLS Handshake Failure (never sent on wire)
- `1016-2999`: Reserved for future use
- `3000-3999`: Registered with IANA
- `4000-4999`: Private use

---

## 5. Extension Parameter Parsing Edge Cases

**Location:** `include/signet/ws/ws_extension.hpp`

**Edge Cases:**
1. **Multiple extensions**: `permessage-deflate, x-custom`
2. **Parameters with values**: `permessage-deflate; client_max_window_bits=15`
3. **Boolean parameters**: `server_no_context_takeover` (no value)
4. **Quoted values**: `param="value with spaces"`
5. **Empty extensions header**: Valid, means no extensions
6. **Whitespace handling**: Spaces around `;` and `,` are optional

**Parsing Rules:**
- Extensions separated by `,`
- Parameters separated by `;`
- Parameter values are optional
- Case-insensitive extension/parameter names
- Values may be quoted or unquoted

---

## 6. permessage-deflate Window Size Boundaries

**Location:** `include/signet/ws/ws_deflate.hpp`

**Valid window_bits range:** 8-15 (RFC 7692)

**Boundaries:**
| Parameter | Min | Max | Default |
|-----------|-----|-----|---------|
| client_max_window_bits | 8 | 15 | 15 |
| server_max_window_bits | 8 | 15 | 15 |

**Edge Cases:**
- Value `8`: Minimum compression (32KB window)
- Value `15`: Maximum compression (32KB window)
- Value `< 8`: Invalid, reject
- Value `> 15`: Invalid, reject
- Omitted: Use default (15)

---

## 7. HTTP Header Parsing Edge Cases

**Location:** `include/signet/ws/ws_handshake.hpp`

**Edge Cases:**
1. **Case insensitivity**: `Upgrade`, `upgrade`, `UPGRADE` all valid
2. **Multiple values**: `Connection: Upgrade, Keep-Alive`
3. **Line folding**: Deprecated but may appear (whitespace continuation)
4. **Empty values**: `Header:` with no value
5. **Missing colon**: Malformed header line
6. **Incomplete headers**: `\r\n\r\n` not yet received

**Buffer Considerations:**
- Maximum header size: Configurable, default 8KB
- Maximum header count: Configurable, prevent DoS
- Line length limit: Prevent memory exhaustion

---

## 8. Ring Buffer Wrap-Around

**Location:** `include/signet/core/ring.hpp`

**Critical Boundary:** When `head` or `tail` pointer wraps around buffer end.

**Edge Cases:**
1. **Exact wrap**: Write ending exactly at buffer boundary
2. **Split write**: Write spanning the wrap point
3. **Full buffer**: `head == tail` ambiguity (empty vs full)
4. **Power-of-two optimization**: Mask operation for index calculation

**Solution:** Use separate read/write indices with wrap-around via bitwise AND with `(size - 1)` for power-of-two sizes.

---

## 9. SSL/TLS Record Size Boundaries

**Location:** `include/signet/tls/tls_context.hpp`

**Boundaries:**
| Parameter | Value | Notes |
|-----------|-------|-------|
| Max record size | 16KB (16384 bytes) | TLS 1.2/1.3 limit |
| Max handshake message | 16MB | Rarely approached |
| Minimum version | TLS 1.2 | TLS 1.0/1.1 deprecated |

**Edge Cases:**
1. **Partial records**: Receive less than full record
2. **Renegotiation**: Handle mid-stream renegotiation
3. **ALPN negotiation**: Protocol selection
4. **SNI**: Server name indication for virtual hosts

---

## 10. io_uring SQE/CQE Boundaries

**Location:** `include/signet/core/ring.hpp`

**Boundaries:**
| Parameter | Typical Value | Notes |
|-----------|---------------|-------|
| Queue depth | 256-4096 | Power of two recommended |
| Max SGE | System dependent | Check `/proc/sys/net/core/somaxconn` |
| CQE overflow | Ring size * 2 | Kernel doubles CQ by default |

**Edge Cases:**
1. **SQ full**: Submit queue exhausted, must wait
2. **CQ overflow**: Completion queue overflows if not drained
3. **SQPOLL timeout**: Thread may sleep if idle too long
4. **EINTR handling**: Interrupted system call

---

## 11. Memory Alignment Requirements

**Location:** Various

**Requirements:**
| Platform | Alignment | Reason |
|----------|-----------|--------|
| x86_64 | 8 bytes | Natural alignment |
| Cache line | 64 bytes | Prevent false sharing |
| Page | 4096 bytes | Huge pages, mmap |
| SIMD | 16/32 bytes | SSE/AVX operations |

**Critical for:**
- Lock-free data structures
- SIMD mask operations
- DMA buffers
- Memory-mapped I/O

---

## Testing Recommendations

### Fuzz Testing Targets
1. Frame parser with malformed frames
2. UTF-8 validator with random byte sequences
3. Extension header parser with crafted inputs
4. HTTP response parser with truncated/malformed data

### Property-Based Testing
1. Base64 encode/decode roundtrip
2. Frame build/parse roundtrip
3. Mask/unmask symmetry
4. Compression/decompression roundtrip

### Boundary Testing
For each boundary value B, test: `B-1`, `B`, `B+1`

### Stress Testing
1. Maximum message size
2. Maximum concurrent connections
3. Rapid connect/disconnect cycles
4. Memory exhaustion scenarios

---

## Changelog

| Date | Issue | Severity | Fix |
|------|-------|----------|-----|
| 2026-01-17 | Base64 buffer overflow | CRITICAL | Fixed loop bounds, added padding |
