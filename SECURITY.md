# Security Policy

## Overview

nkeys-cpp is a cryptographic library that handles sensitive key material. This document outlines security considerations, best practices, and the library's security design.

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it privately:

1. **Do not** open a public GitHub issue
2. Email the maintainer with details about the vulnerability
3. Include steps to reproduce, potential impact, and suggested fixes if available
4. Allow reasonable time for a fix before public disclosure

## Security Design

### Cryptographic Primitives

**Ed25519 Signatures**
- Implementation: [Monocypher](https://monocypher.org/) 4.x
- Algorithm: Ed25519 (Curve25519 + SHA-512)
- Key size: 256-bit (32 bytes)
- Signature size: 512-bit (64 bytes)
- Security level: 128-bit (equivalent to AES-128)

**Random Number Generation**
- **macOS/BSD**: `arc4random_buf()` - cryptographically secure CSPRNG
- **Linux**: `/dev/urandom` with complete read validation
- **Windows**: Not currently supported (contributions welcome)
- Fallback: **None** - throws exception if secure RNG unavailable

### Memory Security

**Sensitive Data Handling**

The library implements multiple layers of protection for sensitive key material:

1. **Automatic Wiping**: RAII guards ensure keys are wiped even on exceptions
2. **Explicit Wiping**: `wipe()` method zeros all sensitive data
3. **Volatile Pointers**: Prevents compiler optimization from removing wipe operations
4. **No Swap**: Sensitive data kept in process memory (not swapped to disk)

**Memory Zeroing Implementation**

```cpp
static void secureZero(std::span<std::uint8_t> data) {
    if (data.empty()) return;
    volatile std::uint8_t* p = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        p[i] = 0;
    }
}
```

The `volatile` qualifier ensures the compiler cannot optimize away the zeroing loop.

### Constant-Time Operations

**CRC Validation**
- Uses lookup table to ensure constant-time execution
- Prevents timing attacks on checksum validation
- No conditional branches based on data values

### Input Validation

All public APIs perform strict validation:

- **Key lengths**: Verified against Ed25519 requirements
- **Prefix types**: Validated against known key types
- **CRC checksums**: Verified on all decoded keys
- **Base32 encoding**: Validated character set
- **Signature lengths**: Must be exactly 64 bytes

Invalid input results in exceptions, never undefined behavior.

## Best Practices for Users

### Key Management

**DO:**
- ✅ Store seeds in secure locations (encrypted files, key management systems)
- ✅ Use appropriate file permissions (600 for seed files)
- ✅ Call `wipe()` on key pairs when done using them
- ✅ Generate keys on secure systems with good entropy
- ✅ Use key types appropriately (User keys for users, Server keys for servers)

**DON'T:**
- ❌ Store seeds in version control or logs
- ❌ Transmit seeds over insecure channels
- ❌ Reuse seeds across different security contexts
- ❌ Share seeds between multiple identities
- ❌ Log or print seed material

### Signature Verification

**Critical Checks:**

```cpp
// Always verify the signature before trusting the message
auto pub = nkeys::FromPublicKey(trustedPublicKey);
if (!pub->verify(message, signature)) {
    throw std::runtime_error("Signature verification failed");
}
// Only now is it safe to use 'message'
```

**Never:**
- Skip signature verification
- Use unverified messages as trusted input
- Verify signatures with wrong key type
- Trust message content before successful verification

### Exception Safety

All key generation functions use exception-safe patterns:

```cpp
auto kp = nkeys::CreateUser();
// Even if an exception is thrown here, the key material
// has been wiped from the stack by RAII guards
```

## Security Features

### Compile-Time Protections

When built with `NKEYS_ENABLE_HARDENING=ON` (default), the following protections are enabled:

**Stack Protection**
- `-fstack-protector-strong`: Guards stack against buffer overflows
- Protects functions with vulnerable characteristics

**Fortified Sources**
- `-D_FORTIFY_SOURCE=2`: Compile-time and runtime buffer overflow checks
- Applied automatically in Release builds

**Position Independent Execution (Linux)**
- `-Wl,-z,relro,-z,now`: Read-only relocations, immediate binding
- Prevents GOT overwrites

### Runtime Sanitizers

Development builds can enable:

**AddressSanitizer** (`-DNKEYS_ENABLE_ASAN=ON`)
- Detects memory errors (use-after-free, buffer overflows)
- ~2x slowdown, use in testing

**UndefinedBehaviorSanitizer** (`-DNKEYS_ENABLE_UBSAN=ON`)
- Detects undefined behavior at runtime
- Minimal performance impact

## Known Limitations

### Platform Support

- **Windows**: Secure random number generation not implemented
  - Windows users should contribute `BCryptGenRandom()` support
- **Exotic Platforms**: Only tested on macOS, Linux (Ubuntu/Debian)

### Side-Channel Resistance

- **Timing**: CRC uses constant-time lookup tables
- **Power Analysis**: Not protected (not applicable for software-only implementation)
- **Cache Timing**: Monocypher provides some cache-timing resistance
- **Speculative Execution**: No specific mitigations (Spectre, Meltdown)

### Denial of Service

The library does not protect against:
- Excessive memory allocation (caller's responsibility)
- CPU exhaustion from signature verification
- File size limits (enforced at 100MB in CLI tool)

## Threat Model

### In Scope

The library protects against:
- ✅ Memory disclosure attacks (key material wiping)
- ✅ Timing attacks on CRC validation
- ✅ Signature forgery (Ed25519 security guarantees)
- ✅ Key confusion (prefix validation)
- ✅ Corrupt/tampered keys (CRC validation)

### Out of Scope

The library does NOT protect against:
- ❌ Physical access to running process (memory dumps)
- ❌ Root/admin level attackers
- ❌ Compromised compilers or build tools
- ❌ Side-channel attacks requiring special equipment
- ❌ Attacks on key storage (filesystem, OS)

## Cryptographic Assurance

### Algorithm Security

**Ed25519** is considered secure against all known attacks:
- No known practical attacks against Curve25519
- Conservative security margin
- Immune to many side-channel attacks
- Widely peer-reviewed and deployed

**Not Quantum-Resistant**: Like all current asymmetric cryptography, Ed25519 is vulnerable to quantum computers with Shor's algorithm.

### Implementation Security

- Uses [Monocypher](https://monocypher.org/), an audited cryptographic library
- Monocypher is designed for side-channel resistance
- No custom cryptographic code (principle of "don't roll your own crypto")

## Compliance

This library is suitable for:
- General-purpose authentication
- Internal service-to-service authentication
- Developer tooling and automation

This library is NOT certified for:
- FIPS 140-2/140-3 compliance
- Medical device software
- Payments (PCI-DSS)
- Government classified systems

Always consult security/compliance experts for regulated environments.

## Security Checklist for Integrators

Before deploying nkeys-cpp in production:

- [ ] Seeds stored in secure location with appropriate access controls
- [ ] Build includes hardening flags (`NKEYS_ENABLE_HARDENING=ON`)
- [ ] All key pairs explicitly wiped after use
- [ ] Exception handling reviewed for memory safety
- [ ] Signature verification errors handled appropriately
- [ ] No seeds in logs, version control, or unsecured storage
- [ ] Tested with sanitizers during development
- [ ] Platform has secure random number generation support
- [ ] Security incident response plan in place
- [ ] Regular dependency updates (Monocypher, compiler)

## Updates and Maintenance

- Monitor this repository for security updates
- Subscribe to GitHub releases for notifications
- Review Monocypher releases for cryptographic updates
- Keep compiler and standard library updated

## References

- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
- [Monocypher Documentation](https://monocypher.org/manual/)
- [NATS NKeys Specification](https://github.com/nats-io/nkeys)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
