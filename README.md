# nkeys-cpp

[![CI](https://github.com/steve-weiland/nkeys-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/steve-weiland/nkeys-cpp/actions/workflows/ci.yml)

A C++20 implementation of the [NATS NKeys](https://github.com/nats-io/nkeys) cryptographic library for Ed25519-based authentication.

## Overview

NKeys provides a secure, modern approach to authentication in distributed systems using Ed25519 public-key cryptography. This C++ implementation is compatible with the Go and other language implementations of NKeys, making it suitable for cross-platform NATS deployments.

### Features

- **Ed25519 Cryptography**: Fast, secure digital signatures using Monocypher
- **Multiple Key Types**: Support for User, Account, Server, Cluster, and Operator keys
- **XKeys Encryption**: Curve (x25519) key pairs with NaCl-box `seal`/`open`,
  byte-compatible with Go's `Seal`/`Open` (verified against live Go ciphertexts)
- **Decorated Credentials**: `ParseDecoratedJWT` / `ParseDecoratedNKey` /
  `ParseDecoratedUserNKey` for NATS `.creds` files
- **Base32 Encoding**: Human-readable key representation with CRC16 validation
- **Secure Memory Handling**: Automatic wiping of sensitive key material
- **Cross-Platform**: macOS and Linux (both build- and test-verified); Windows pending a secure-RNG implementation (see SECURITY.md)
- **Modern C++20**: Type-safe API with `std::span`, `std::unique_ptr`, and concepts
- **No External Dependencies**: C++20 standard library and CMake only — Monocypher is vendored in-tree

## Quick Start

### Building

```bash
# Configure and build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

### Basic Usage

```cpp
#include <nkeys/nkeys.hpp>
#include <iostream>

int main() {
    // Generate a new user key pair
    auto kp = nkeys::CreateUser();

    // Get the encoded keys
    std::string seed = kp->seedString();      // Private seed (keep secret!)
    std::string publicKey = kp->publicString(); // Public key (share freely)

    std::cout << "Seed: " << seed << "\n";
    std::cout << "Public: " << publicKey << "\n";

    // Sign a message
    std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
    auto signature = kp->sign(message);

    // Verify signature
    bool valid = kp->verify(message, signature);
    std::cout << "Signature valid: " << (valid ? "yes" : "no") << "\n";

    // Key material is wiped automatically when the pair is destroyed.
    // Call wipe() only to end its lifetime EARLY — the pair is unusable after.
    kp->wipe();

    return 0;
}
```

### CLI Tool (nk++)

The included `nk++` command-line tool provides key management operations:

```bash
# Generate a new user key
./build/nk++ --gen user > user.seed

# Generate a curve (x25519) encryption key pair
./build/nk++ --gen curve --pubout

# Extract public key from seed
./build/nk++ --inkey user.seed --pubout > user.pub

# Sign a file
./build/nk++ --sign data.txt --inkey user.seed > data.sig

# Verify signature
./build/nk++ --verify data.txt --sigfile data.sig --pubin user.pub
```

Run `./build/nk++` without arguments to see all available options and examples.

## API Reference

### Key Generation

```cpp
// Create new key pairs
auto user     = nkeys::CreateUser();
auto account  = nkeys::CreateAccount();
auto server   = nkeys::CreateServer();
auto cluster  = nkeys::CreateCluster();
auto oper     = nkeys::CreateOperator(); // ('operator' is a C++ keyword)

// Or create by prefix
auto kp2 = nkeys::CreatePair(nkeys::Prefix::User);

// Load from seed string
auto kp = nkeys::FromSeed("SUAAV...");

// Load public key only (for verification)
auto pub = nkeys::FromPublicKey("UAH4N...");

// Encoded accessors
kp->seedString();    // "SUAAV..." — the seed (keep secret!)
kp->publicString();  // "UAH4N..." — the public key
kp->privateString(); // "PA6X..."  — the raw private key (rarely needed; prefer the seed)
```

### Signing and Verification

```cpp
// Sign a message
std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};
auto signature = kp->sign(msg);

// Verify with full key pair
bool valid = kp->verify(msg, signature);

// Verify with public key only
auto pub = nkeys::FromPublicKey(kp->publicString());
bool valid = pub->verify(msg, signature);
```

### Curve Keys (XKeys) — Encryption

Curve keys encrypt; they don't sign. They are a separate type — where Go's
single `KeyPair` interface errors at runtime if a curve pair is asked to
`Sign`, here `FromSeed` rejects `SX…` seeds at the door and `CurveKeyPair`
simply has no `sign`.

```cpp
auto alice = nkeys::CreateCurveKeys();          // seed "SX…", public "X…"
auto bob   = nkeys::FromCurveSeed("SXAHRV...");

// NaCl box, wire-compatible with Go: "xkv1" || nonce || tag || ciphertext
std::vector<uint8_t> msg = {'h', 'i'};
auto sealed = alice->seal(msg, bob->publicString());     // random nonce
auto opened = bob->open(sealed, alice->publicString());  // throws if tampered
```

`sealWithNonce()` exists for deterministic test vectors (Go's `SealWithRand`)
— never reuse a nonce for real traffic.

### Decorated Credentials (.creds files)

```cpp
std::string creds = /* contents of a NATS .creds file */;
std::string jwt = nkeys::ParseDecoratedJWT(creds);       // first armored block (or bare JWT)
auto kp  = nkeys::ParseDecoratedNKey(creds);             // the seed inside
auto ukp = nkeys::ParseDecoratedUserNKey(creds);         // same, but must be a user seed
```

The parsed seed is wiped from intermediate buffers on every path; quirks match
Go (an indented bare seed line is NOT found, exactly as in the Go parser).

### Validation Helpers

```cpp
nkeys::IsValidPublicKey(s);         // any public type
nkeys::IsValidPublicUserKey(s);     // plus Account/Server/Cluster/Operator/Curve variants
```

### Error Handling

Every failure the library throws derives from `nkeys::Error` (in
`<nkeys/nkeys_errors.hpp>`, included by the main header), so library errors
are distinguishable from the standard library's own exceptions — and each
concrete type ALSO derives from the std exception it historically was, so
existing `catch (std::invalid_argument)` code keeps working.

```cpp
try {
    auto kp = nkeys::FromSeed(userInput);
} catch (const nkeys::InvalidKeyError& e) {
    // malformed key/seed/encoding, or the wrong kind of key
} catch (const nkeys::Error& e) {
    // any other nkeys failure; e.what() carries the message
}
```

| type | std base | thrown for |
|---|---|---|
| `InvalidKeyError` | `std::invalid_argument` | malformed or wrong-type keys, seeds, encodings |
| `DecryptionError` | `std::runtime_error` | `open()`: bad wire format/version, failed authentication |
| `CredsError` | `std::invalid_argument` | `.creds` parsing: no seed found / wrong seed type |
| `RandomnessError` | `std::runtime_error` | secure RNG unavailable or failed |
| `WipedKeyError` | `std::logic_error` | key pair used after `wipe()` |

`verify()` never throws — malformed signatures return `false` (wire data is
attacker-controlled; an exception path would be handed to the attacker).

### Memory Security

Key material is zeroed automatically when a `KeyPair` is destroyed. To end
its lifetime early:

```cpp
kp->wipe();  // zeros seed, secret key, and public key; the pair is unusable after
```

## Build Options

### CMake Options

```bash
# Enable sanitizers for development
cmake -B build -DNKEYS_ENABLE_ASAN=ON      # AddressSanitizer
cmake -B build -DNKEYS_ENABLE_UBSAN=ON     # UndefinedBehaviorSanitizer

# Security hardening (enabled by default in Release)
cmake -B build -DNKEYS_ENABLE_HARDENING=ON # Stack protection, FORTIFY_SOURCE, RELRO

# Treat warnings as errors
cmake -B build -DNKEYS_WARNINGS_AS_ERRORS=ON

# Use system GTest instead of fetching
cmake -B build -DNKEYS_USE_SYSTEM_GTEST=ON

# Shared library instead of static
cmake -B build -DBUILD_SHARED_LIBS=ON

# Embed-oriented switches (all default ON at the top level, OFF when this
# project is consumed via add_subdirectory/FetchContent)
cmake -B build -DNKEYS_BUILD_TESTS=OFF -DNKEYS_BUILD_CLI=OFF -DNKEYS_INSTALL=OFF
```

### Build Types

```bash
# Release build (optimized, with hardening)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Debug build (symbols, assertions)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Release with debug info
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

## Security Considerations

- **Seed Protection**: Seeds contain private key material and must be kept secret
- **Memory Wiping**: automatic on destruction; `wipe()` ends the key material's lifetime early and marks the pair unusable
- **Secure RNG**: platform-specific secure generation — `arc4random_buf` on macOS/BSD, `getrandom(2)` on Linux (with `/dev/urandom` fallback)
- **Exception Safety**: All operations that generate keys use RAII guards to ensure memory is wiped even if exceptions occur
- **Constant-Time Cryptography**: all secret-dependent operations are constant-time via Monocypher. (The CRC16 is an integrity check on encodings, not a security boundary.)

See [SECURITY.md](SECURITY.md) for detailed security documentation.

## Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run with sanitizers
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DNKEYS_ENABLE_ASAN=ON
cmake --build build
ctest --test-dir build
```

Test suite covers:
- All public API operations, encoding/decoding, and error paths
- Cryptographic correctness, including Go-measured decoder strictness
- Golden vectors produced by the live Go library — including byte-identical
  fixed-nonce `seal` ciphertexts (see `tests/interop/` for the Go probe that
  generated them and can re-verify against a Go checkout)
- Security-focused cases (cross-type verification, bit flips, tampering,
  use-after-wipe, malformed signatures, public-key-as-seed rejection)
- Memory wiping verification

## Installation

### Install from Source

Set the prefix at configure time (so the generated pkg-config file carries the
real install location), then build and install:

```bash
# Default prefix (/usr/local) — sudo for the install step
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build

# Custom prefix
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/nkeys
cmake --build build
cmake --install build
```

This installs headers (`include/nkeys/`), the library (`lib/libnkeys.a`, or
`.so`/`.dylib` with `-DBUILD_SHARED_LIBS=ON`), the `nk++` binary, the CMake
package files (`lib/cmake/nkeys/`), and a pkg-config file (`lib/pkgconfig/`).

### Using the Installed Library

**CMake (`find_package`)** — the intended path:

```cmake
cmake_minimum_required(VERSION 3.21)
project(my_project CXX)

find_package(nkeys 1.0 CONFIG REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE nkeys::nkeys)
```

The `nkeys::nkeys` target carries the include paths and the C++20 requirement;
no manual paths or `CMAKE_CXX_STANDARD` needed. For a non-default prefix, point
CMake at it: `cmake -B build -DCMAKE_PREFIX_PATH=/opt/nkeys`.

**Embedding (`add_subdirectory` / `FetchContent`)** — no install required:

```cmake
include(FetchContent)
FetchContent_Declare(nkeys
    GIT_REPOSITORY https://github.com/steve-weiland/nkeys-cpp.git
    GIT_TAG v1.0.0)
FetchContent_MakeAvailable(nkeys)

target_link_libraries(my_app PRIVATE nkeys::nkeys)
```

Embedded builds get only the library: tests, `nk++`, and install rules are
top-level-only by default (`NKEYS_BUILD_TESTS` / `NKEYS_BUILD_CLI` /
`NKEYS_INSTALL`).

**pkg-config** — for non-CMake builds:

```bash
g++ -std=c++20 my_app.cpp $(pkg-config --cflags --libs nkeys) -o my_app
```

**In your code:**
```cpp
#include <nkeys/nkeys.hpp>

int main() {
    auto kp = nkeys::CreateUser();
    // ...
}
```

All four consumption paths (find_package static + shared, pkg-config,
add_subdirectory embed) are exercised by `tests/packaging/test.sh` in CI —
which also asserts symbol hygiene: `libnkeys` exports **no** `crypto_*`
symbols (the vendored Monocypher is renamed to an `nkeys__` prefix at build
time), so linking your own Monocypher alongside nkeys neither collides nor
silently substitutes one copy for the other.

### Uninstallation

CMake doesn't provide a built-in uninstall target. To remove installed files:

```bash
# From build directory, if install_manifest.txt exists:
cat install_manifest.txt | xargs rm

# Or manually remove:
sudo rm -rf /usr/local/include/nkeys /usr/local/lib/cmake/nkeys
sudo rm /usr/local/lib/libnkeys.a /usr/local/lib/pkgconfig/nkeys.pc /usr/local/bin/nk++
```

## Requirements

- **Compiler**: C++20 support required
  - GCC 10+ (build/test-verified on GCC 13)
  - Clang 12+ (build/test-verified on Apple Clang)
  - MSVC 19.29+ should compile, but key **generation** throws until a
    Windows secure-RNG backend lands (contributions welcome)
- **CMake**: 3.21 or higher
- **Dependencies**: None (Monocypher included, GoogleTest auto-fetched for tests)

## Project Structure

```
nkeys-cpp/
├── include/nkeys/         # Public API headers
│   ├── nkeys.hpp          # Main API
│   └── nkeys_constants.hpp # Constants
├── src/                   # Implementation
│   ├── nkeys.cpp          # Core implementation
│   └── tools/             # Command-line tools
│       ├── nk-main.cpp    # CLI tool
│       └── cmd_args.hpp   # Argument parser
├── cmake/                 # Package-config + pkg-config templates
├── tests/                 # Test suite
│   ├── nkeys_test.cpp     # Library tests
│   ├── cmd_args_test.cpp  # Tool tests
│   ├── fixtures/          # Test data
│   ├── interop/           # Live Go↔C++ matrix (run.sh) + the Go probe
│   │                      #   that produced every golden vector
│   └── packaging/         # Consumability gate: find_package/pkg-config/embed
├── external/monocypher/   # Ed25519 / X25519 / Poly1305 primitives
├── CMakeLists.txt         # Build configuration
└── README.md              # This file
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Licensed under the [Apache License 2.0](LICENSE) — the same license as the
Go [NATS NKeys](https://github.com/nats-io/nkeys) library this project is a
port of. Vendored [Monocypher](https://monocypher.org/) is used under its
BSD-2-Clause option (dual CC0/BSD-2); see [NOTICE](NOTICE).

## Acknowledgments

- [NATS.io](https://nats.io/) for the original NKeys specification and Go implementation
- [Monocypher](https://monocypher.org/) for the Ed25519, X25519, and Poly1305 primitives
  (the Salsa20 core needed for NaCl-box compatibility is vendored in `src/nkeys.cpp`)
- [GoogleTest](https://github.com/google/googletest) for the testing framework
