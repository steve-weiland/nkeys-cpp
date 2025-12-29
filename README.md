# nkeys-cpp

A C++20 implementation of the [NATS NKeys](https://github.com/nats-io/nkeys) cryptographic library for Ed25519-based authentication.

## Overview

NKeys provides a secure, modern approach to authentication in distributed systems using Ed25519 public-key cryptography. This C++ implementation is compatible with the Go and other language implementations of NKeys, making it suitable for cross-platform NATS deployments.

### Features

- **Ed25519 Cryptography**: Fast, secure digital signatures using Monocypher
- **Multiple Key Types**: Support for User, Account, Server, Cluster, and Operator keys
- **Base32 Encoding**: Human-readable key representation with CRC16 validation
- **Secure Memory Handling**: Automatic wiping of sensitive key material
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **Modern C++20**: Type-safe API with `std::span`, `std::unique_ptr`, and concepts
- **Zero Dependencies**: Only requires C++20 standard library and CMake

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

    // Securely wipe keys from memory when done
    kp->wipe();

    return 0;
}
```

### CLI Tool (nk++)

The included `nk++` command-line tool provides key management operations:

```bash
# Generate a new user key
./build/nk++ --gen user > user.seed

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
auto operator = nkeys::CreateOperator();

// Load from seed string
auto kp = nkeys::FromSeed("SUAAV...");

// Load public key only (for verification)
auto pub = nkeys::FromPublicKey("UAH4N...");
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

### Memory Security

```cpp
// Securely wipe sensitive key material
kp->wipe();  // Zeros out seed, secret key, and public key in memory
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
- **Memory Wiping**: Always call `wipe()` on key pairs when done to clear sensitive data
- **Secure RNG**: Uses platform-specific secure random number generation (`arc4random_buf` on macOS/BSD, `/dev/urandom` on Linux)
- **Exception Safety**: All operations that generate keys use RAII guards to ensure memory is wiped even if exceptions occur
- **Constant-Time Operations**: CRC validation uses lookup tables to prevent timing attacks

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

Test suite includes:
- 22 unit tests covering all API operations
- Encoding/decoding validation
- Cryptographic operation correctness
- Security-focused tests (cross-type verification, bit flips, tampering detection)
- Memory wiping verification

## Installation

### Install from Source

After building the project, install it to your system:

```bash
# Default installation (to /usr/local/)
sudo cmake --install build

# Custom installation prefix
cmake --install build --prefix /custom/path
```

**Default Installation Locations:**
- Headers: `/usr/local/include/nkeys/`
- Library: `/usr/local/lib/libnkeys.a`
- Executable: `/usr/local/bin/nk++`

**Custom Prefix Installation:**

To install to a custom location, configure with `CMAKE_INSTALL_PREFIX`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/nkeys
cmake --build build
cmake --install build
```

This installs to:
- Headers: `/opt/nkeys/include/nkeys/`
- Library: `/opt/nkeys/lib/libnkeys.a`
- Executable: `/opt/nkeys/bin/nk++`

### Using the Installed Library

After installation, use nkeys-cpp in your CMake projects:

```cmake
# Your project's CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(my_project)

set(CMAKE_CXX_STANDARD 20)

# Find and link nkeys
add_executable(my_app main.cpp)
target_include_directories(my_app PRIVATE /usr/local/include)
target_link_libraries(my_app PRIVATE /usr/local/lib/libnkeys.a)
```

**In your code:**
```cpp
#include <nkeys/nkeys.hpp>

int main() {
    auto kp = nkeys::CreateUser();
    // ...
}
```

**Note:** Alternatively, add the install prefix to your compiler search paths:
```bash
# Compile with installed library
g++ -std=c++20 my_app.cpp -I/usr/local/include -L/usr/local/lib -lnkeys -o my_app
```

### Uninstallation

CMake doesn't provide a built-in uninstall target. To remove installed files:

```bash
# From build directory, if install_manifest.txt exists:
cat install_manifest.txt | xargs rm

# Or manually remove:
sudo rm -rf /usr/local/include/nkeys
sudo rm /usr/local/lib/libnkeys.a
sudo rm /usr/local/bin/nk++
```

## Requirements

- **Compiler**: C++20 support required
  - GCC 10+
  - Clang 12+
  - MSVC 19.29+ (Visual Studio 2019 16.10+)
- **CMake**: 3.20 or higher
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
├── tests/                 # Test suite
│   ├── nkeys_test.cpp     # Library tests
│   ├── cmd_args_test.cpp  # Tool tests
│   └── fixtures/          # Test data
├── external/monocypher/   # Ed25519 implementation
├── CMakeLists.txt         # Build configuration
└── README.md              # This file
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

This project is a port of the Go [NATS NKeys](https://github.com/nats-io/nkeys) library.

## Acknowledgments

- [NATS.io](https://nats.io/) for the original NKeys specification and Go implementation
- [Monocypher](https://monocypher.org/) for the Ed25519 cryptographic implementation
- [GoogleTest](https://github.com/google/googletest) for the testing framework
