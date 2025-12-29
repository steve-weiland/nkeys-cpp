# Contributing to nkeys-cpp

Thank you for your interest in contributing to nkeys-cpp! This document provides guidelines and best practices for contributing to the project.

## Getting Started

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 19.29+)
- CMake 3.20 or higher
- Git
- Basic knowledge of cryptography (helpful but not required)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourorg/nkeys-cpp.git
cd nkeys-cpp

# Build with debug symbols and sanitizers
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DNKEYS_ENABLE_ASAN=ON \
    -DNKEYS_WARNINGS_AS_ERRORS=ON

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check existing issues to avoid duplicates
2. Verify the bug exists in the latest version
3. Gather relevant information (OS, compiler, CMake version)

**Bug Report Template:**

```markdown
**Description**
Clear description of the bug

**Steps to Reproduce**
1. Step 1
2. Step 2
3. ...

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Ubuntu 22.04, macOS 14.0]
- Compiler: [e.g., GCC 11.3, Clang 15.0]
- CMake: [e.g., 3.25.1]
- Build Type: [Debug/Release]

**Additional Context**
Logs, stack traces, etc.
```

### Suggesting Features

Feature requests are welcome! Please include:
- **Use case**: Why is this feature needed?
- **Proposed API**: How should it work?
- **Alternatives**: What other approaches did you consider?
- **Implementation ideas**: How might this be implemented?

## Development Guidelines

### Code Style

**Formatting**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Opening braces on same line for functions and classes
- Use clang-format (configuration TBD)

**Naming Conventions**
```cpp
// Classes: PascalCase
class KeyPairImpl { ... };

// Functions: camelCase
void secureRandomBytes(...);

// Variables: camelCase
std::uint8_t prefixByte;

// Constants: UPPER_SNAKE_CASE
inline constexpr std::size_t ED25519_SEED_SIZE = 32;

// Namespaces: lowercase
namespace nkeys { ... }
```

**Modern C++ Practices**
```cpp
// ✅ Prefer auto with clear types
auto kp = nkeys::CreateUser();

// ✅ Use std::span for non-owning views
void processData(std::span<const uint8_t> data);

// ✅ Use [[nodiscard]] for pure functions
[[nodiscard]] virtual bool verify(...) const = 0;

// ✅ Use std::unique_ptr for ownership
std::unique_ptr<KeyPair> createPair(Prefix prefix);

// ❌ Don't use raw pointers for ownership
KeyPair* createPair(Prefix prefix); // No!

// ❌ Don't use C-style casts
int x = (int)value; // No!
int x = static_cast<int>(value); // Yes!
```

### Error Handling

**Exception Policy**
- Use exceptions for error conditions
- Prefer `std::invalid_argument` for bad input
- Prefer `std::runtime_error` for runtime failures
- Never throw from destructors or `noexcept` functions

**Error Message Format**
```cpp
// ✅ Good: Descriptive with component and reason
throw std::invalid_argument("Invalid seed: must be 32 bytes");

// ❌ Bad: Vague or abbreviated
throw std::invalid_argument("bad seed");
```

### Memory Safety

**Critical Rules**
1. Always wipe sensitive data when done
2. Use RAII for automatic cleanup
3. Use `volatile` for security-critical zeroing
4. Test with AddressSanitizer

**Example: Secure Temporary Data**
```cpp
// ✅ Good: RAII ensures cleanup
{
    KeyPair::Seed seed{};
    SecureGuard<KeyPair::Seed> guard(seed);
    secureRandomBytes(seed);
    // ... use seed ...
} // Automatically wiped

// ❌ Bad: Manual cleanup can be forgotten
KeyPair::Seed seed{};
secureRandomBytes(seed);
// ... use seed ...
secureZero(seed); // What if exception happens?
```

### Testing Requirements

All contributions must include tests:

**What to Test**
- ✅ All new public APIs
- ✅ Error conditions and exceptions
- ✅ Edge cases (empty input, maximum sizes)
- ✅ Security properties (wipe verification, cross-type checks)

**Test Structure**
```cpp
TEST(NKeysTest, DescriptiveName) {
    // Arrange: Set up test data
    auto kp = CreateUser();
    std::vector<uint8_t> msg = {'t', 'e', 's', 't'};

    // Act: Perform operation
    auto sig = kp->sign(msg);

    // Assert: Verify results
    EXPECT_TRUE(kp->verify(msg, sig));
    EXPECT_EQ(sig.size(), 64);
}
```

**Running Tests**
```bash
# Standard test run
ctest --test-dir build --output-on-failure

# With sanitizers
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DNKEYS_ENABLE_ASAN=ON
cmake --build build
ctest --test-dir build

# Verbose output
ctest --test-dir build --verbose
```

### Documentation

**Code Documentation**
- Add comments for non-obvious logic
- Document all public APIs with Doxygen-style comments
- Include parameter descriptions and return values
- Note any exceptions that can be thrown

**Example:**
```cpp
/// Creates a new User key pair with cryptographically secure random seed.
/// @return Unique pointer to KeyPair instance
/// @throws std::runtime_error if secure RNG unavailable
std::unique_ptr<KeyPair> CreateUser();
```

**User Documentation**
- Update README.md for new features
- Add examples for new APIs
- Update SECURITY.md for security-relevant changes

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] No compiler warnings
- [ ] Sanitizers pass (ASAN, UBSAN)

### Commit Messages

Follow conventional commits format:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or changes
- `refactor`: Code restructuring without behavior change
- `perf`: Performance improvements
- `build`: Build system changes
- `ci`: CI/CD changes

**Examples:**
```
feat: add support for x25519 curve keys

Implements x25519 key generation and conversion from ed25519.
Includes comprehensive tests for key conversion.

Closes #123
```

```
fix: prevent memory leak in key generation

SecureGuard was not properly wrapping temporary buffers
in the derive() function, causing potential leaks on
exception paths.
```

### Pull Request Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Bullet list of changes

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Sanitizers pass
- [ ] No new warnings
```

### Review Process

1. **Automated Checks**: CI must pass
2. **Code Review**: At least one maintainer approval
3. **Discussion**: Address all review comments
4. **Merge**: Squash or merge based on maintainer preference

## Code of Conduct

### Our Standards

- **Respectful**: Treat everyone with respect
- **Collaborative**: Work together towards common goals
- **Constructive**: Provide helpful feedback
- **Professional**: Maintain professional conduct

### Unacceptable Behavior

- Harassment, discrimination, or offensive language
- Personal attacks or trolling
- Publishing private information
- Unprofessional or unwelcome conduct

## Development Workflow

### Branch Strategy

- `main`: Stable, release-ready code
- `develop`: Integration branch for features
- `feature/*`: Feature branches
- `fix/*`: Bug fix branches

### Typical Workflow

```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes, test locally
# ...

# Commit changes
git add .
git commit -m "feat: add my feature"

# Push and create PR
git push origin feature/my-feature
```

## Security-Sensitive Changes

For changes involving cryptography or security:

1. **Extra scrutiny**: Security-critical code requires thorough review
2. **Testing**: Include security-focused tests
3. **Documentation**: Update SECURITY.md if threat model changes
4. **Expert review**: Consider external security review for major changes

**Never:**
- Implement custom cryptographic algorithms
- Disable security features without justification
- Skip memory wiping for sensitive data
- Introduce timing vulnerabilities

## Getting Help

- **Questions**: Open a GitHub discussion
- **Chat**: [Link to Discord/Slack if available]
- **Email**: [Maintainer email]

## Recognition

Contributors are recognized in:
- Git commit history
- Release notes
- Contributors list (if we add one)

Thank you for contributing to nkeys-cpp! Your efforts help make secure authentication accessible to everyone.
