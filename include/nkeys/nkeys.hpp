#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "nkeys/nkeys_constants.hpp"

namespace nkeys {

    /// Key prefix types for NATS authentication.
    /// Pre-shifted so Base32's first char is human-friendly (A/U/N/C/O/P/S).
    enum class Prefix : std::uint8_t {
        Seed     = 18u << 3, // 'S' - Seed key prefix
        Private  = 15u << 3, // 'P' - Private key prefix
        Operator = 14u << 3, // 'O' - Operator key type
        Server   = 13u << 3, // 'N' - Server key type
        Cluster  = 2u << 3,  // 'C' - Cluster key type
        Account  = 0u << 3,  // 'A' - Account key type
        User     = 20u << 3, // 'U' - User key type
        Curve    = 23u << 3, // 'X' - Curve (x25519) key type — encryption, not signing
        Unknown  = 25u << 3, // 'Z' - Unknown/invalid prefix sentinel (matches Go)
    };

    /// Ed25519 key pair with signing and verification capabilities.
    /// Contains both private (seed, secret key) and public key material.
    class KeyPair {
    public:
        using Seed         = std::array<std::uint8_t, ED25519_SEED_SIZE>;
        using SecretKey    = std::array<std::uint8_t, ED25519_SECRET_KEY_SIZE>;
        using PublicKey    = std::array<std::uint8_t, ED25519_PUBLIC_KEY_SIZE>;
        virtual ~KeyPair() = default;

        /// Returns the 32-byte Ed25519 seed.
        [[nodiscard]] virtual const Seed&      seed() const noexcept = 0;
        /// Returns the 64-byte Ed25519 secret key.
        [[nodiscard]] virtual const SecretKey& secretKey() const noexcept = 0;
        /// Returns the 32-byte Ed25519 public key.
        [[nodiscard]] virtual const PublicKey& publicKey() const noexcept = 0;
        /// Returns the key type prefix (User, Account, Server, etc.).
        [[nodiscard]] virtual Prefix           prefix() const noexcept = 0;
        /// Returns the Base32-encoded seed string (starts with 'S').
        [[nodiscard]] virtual std::string      seedString() const = 0;
        /// Returns the Base32-encoded public key string.
        [[nodiscard]] virtual std::string      publicString() const = 0;
        /// Returns the Base32-encoded private key string (starts with 'P').
        /// Encodes the full 64-byte Ed25519 secret key, matching Go's PrivateKey().
        [[nodiscard]] virtual std::string      privateString() const = 0;
        /// Signs a message and returns the 64-byte Ed25519 signature.
        [[nodiscard]] virtual std::vector<uint8_t> sign(std::span<const uint8_t> msg) const = 0;
        /// Verifies a signature against a message. Returns true iff valid.
        /// A malformed signature (wrong length) is an invalid signature —
        /// it returns false rather than throwing: the bytes come from the
        /// wire, and throwing on attacker-controlled input is an exception
        /// path handed to the attacker.
        [[nodiscard]] virtual bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) const noexcept = 0;
        /// Securely wipes all sensitive key material from memory.
        virtual void wipe() = 0;
    };

    /// Creates a new User key pair with cryptographically secure random seed.
    std::unique_ptr<KeyPair> CreateUser();
    /// Creates a new Account key pair with cryptographically secure random seed.
    std::unique_ptr<KeyPair> CreateAccount();
    /// Creates a new Server key pair with cryptographically secure random seed.
    std::unique_ptr<KeyPair> CreateServer();
    /// Creates a new Cluster key pair with cryptographically secure random seed.
    std::unique_ptr<KeyPair> CreateCluster();
    /// Creates a new Operator key pair with cryptographically secure random seed.
    std::unique_ptr<KeyPair> CreateOperator();

    /// Creates a new key pair of the given public type (User, Account, Server,
    /// Cluster, Operator). Throws std::invalid_argument for any other prefix —
    /// curve (x25519) pairs are a different type with their own factory.
    std::unique_ptr<KeyPair> CreatePair(Prefix prefix);

    /// Creates a key pair from a raw 32-byte seed and specified prefix type.
    std::unique_ptr<KeyPair> FromRawSeed(const std::array<std::uint8_t, ED25519_SEED_SIZE>& rawSeed,
                                         Prefix                                             prefix);

    /// Decodes a Base32-encoded seed string and creates a key pair.
    std::unique_ptr<KeyPair> FromSeed(std::string_view b32);

    /// Public key interface capable of verifying signatures (no private key material).
    class Public {
    public:
        using PublicKey   = std::array<std::uint8_t, ED25519_PUBLIC_KEY_SIZE>;
        virtual ~Public() = default;
        /// Returns the 32-byte Ed25519 public key.
        [[nodiscard]] virtual const PublicKey& publicKey() const noexcept = 0;
        /// Returns the key type prefix (User, Account, Server, etc.).
        [[nodiscard]] virtual Prefix           prefix() const noexcept = 0;
        /// Returns the Base32-encoded public key string.
        [[nodiscard]] virtual std::string      publicString() const = 0;
        /// Verifies a signature against a message. Returns true iff valid.
        /// Malformed signatures return false; never throws (see KeyPair::verify).
        [[nodiscard]] virtual bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) const noexcept = 0;
        /// Securely wipes public key from memory.
        virtual void wipe() = 0;
    };

    /// Decodes a Base32-encoded public key string and creates a Public instance.
    std::unique_ptr<Public>  FromPublicKey(std::string_view b32);

    /// Fills the output span with cryptographically secure random bytes.
    /// Uses platform-specific secure RNG (arc4random_buf, /dev/urandom).
    /// Throws std::runtime_error if secure RNG is unavailable.
    void secureRandomBytes(std::span<std::uint8_t> out);

    /// Checks if a prefix represents an Ed25519 SIGNING public key type
    /// (User, Account, Server, Cluster, Operator). Deliberately excludes
    /// Curve: an x25519 key must never reach Ed25519 verification.
    inline bool isPublicPrefix(Prefix p) {
        return p == Prefix::Server || p == Prefix::Operator || p == Prefix::Cluster ||
               p == Prefix::Account || p == Prefix::User;
    }

    /// Checks if a prefix is valid (any of the defined prefix types).
    inline bool validPrefix(Prefix p) {
        return p == Prefix::Server || p == Prefix::Operator || p == Prefix::Cluster ||
               p == Prefix::Account || p == Prefix::User ||
               p == Prefix::Seed || p == Prefix::Private || p == Prefix::Curve;
    }

    /// Validators mirroring Go's IsValidPublic*Key family: true iff the string
    /// decodes cleanly (CRC-valid, well-formed) to a public key of the given
    /// type. noexcept — they answer, never throw.
    bool IsValidPublicKey(std::string_view b32) noexcept;         ///< any signing public type
    bool IsValidPublicUserKey(std::string_view b32) noexcept;
    bool IsValidPublicAccountKey(std::string_view b32) noexcept;
    bool IsValidPublicServerKey(std::string_view b32) noexcept;
    bool IsValidPublicClusterKey(std::string_view b32) noexcept;
    bool IsValidPublicOperatorKey(std::string_view b32) noexcept;
    bool IsValidPublicCurveKey(std::string_view b32) noexcept;    ///< x25519 'X…' key

    /// Base32 encoding/decoding with CRC16 validation for NATS keys.
    namespace codec {
        /// Encodes raw bytes with a prefix and CRC16 checksum to Base32.
        /// Format: [1-byte prefix][payload][2-byte CRC16] → Base32
        std::string Encode(Prefix                        prefix,
                           std::span<const std::uint8_t> raw);

        /// Encodes a seed with special 2-byte prefix and CRC16 checksum to Base32.
        /// Format: [2-byte prefix (Seed + type)][32-byte seed][2-byte CRC16] → Base32
        /// The prefix encodes both 'S' (Seed) and the key type (User, Account, etc.)
        std::string EncodeSeed(Prefix                        prefix,
                               std::span<const std::uint8_t> seed);

        /// Result of decoding a Base32-encoded key.
        struct Decoded {
            Prefix                    prefix;  ///< Key type prefix (for a seed: the KEY TYPE it encodes, e.g. User)
            std::vector<std::uint8_t> payload; ///< Decoded payload (seed or public key)
            bool                      isSeed = false; ///< True iff the input was an 'S…' seed string.
            ///< Without this, a decoded seed is indistinguishable from a decoded
            ///< public key of the same type — the conflation that let FromSeed
            ///< accept a public key and derive a wrong identity from its bytes.
        };

        /// Decodes a Base32-encoded key string, validates CRC16, and returns prefix + payload.
        /// Throws std::invalid_argument if CRC validation fails or format is invalid.
        Decoded Decode(std::string_view b32);
    } // namespace codec

} // namespace nkeys
