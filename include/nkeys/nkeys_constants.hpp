#pragma once

#include <cstddef>

namespace nkeys {

    /// Ed25519 key and signature sizes
    inline constexpr std::size_t ED25519_SEED_SIZE = 32;
    inline constexpr std::size_t ED25519_PUBLIC_KEY_SIZE = 32;
    inline constexpr std::size_t ED25519_SECRET_KEY_SIZE = 64;
    inline constexpr std::size_t ED25519_SIGNATURE_SIZE = 64;

    /// Encoded key sizes (Base32 with prefix and CRC)
    inline constexpr std::size_t NKEYS_PUBLIC_KEY_ENCODED_SIZE = 56;
    inline constexpr std::size_t NKEYS_SEED_ENCODED_SIZE = 58;

    /// File size limits
    inline constexpr std::size_t MAX_FILE_SIZE = 100 * 1024 * 1024;  // 100 MB

} // namespace nkeys
