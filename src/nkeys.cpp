#include "nkeys/nkeys.hpp"

#include <algorithm> // std::copy_n — libc++ provides it transitively, libstdc++ does not
#include <array>
#include <cassert>
#include <random>
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#endif

extern "C" {
#include <monocypher/monocypher-ed25519.h>
#include <monocypher/monocypher.h> // crypto_x25519_public_key for curve keys
}

namespace nkeys {

    // Forward declarations
    static void secureZero(std::span<std::uint8_t> data);

    // RAII guard to ensure sensitive data is wiped on both normal and error paths
    template<typename T>
    class SecureGuard {
    public:
        explicit SecureGuard(T& data) : data_(data) {}
        ~SecureGuard() { secureZero(data_); }
        SecureGuard(const SecureGuard&) = delete;
        SecureGuard& operator=(const SecureGuard&) = delete;
    private:
        T& data_;
    };

    class KeyPairImpl final : public KeyPair {
    public:
        KeyPairImpl(const Seed& s, const SecretKey& sk, const PublicKey& pk, Prefix prefix)
            : seed_(s), sk_(sk), pk_(pk), prefix_(prefix) {}

        // Wiping is automatic: destruction zeroes the key material whether or
        // not the caller remembered wipe(). Explicit wipe() remains for ending
        // the material's lifetime EARLY (and marks the pair unusable).
        ~KeyPairImpl() override {
            secureZero(seed_);
            secureZero(sk_);
            secureZero(pk_);
        }

        [[nodiscard]] const Seed& seed() const noexcept override {
            return seed_;
        }

        [[nodiscard]] const SecretKey& secretKey() const noexcept override {
            return sk_;
        }

        [[nodiscard]] const PublicKey& publicKey() const noexcept override {
            return pk_;
        }

        [[nodiscard]] Prefix prefix() const noexcept override {
            return prefix_;
        }

        [[nodiscard]] std::string seedString() const override {
            requireLive();
            return codec::EncodeSeed(prefix_, seed_);
        }

        [[nodiscard]] std::string publicString() const override {
            requireLive();
            return codec::Encode(prefix_, pk_);
        }

        [[nodiscard]] std::string privateString() const override {
            requireLive();
            // The 64-byte secret key (seed‖pubkey) under the 'P' prefix —
            // byte-identical to Go's PrivateKey() (golden-vector tested).
            return codec::Encode(Prefix::Private, sk_);
        }

        [[nodiscard]] std::vector<uint8_t> sign(std::span<const uint8_t> msg) const override {
            // Signing with zeroed key material would return 64 plausible-looking
            // bytes — a use-after-wipe must be loud, not a silent bad signature.
            requireLive();
            std::vector<uint8_t> sig(ED25519_SIGNATURE_SIZE);
            crypto_ed25519_sign(sig.data(), sk_.data(), msg.data(), msg.size());
            return sig;
        }

        [[nodiscard]] bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) const noexcept override {
            if (sig.size() != ED25519_SIGNATURE_SIZE) return false; // malformed = invalid, not an error

            const int ok = crypto_ed25519_check(sig.data(), pk_.data(), msg.data(), msg.size());
            return ok == 0;
        }

        void wipe() override {
            secureZero(seed_);
            secureZero(sk_);
            secureZero(pk_);
            wiped_ = true;
        }

    private:
        void requireLive() const {
            if (wiped_) throw std::logic_error("key pair has been wiped");
        }

        Seed      seed_{};
        SecretKey sk_{};
        PublicKey pk_{};
        Prefix    prefix_{Prefix::User};
        bool      wiped_{false};
    };

    class PublicImpl final : public Public {
    public:
        PublicImpl(const PublicKey& pk, Prefix pubPrefix) : pk_(pk), prefix_(pubPrefix) {}

        [[nodiscard]] const PublicKey& publicKey() const noexcept override {
            return pk_;
        }

        [[nodiscard]] Prefix prefix() const noexcept override {
            return prefix_;
        }

        [[nodiscard]] std::string publicString() const override {
            return codec::Encode(prefix_, pk_);
        }

        [[nodiscard]] bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) const noexcept override {
            if (sig.size() != ED25519_SIGNATURE_SIZE) return false; // malformed = invalid, not an error
            const int ok = crypto_ed25519_check(sig.data(), pk_.data(), msg.data(), msg.size());
            return ok == 0;
        }

        void wipe() override {
            secureZero(pk_);
        }

    private:
        PublicKey pk_{};
        Prefix    prefix_{Prefix::User};
    };

    // --- Secure memory operations ---

    // Securely zero memory - prevents compiler optimization from removing the write
    static void secureZero(std::span<std::uint8_t> data) {
        if (data.empty()) return;
        volatile std::uint8_t* p = data.data();
        for (size_t i = 0; i < data.size(); ++i) {
            p[i] = 0;
        }
    }

    void secureRandomBytes(std::span<std::uint8_t> out) {
        if (out.empty()) return;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        // Use arc4random_buf() on BSD-derived systems (macOS, BSD)
        // This is cryptographically secure and doesn't require file I/O
        arc4random_buf(out.data(), out.size());
        return;
#elif defined(__linux__) || defined(__unix__)
#if defined(__linux__)
        // Prefer getrandom(2): no file descriptor (works under fd exhaustion,
        // chroot, and seccomp policies that allow it), and blocks only until
        // the kernel entropy pool is initialized. Fall back to /dev/urandom
        // only if the kernel predates it (ENOSYS).
        {
            size_t total = 0;
            bool unsupported = false;
            while (total < out.size()) {
                const ssize_t n = ::getrandom(out.data() + total, out.size() - total, 0);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    if (errno == ENOSYS) { unsupported = true; break; }
                    throw std::runtime_error("getrandom() failed for secure random bytes");
                }
                total += static_cast<size_t>(n);
            }
            if (!unsupported) return;
        }
#endif
        // /dev/urandom with complete read validation (non-Linux unix, or
        // Linux kernels without getrandom).
        FILE* f = std::fopen("/dev/urandom", "rb");
        if (!f) {
            throw std::runtime_error("Failed to open /dev/urandom for secure random bytes");
        }

        size_t total_read = 0;
        while (total_read < out.size()) {
            size_t n = std::fread(out.data() + total_read, 1, out.size() - total_read, f);
            if (n == 0) {
                // Inspect the stream BEFORE closing it — the previous code
                // called feof(f) after fclose(f): use-after-free of the FILE.
                const bool hitEof = std::feof(f) != 0;
                std::fclose(f);
                throw std::runtime_error(hitEof ? "Unexpected EOF reading /dev/urandom"
                                                : "Failed to read from /dev/urandom");
            }
            total_read += n;
        }
        std::fclose(f);
        return;
#else
        // No secure RNG available on this platform
        throw std::runtime_error("Secure random number generation not available on this platform");
#endif
    }

    static KeyPair::SecretKey derive(const KeyPair::Seed& seed, KeyPair::PublicKey& pk) {
        KeyPair::SecretKey sk{};
        // make a mutable copy, Monocypher wipes the seed
        std::array<std::uint8_t, ED25519_SEED_SIZE> seed_copy = seed;

        crypto_ed25519_key_pair(sk.data(), pk.data(), seed_copy.data());

        return sk;
    }

    static std::unique_ptr<KeyPair> createPair(Prefix prefix) {
        KeyPair::Seed seed{};
        SecureGuard<KeyPair::Seed> seedGuard(seed);
        secureRandomBytes(seed);

        KeyPair::PublicKey pk{};
        SecureGuard<KeyPair::PublicKey> pkGuard(pk);

        KeyPair::SecretKey sk = derive(seed, pk);
        SecureGuard<KeyPair::SecretKey> skGuard(sk);

        // KeyPairImpl constructor copies the data, then guards wipe stack copies
        return std::make_unique<KeyPairImpl>(seed, sk, pk, prefix);
    }

    std::unique_ptr<KeyPair> CreatePair(Prefix prefix) {
        if (!isPublicPrefix(prefix))
            throw std::invalid_argument(
                "Invalid prefix: CreatePair takes a signing key type (User, Account, ...); "
                "curve pairs have their own factory");
        return createPair(prefix);
    }

    std::unique_ptr<KeyPair> CreateUser() {
        return createPair(Prefix::User);
    }

    std::unique_ptr<KeyPair> CreateAccount() {
        return createPair(Prefix::Account);
    }

    std::unique_ptr<KeyPair> CreateServer() {
        return createPair(Prefix::Server);
    }

    std::unique_ptr<KeyPair> CreateCluster() {
        return createPair(Prefix::Cluster);
    }

    std::unique_ptr<KeyPair> CreateOperator() {
        return createPair(Prefix::Operator);
    }

    std::unique_ptr<KeyPair> FromRawSeed(const std::array<std::uint8_t, ED25519_SEED_SIZE>& rawSeed,
                                         Prefix                                             prefix) {
        // Fail here, at the mistake — not later inside seedString()'s encoder.
        if (!isPublicPrefix(prefix))
            throw std::invalid_argument("Invalid prefix: must be a public key type (User, Account, ...)");
        KeyPair::PublicKey pk{};
        KeyPair::SecretKey sk = derive(rawSeed, pk);
        // Wipe the stack copy of the secret key after the ctor copies it —
        // createPair guards its locals the same way.
        SecureGuard<KeyPair::SecretKey> skGuard(sk);
        return std::make_unique<KeyPairImpl>(rawSeed, sk, pk, prefix);
    }

    std::unique_ptr<KeyPair> FromSeed(std::string_view b32) {
        auto decoded = codec::Decode(b32);
        // A public key of the right type also carries a 32-byte payload — only
        // the 'S…' seed form may reach key derivation (Go: "nkeys: invalid seed").
        if (!decoded.isSeed) throw std::invalid_argument("Invalid seed: not a seed string (expected 'S' prefix)");
        if (decoded.prefix == Prefix::Curve)
            throw std::invalid_argument("Curve ('SX…') seed: use FromCurveSeed — curve pairs encrypt, they don't sign");
        const auto& prefix = decoded.prefix;
        auto& payload = decoded.payload;
        if (payload.size() != ED25519_SEED_SIZE) throw std::invalid_argument("Invalid seed: must be 32 bytes");

        std::array<std::uint8_t, ED25519_SEED_SIZE> seed{};
        SecureGuard<std::array<std::uint8_t, ED25519_SEED_SIZE>> seedGuard(seed);
        std::copy_n(payload.begin(), ED25519_SEED_SIZE, seed.begin());
        auto kp = FromRawSeed(seed, prefix);
        // The decoded payload vector also holds the seed bytes — wipe it too.
        secureZero(payload);
        return kp;
    }

    std::unique_ptr<Public> FromPublicKey(std::string_view b32) {
        if (b32.size() != NKEYS_PUBLIC_KEY_ENCODED_SIZE) {
            throw std::invalid_argument("Invalid encoded key: must be 56 characters");
        }
        const auto decoded = codec::Decode(b32);
        if (decoded.isSeed) {
            throw std::invalid_argument("Invalid public key: got a seed string");
        }
        const auto& prefix = decoded.prefix;
        const auto& payload = decoded.payload;
        if (payload.size() != ED25519_PUBLIC_KEY_SIZE) {
            throw std::invalid_argument("Invalid public key: must be 32 bytes");
        }

        if (!isPublicPrefix(prefix)) {
            throw std::invalid_argument("Invalid prefix: not a public key type");
        }

        std::array<std::uint8_t, ED25519_PUBLIC_KEY_SIZE> pk{};
        std::copy_n(payload.begin(), ED25519_PUBLIC_KEY_SIZE, pk.begin());
        return std::make_unique<PublicImpl>(pk, prefix);
    }

    // ---------------- Curve (x25519) key pairs ----------------

    class CurveKeyPairImpl final : public CurveKeyPair {
    public:
        explicit CurveKeyPairImpl(const Seed& seed) : seed_(seed) {
            crypto_x25519_public_key(pk_.data(), seed_.data());
        }
        ~CurveKeyPairImpl() override {
            secureZero(seed_);
            secureZero(pk_);
        }
        [[nodiscard]] Prefix prefix() const noexcept override { return Prefix::Curve; }
        [[nodiscard]] std::string seedString() const override {
            requireLive();
            return codec::EncodeSeed(Prefix::Curve, seed_);
        }
        [[nodiscard]] std::string publicString() const override {
            requireLive();
            return codec::Encode(Prefix::Curve, pk_);
        }
        [[nodiscard]] std::string privateString() const override {
            requireLive();
            // Curve private keys encode the 32-byte seed (Go quirk, matched) —
            // Ed25519 pairs encode their 64-byte secret key here.
            return codec::Encode(Prefix::Private, seed_);
        }
        void wipe() override {
            secureZero(seed_);
            secureZero(pk_);
            wiped_ = true;
        }

    private:
        void requireLive() const {
            if (wiped_) throw std::logic_error("curve key pair has been wiped");
        }
        Seed      seed_{};
        PublicKey pk_{};
        bool      wiped_{false};
    };

    std::unique_ptr<CurveKeyPair> CreateCurveKeys() {
        CurveKeyPair::Seed seed{};
        SecureGuard<CurveKeyPair::Seed> guard(seed);
        secureRandomBytes(seed);
        return std::make_unique<CurveKeyPairImpl>(seed);
    }

    std::unique_ptr<CurveKeyPair> FromCurveSeed(std::string_view b32) {
        auto decoded = codec::Decode(b32);
        if (!decoded.isSeed || decoded.prefix != Prefix::Curve)
            throw std::invalid_argument("Invalid curve seed: expected an 'SX…' seed string");
        if (decoded.payload.size() != ED25519_SEED_SIZE)
            throw std::invalid_argument("Invalid curve seed: must be 32 bytes");
        CurveKeyPair::Seed seed{};
        SecureGuard<CurveKeyPair::Seed> guard(seed);
        std::copy_n(decoded.payload.begin(), ED25519_SEED_SIZE, seed.begin());
        secureZero(decoded.payload);
        return std::make_unique<CurveKeyPairImpl>(seed);
    }

    // ---------------- Decorated creds parsing (Go's creds_utils) ----------------

    namespace {
        // Go: `\s*(?:(?:[-]{3,}.*[-]{3,}\r?\n)([\w\-.=]+)(?:\r?\n[-]{3,}.*[-]{3,}\r?\n))`
        // ECMAScript '.' does not match '\n', same as Go's — verified against
        // the Go library on shared fixtures, not assumed.
        const std::regex& credsBlockRe() {
            static const std::regex re(
                R"(\s*(?:(?:[-]{3,}.*[-]{3,}
?
)([\w\-.=]+)(?:
?
[-]{3,}.*[-]{3,}
?
)))");
            return re;
        }

        std::vector<std::string> credsBlocks(std::string_view contents) {
            std::vector<std::string> out;
            std::cregex_iterator it(contents.data(), contents.data() + contents.size(), credsBlockRe());
            for (std::cregex_iterator end; it != end; ++it) {
                out.emplace_back((*it)[1].str());
            }
            return out;
        }

        std::string_view trimView(std::string_view v) {
            const auto isws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
            while (!v.empty() && isws(v.front())) v.remove_prefix(1);
            while (!v.empty() && isws(v.back())) v.remove_suffix(1);
            return v;
        }

        bool startsWithSeedType(std::string_view v) {
            return v.substr(0, 2) == "SO" || v.substr(0, 2) == "SA" || v.substr(0, 2) == "SU";
        }
    } // namespace

    std::string ParseDecoratedJWT(std::string_view contents) {
        auto blocks = credsBlocks(contents);
        if (blocks.empty()) {
            // No armor: Go returns the content unmodified, byte-exact.
            return std::string(contents);
        }
        std::string jwt(trimView(blocks[0]));
        for (auto& b : blocks) secureZero({reinterpret_cast<std::uint8_t*>(b.data()), b.size()});
        return jwt;
    }

    std::unique_ptr<KeyPair> ParseDecoratedNKey(std::string_view contents) {
        std::string seedLine;
        auto blocks = credsBlocks(contents);
        if (blocks.size() > 1) {
            seedLine = blocks[1];
        } else {
            // Go's line-scan, quirk included: the TRIMMED line is tested for
            // the seed prefix, but the RAW line is kept — so an indented seed
            // fails the final prefix check below, exactly as Go errors.
            std::string_view rest = contents;
            while (!rest.empty()) {
                const auto nl = rest.find('\n');
                std::string_view line = rest.substr(0, nl);
                if (startsWithSeedType(trimView(line))) {
                    seedLine = std::string(line);
                    break;
                }
                if (nl == std::string_view::npos) break;
                rest.remove_prefix(nl + 1);
            }
        }
        for (auto& b : blocks) secureZero({reinterpret_cast<std::uint8_t*>(b.data()), b.size()});
        const auto wipeLine = [&seedLine]() {
            secureZero({reinterpret_cast<std::uint8_t*>(seedLine.data()), seedLine.size()});
        };
        if (seedLine.empty())
            throw std::invalid_argument("no nkey seed found");
        if (!startsWithSeedType(seedLine)) {
            wipeLine();
            throw std::invalid_argument("doesn't contain a valid nkey seed");
        }
        try {
            auto kp = FromSeed(seedLine);
            wipeLine();
            return kp;
        } catch (...) {
            wipeLine();
            throw;
        }
    }

    std::unique_ptr<KeyPair> ParseDecoratedUserNKey(std::string_view contents) {
        auto kp = ParseDecoratedNKey(contents);
        if (kp->prefix() != Prefix::User)
            throw std::invalid_argument("doesn't contain a user seed nkey");
        return kp;
    }

    // ---------------- Validators (Go's IsValidPublic*Key family) ----------------

    namespace {
        bool isValidPublicOfType(std::string_view b32, Prefix want) noexcept {
            try {
                const auto d = codec::Decode(b32);
                if (d.isSeed || d.payload.size() != ED25519_PUBLIC_KEY_SIZE) return false;
                return d.prefix == want;
            } catch (...) {
                return false;
            }
        }
    } // namespace

    bool IsValidPublicKey(std::string_view b32) noexcept {
        try {
            const auto d = codec::Decode(b32);
            return !d.isSeed && d.payload.size() == ED25519_PUBLIC_KEY_SIZE &&
                   isPublicPrefix(d.prefix);
        } catch (...) {
            return false;
        }
    }
    bool IsValidPublicUserKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::User); }
    bool IsValidPublicAccountKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::Account); }
    bool IsValidPublicServerKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::Server); }
    bool IsValidPublicClusterKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::Cluster); }
    bool IsValidPublicOperatorKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::Operator); }
    bool IsValidPublicCurveKey(std::string_view b32) noexcept { return isValidPublicOfType(b32, Prefix::Curve); }

    // ---------------- Codec ----------------
    namespace {

        constexpr char B32_ALPH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        std::vector<std::uint8_t> base32_decode(std::string_view s) {
            auto val = [](char c) -> int {
                if (c >= 'A' && c <= 'Z')
                    return c - 'A';
                if (c >= '2' && c <= '7')
                    return c - '2' + 26;
                return -1;
            };
            std::vector<std::uint8_t> out;
            int                       buffer = 0, bitsLeft = 0;
            for (char ch : s) {
                // Strictness measured against Go's decoder: uppercase only
                // (no tolower leniency), and '=' is illegal — NoPadding means
                // padding characters don't exist, and the old break-on-'='
                // silently decoded a truncated prefix. Trailing slack bits,
                // however, are ACCEPTED: Go decodes them to the same key.
                int v = val(ch);
                if (v < 0)
                    throw std::invalid_argument("Invalid Base32 encoding: illegal character");
                buffer = (buffer << 5) | v;
                bitsLeft += 5;
                if (bitsLeft >= 8) {
                    bitsLeft -= 8;
                    out.push_back(static_cast<std::uint8_t>((buffer >> bitsLeft) & 0xFF));
                }
            }
            return out;
        }

        std::string base32_encode(std::span<const std::uint8_t> in) {
            std::string out;
            int         buffer = 0, bitsLeft = 0;
            for (std::uint8_t b : in) {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;
                while (bitsLeft >= 5) {
                    bitsLeft -= 5;
                    out.push_back(B32_ALPH[(buffer >> bitsLeft) & 0x1F]);
                }
            }
            if (bitsLeft) {
                out.push_back(B32_ALPH[(buffer << (5 - bitsLeft)) & 0x1F]);
            }
            return out; // no padding
        }

        // CRC-16/CCITT-XMODEM lookup table (poly 0x1021, init 0x0000, ref=false)
        // Using lookup table for constant-time operation (prevents timing attacks)
        constexpr std::uint16_t CRC16_TABLE[256] = {
            0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
            0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
            0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
            0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
            0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
            0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
            0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
            0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
            0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
            0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
            0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
            0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
            0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
            0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
            0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
            0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
            0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
            0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
            0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
            0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
            0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
            0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
            0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
            0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
            0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
            0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
            0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
            0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
            0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
            0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
            0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
            0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
        };

        std::uint16_t crc16_ccitt_xmodem(std::span<const std::uint8_t> buf) {
            std::uint16_t crc = 0x0000;
            for (std::uint8_t b : buf) {
                // Constant-time lookup table access
                crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ b) & 0xFF];
            }
            return crc;
        }

    } // namespace

    std::string codec::Encode(Prefix prefix, std::span<const std::uint8_t> raw) {
        if (!validPrefix(prefix))
            throw std::invalid_argument("Invalid prefix: not a valid prefix type");
        if (raw.empty())
            throw std::invalid_argument("Invalid payload: cannot be empty");
        // Layout: [prefix(1)][payload][crc16 LE(2)]
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + raw.size() + 2);
        buf.push_back(static_cast<std::uint8_t>(prefix));
        buf.insert(buf.end(), raw.begin(), raw.end());
        std::uint16_t crc = crc16_ccitt_xmodem(buf);
        buf.push_back(static_cast<std::uint8_t>(crc & 0xFF));        // LE
        buf.push_back(static_cast<std::uint8_t>((crc >> 8) & 0xFF)); // LE
        return base32_encode(buf);
    }

    std::string codec::EncodeSeed(Prefix prefix, std::span<const std::uint8_t> seed32) {
        if (seed32.size() != ED25519_SEED_SIZE)
            throw std::invalid_argument("Invalid seed: must be 32 bytes");
        // Seedable types are the signing publics PLUS Curve ("SX…") — Go's
        // EncodeSeed accepts curve too. isPublicPrefix stays curve-free on
        // purpose (Ed25519 verification must never see an X key).
        if (!isPublicPrefix(prefix) && prefix != Prefix::Curve)
            throw std::invalid_argument("Invalid prefix: must be a seedable key type");

        // We want Base32 chars:
        //   c0 = 'S' (value 18), c1 = public type ('U','A','N','C','O')
        // Let vS  = 18 (index of 'S'), vT = (publicPrefix >> 3)  (index of type)
        // We construct two bytes so that Base32 sees:
        //   c0 = top5(b0) = vS
        //   c1 = (low3(b0) << 2) | top2(b1) = vT
        //
        // Using the pre-shifted byte values: Seed = (18<<3), type = (t<<3),
        //   vS = Seed >> 3  == 18
        //   vT = publicPrefix >> 3  in [0..31]
        const auto vT = static_cast<uint8_t>(static_cast<uint8_t>(prefix) >> 3);

        const uint8_t b0 = static_cast<uint8_t>(Prefix::Seed) |
                           static_cast<uint8_t>(vT >> 2); // top5(b0)=18, low3 carry top3 of vT
        const auto b1 = static_cast<uint8_t>((vT & 0x03) << 6); // top2(b1)=low2 of vT

        // Layout we CRC and Base32-encode: [b0][b1][seed(32)][crc16 LE]
        std::vector<std::uint8_t> buf;
        buf.reserve(2 + ED25519_SEED_SIZE + 2);
        buf.push_back(b0);
        buf.push_back(b1);
        buf.insert(buf.end(), seed32.begin(), seed32.end());

        std::uint16_t crc = crc16_ccitt_xmodem(buf);
        buf.push_back(static_cast<std::uint8_t>(crc & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((crc >> 8) & 0xFF));

        return base32_encode(buf);
    }

    codec::Decoded codec::Decode(std::string_view b32) {
        auto raw = base32_decode(b32);
        if (raw.size() < 3)
            throw std::invalid_argument("Invalid encoded key: too short");

        const std::size_t   n = raw.size() - 2;
        const std::uint16_t expect =
            static_cast<std::uint16_t>(raw[n]) | (static_cast<std::uint16_t>(raw[n + 1]) << 8);
        const std::uint16_t got = crc16_ccitt_xmodem(std::span<const std::uint8_t>(raw.data(), n));
        if (expect != got)
            throw std::invalid_argument("Invalid encoded key: CRC checksum failed");

        // Seed path: first Base32 char must be 'S' – in our packed form that means
        // top5(raw[0]) == 18. The public type is carried in:
        //   vT = (low3(raw[0]) << 2) | (top2(raw[1]))
        // Then the seed bytes start at raw[2] for 32 bytes.
        const auto top5 = [](uint8_t b) { return b >> 3; };
        const auto low3 = [](uint8_t b) { return b & 0x07; };
        const auto top2 = [](uint8_t b) { return b >> 6; };

        if (top5(raw[0]) == 18) { // 'S'
            if (raw.size() != 2 + ED25519_SEED_SIZE + 2)
                throw std::invalid_argument("Invalid seed: wrong size");
            const auto vT = static_cast<uint8_t>((low3(raw[0]) << 2) | top2(raw[1])); // 0..31
            // Rebuild the public Prefix byte (= vT << 3)
            auto pub = static_cast<Prefix>(static_cast<uint8_t>(vT << 3));
            // sanity check: only allow seedable types (signing publics + Curve)
            if (!isPublicPrefix(pub) && pub != Prefix::Curve)
                throw std::invalid_argument("Invalid prefix: not a valid seed key type");
            std::vector<std::uint8_t> payload(raw.begin() + 2, raw.begin() + 2 + ED25519_SEED_SIZE);
            return {pub, std::move(payload), /*isSeed=*/true}; // payload = 32B seed
        }

        // 1-byte prefix (public/private)
        const auto p = static_cast<Prefix>(raw[0]);
        // Validate that the prefix is a known valid value
        if (!validPrefix(p)) {
            throw std::invalid_argument("Invalid prefix: unknown prefix byte");
        }
        std::vector<std::uint8_t> payload(raw.begin() + 1, raw.begin() + n);
        return {p, std::move(payload), /*isSeed=*/false};
    }

} // namespace nkeys
