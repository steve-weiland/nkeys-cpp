#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <algorithm>
#include <random>
#include <regex>
#include <string>
#include "nkeys/nkeys.hpp"

using ::testing::ContainerEq;

using namespace nkeys;

static char first_char(std::string_view s)  { return s.empty() ? '?' : s[0]; }
static char second_char(std::string_view s) { return s.size() < 2 ? '?' : s[1]; }

using Maker = std::unique_ptr<KeyPair>(*)();

class NKeysTest : public ::testing::TestWithParam<std::tuple<Prefix,char,Maker>> {};

INSTANTIATE_TEST_SUITE_P(
    Hard,
    NKeysTest,
    ::testing::Values(
        std::make_tuple(Prefix::User, 'U', &CreateUser),
        std::make_tuple(Prefix::Account, 'A', &CreateAccount),
        std::make_tuple(Prefix::Server, 'N', &CreateServer),
        std::make_tuple(Prefix::Cluster, 'C', &CreateCluster),
        std::make_tuple(Prefix::Operator, 'O', &CreateOperator)
    )
);

TEST_P(NKeysTest, EachPairEncodeDecode) {
    auto [p, expectPubFirst, maker] = GetParam();
    const auto kp = maker();
    const std::string seedB32 = kp->seedString();
    const std::string pubB32  = kp->publicString();

    EXPECT_EQ(first_char(seedB32), 'S');
    EXPECT_EQ(first_char(pubB32), expectPubFirst);
    EXPECT_EQ(second_char(seedB32), expectPubFirst);

    // 2) Round-trip Decode for seed: returns (publicPrefix, seed32)
    const auto seedRaw = codec::Decode(seedB32);
    EXPECT_EQ(seedRaw.prefix, p);
    EXPECT_EQ(seedRaw.payload.size(), 32);
    const std::vector seed(kp->seed().begin(), kp->seed().end());
    EXPECT_THAT(seedRaw.payload, ContainerEq(seed));

    // 3) Round-trip Decode for public: returns (publicPrefix, pk32)
    auto pubRaw = codec::Decode(pubB32);
    EXPECT_EQ(pubRaw.prefix, p);
    EXPECT_EQ(pubRaw.payload.size(), 32);
    const std::vector pk(kp->publicKey().begin(), kp->publicKey().end());
    EXPECT_THAT(pubRaw.payload, ContainerEq(pk));

    // sk[64] = seedRaw[32] + pubRaw[32]
    const auto        sk = kp->secretKey();
    const std::vector first32(sk.begin(), sk.begin() + 32);
    EXPECT_THAT(first32, ContainerEq(seedRaw.payload));
    const std::vector last32(sk.begin() + 32, sk.end());
    EXPECT_THAT(last32, ContainerEq(pubRaw.payload));
}

TEST(NKeysTest, EncodeErrors) {
    EXPECT_THROW(codec::Encode(Prefix::User, {}), std::invalid_argument);
    auto kp = CreateUser();
    EXPECT_THROW(codec::Encode(static_cast<Prefix>(22 << 3), kp->publicKey()), std::invalid_argument);
}

TEST(NKeysTest, DecodeErrors) {
    EXPECT_THROW(codec::Decode("foo"), std::invalid_argument);
    EXPECT_THROW(codec::Decode("ok"), std::invalid_argument);
    // Create invalid checksum
    auto account = CreateAccount();
    auto pkey = account->publicString();
    auto badPk = pkey;
    badPk[badPk.size()-1] = '0';
    badPk[badPk.size()-2] = '0';
    EXPECT_THROW(codec::Decode(badPk), std::invalid_argument);

    auto seed = account->seedString();
    auto badSeed = seed;
    badSeed[1] = 'S';
    EXPECT_THROW(codec::Decode(badSeed), std::invalid_argument);
    EXPECT_THROW(FromSeed(badSeed), std::invalid_argument);
    EXPECT_THROW(FromPublicKey(badPk), std::invalid_argument);
    EXPECT_THROW(FromPublicKey(seed), std::invalid_argument);
}

TEST(NKeysTest, Seed) {
    std::array<std::uint8_t, 16> smol{};
    secureRandomBytes(smol);
    EXPECT_THROW(codec::EncodeSeed(Prefix::User, smol), std::invalid_argument);

    // Seeds need to be typed with only public types.
    std::array<std::uint8_t, 32> seed{};
    secureRandomBytes(seed);
    EXPECT_THROW(codec::EncodeSeed(Prefix::Seed, seed), std::invalid_argument);

    secureRandomBytes(seed);
    auto encoded = codec::EncodeSeed(Prefix::User, seed);
    auto [pre, raw, isSeed] = codec::Decode(encoded);
    EXPECT_EQ(pre, Prefix::User);
    EXPECT_TRUE(isSeed) << "an encoded seed must decode AS a seed";
    const std::vector s(seed.begin(), seed.end());
    EXPECT_THAT(s, ContainerEq(raw));
}

TEST(NKeysTest, SeedFormat) {
    const auto kp   = nkeys::CreateUser();
    const auto seed = kp->seedString();
    // const auto seed = expectAndExtractValue(kp->seedString());
    // Should start with 'S' (seed prefix)
    EXPECT_EQ(first_char(seed), 'S');
    // Base32 alphabet after prefix
    std::regex re("^S[A-Z2-7]+$");
    EXPECT_TRUE(std::regex_match(seed, re));
    EXPECT_EQ(seed.size(), 58);
}

TEST(NKeysTest, UserPublicKeyFormat) {
    auto kp = nkeys::CreateUser();
    const auto pub = kp->publicString();
    // const auto pub = expectAndExtractValue(kp->publicKey());
    // Should start with 'U' (user public prefix)
    EXPECT_EQ(pub[0], 'U');
    std::regex re("^U[A-Z2-7]+$");
    EXPECT_TRUE(std::regex_match(pub, re));
    EXPECT_EQ(pub.size(), 56);
}

TEST(NKeysTest, Decode) {
    std::vector<uint8_t> raw(32);
    secureRandomBytes(raw);
    // round-trip
    auto encoded = codec::Encode(Prefix::User, raw);
    auto decoded = codec::Decode(encoded);
    EXPECT_EQ(decoded.payload, raw);
    EXPECT_EQ(decoded.prefix, Prefix::User);
}

TEST(NKeysTest, SignVerify) {
    const auto kp = nkeys::CreateUser();
    std::vector<uint8_t> msg = { 'h','e','l','l','o' };
    auto sig = kp->sign(msg);
    EXPECT_TRUE(kp->verify(msg, sig));
    sig[0] ^= 1;
    EXPECT_FALSE(kp->verify(msg, sig));
}

TEST(NKeysTest, FromRawSeed) {
    const auto user = nkeys::CreateUser();
    const auto pair = nkeys::FromRawSeed(user->seed(), Prefix::User);
    EXPECT_EQ(user->seed(), pair->seed());
    EXPECT_EQ(user->secretKey(), pair->secretKey());
    EXPECT_EQ(user->publicKey(), pair->publicKey());
    EXPECT_EQ(user->prefix(), pair->prefix());
}

TEST(NKeysTest, FromSeed) {
    const auto kp = nkeys::CreateUser();
    const auto encoded = codec::EncodeSeed(kp->prefix(), kp->seed());
    const auto pair = nkeys::FromSeed(encoded);
    EXPECT_TRUE(encoded.starts_with("SU")) << "expected SU to start encoded seed";
    EXPECT_EQ(kp->seed(), pair->seed());
    EXPECT_EQ(kp->secretKey(), pair->secretKey());
    EXPECT_EQ(kp->publicKey(), pair->publicKey());
    EXPECT_EQ(kp->prefix(), pair->prefix());
}

TEST(NKeysTest, FromPublicKey) {
    const auto kp = nkeys::CreateAccount();
    const auto encoded = kp->publicString();
    const auto pub = nkeys::FromPublicKey(encoded);
    EXPECT_EQ(pub->publicKey(), kp->publicKey());
    EXPECT_EQ(pub->prefix(), kp->prefix());
}

TEST(NKeysTest, FromPublicVerify) {
    const auto kp = nkeys::CreateUser();
    std::vector<uint8_t> msg = { 'h','e','l','l','o' };
    auto sig = kp->sign(msg);
    EXPECT_TRUE(kp->verify(msg, sig));

    const auto pk = kp->publicString();
    const auto pub = nkeys::FromPublicKey(pk);
    EXPECT_TRUE(pub->verify(msg, sig));

    const auto kp2 = nkeys::CreateUser();
    auto sig2 = kp2->sign(msg);
    ASSERT_FALSE(pub->verify(msg, sig2));
}

TEST(NKeysTest, Wipe) {
    // Helper to check if all bytes are zero
    auto allZero = [](const auto& arr) {
        return std::all_of(arr.begin(), arr.end(), [](uint8_t b) { return b == 0; });
    };

    const auto user = nkeys::CreateUser();
    const auto seed = user->seed();
    const auto secretKey = user->secretKey();
    const auto pubKey = user->publicKey();
    const auto pk = user->publicString();

    // Verify keys are not all zeros before wipe
    EXPECT_FALSE(allZero(seed));
    EXPECT_FALSE(allZero(secretKey));
    EXPECT_FALSE(allZero(pubKey));

    user->wipe();

    // After wipe, all sensitive data should be zeroed
    EXPECT_TRUE(allZero(user->seed()));
    EXPECT_TRUE(allZero(user->secretKey()));
    EXPECT_TRUE(allZero(user->publicKey()));

    const auto pubUser = FromPublicKey(pk);
    const auto ppk = pubUser->publicKey();

    // Verify public key is not all zeros before wipe
    EXPECT_FALSE(allZero(ppk));

    pubUser->wipe();

    // After wipe, public key should be zeroed
    EXPECT_TRUE(allZero(pubUser->publicKey()));
}

// Security-focused tests

TEST(NKeysTest, CrossTypeVerificationFails) {
    // Test that a signature from one key type cannot be verified by another
    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};

    auto userKey = CreateUser();
    auto serverKey = CreateServer();
    auto accountKey = CreateAccount();

    // Sign with user key
    auto userSig = userKey->sign(msg);

    // Verify with same key type (should pass)
    EXPECT_TRUE(userKey->verify(msg, userSig));

    // Try to verify with different key type (should fail)
    EXPECT_FALSE(serverKey->verify(msg, userSig));
    EXPECT_FALSE(accountKey->verify(msg, userSig));

    // Sign with server key
    auto serverSig = serverKey->sign(msg);

    // Verify with same key type (should pass)
    EXPECT_TRUE(serverKey->verify(msg, serverSig));

    // Try to verify with different key type (should fail)
    EXPECT_FALSE(userKey->verify(msg, serverSig));
    EXPECT_FALSE(accountKey->verify(msg, serverSig));
}

TEST(NKeysTest, EmptyMessageSignVerify) {
    // Test that empty messages can be signed and verified correctly
    std::vector<uint8_t> emptyMsg;

    auto kp = CreateUser();
    auto sig = kp->sign(emptyMsg);

    // Signature should be generated even for empty message
    EXPECT_EQ(sig.size(), ED25519_SIGNATURE_SIZE);

    // Verification should succeed
    EXPECT_TRUE(kp->verify(emptyMsg, sig));

    // Tampering with signature should fail verification
    sig[0] ^= 1;
    EXPECT_FALSE(kp->verify(emptyMsg, sig));
}

TEST(NKeysTest, SignatureBitFlipsDetected) {
    // Test that flipping individual bits in signature causes verification failure
    std::vector<uint8_t> msg = {'t', 'e', 's', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

    auto kp = CreateUser();
    auto sig = kp->sign(msg);

    // Original signature should verify
    EXPECT_TRUE(kp->verify(msg, sig));

    // Test bit flips at various positions in the signature
    for (size_t bytePos : {0, 10, 31, 32, 50, 63}) {
        for (int bitPos = 0; bitPos < 8; ++bitPos) {
            auto tamperedSig = sig;
            tamperedSig[bytePos] ^= (1 << bitPos);

            // Any single bit flip should cause verification to fail
            EXPECT_FALSE(kp->verify(msg, tamperedSig))
                << "Verification should fail for bit flip at byte " << bytePos
                << ", bit " << bitPos;
        }
    }
}

TEST(NKeysTest, MessageTamperingDetected) {
    // Test that any tampering with the message causes verification failure
    std::vector<uint8_t> msg = {'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};

    auto kp = CreateUser();
    auto sig = kp->sign(msg);

    // Original message should verify
    EXPECT_TRUE(kp->verify(msg, sig));

    // Flip a bit in the message
    auto tamperedMsg = msg;
    tamperedMsg[0] ^= 1;
    EXPECT_FALSE(kp->verify(tamperedMsg, sig));

    // Add a byte to the message
    tamperedMsg = msg;
    tamperedMsg.push_back('x');
    EXPECT_FALSE(kp->verify(tamperedMsg, sig));

    // Remove a byte from the message
    tamperedMsg = msg;
    tamperedMsg.pop_back();
    EXPECT_FALSE(kp->verify(tamperedMsg, sig));

    // Change one byte in the middle
    tamperedMsg = msg;
    tamperedMsg[msg.size() / 2] = 'X';
    EXPECT_FALSE(kp->verify(tamperedMsg, sig));
}

TEST(NKeysTest, PublicKeyVerificationSecurity) {
    // Test that public-only interface maintains same security properties
    std::vector<uint8_t> msg = {'s', 'e', 'c', 'u', 'r', 'e'};

    auto kp = CreateUser();
    auto sig = kp->sign(msg);
    auto pubKeyStr = kp->publicString();

    // Load public key only
    auto pub = FromPublicKey(pubKeyStr);

    // Should verify legitimate signature
    EXPECT_TRUE(pub->verify(msg, sig));

    // Should reject tampered signature
    auto tamperedSig = sig;
    tamperedSig[15] ^= 0x42;
    EXPECT_FALSE(pub->verify(msg, tamperedSig));

    // Should reject tampered message
    auto tamperedMsg = msg;
    tamperedMsg[2] = 'X';
    EXPECT_FALSE(pub->verify(tamperedMsg, sig));

    // Should reject signature from different key
    auto kp2 = CreateUser();
    auto sig2 = kp2->sign(msg);
    EXPECT_FALSE(pub->verify(msg, sig2));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// FromSeed must reject anything that is not an 'S…' seed. Pre-fix,
// codec::Decode's seed path returned the public TYPE prefix — erasing the
// fact that the input was a seed — so a 56-char PUBLIC key decoded to a
// 32-byte payload that passed FromSeed's size check, and the public-key
// bytes were used as a seed: a brand-new identity minted from a mixed-up
// .pub file, exit 0, no error anywhere. (Go: "nkeys: invalid seed".)
TEST(NKeysTest, FromSeedRejectsPublicKeyInput) {
    const auto kp = nkeys::CreateUser();
    const std::string pub = kp->publicString();
    EXPECT_THROW(
        {
            auto wrong = nkeys::FromSeed(pub);
            // Pre-fix this line was reachable and the identity was wrong:
            ADD_FAILURE() << "FromSeed accepted a public key and derived " << wrong->publicString();
        },
        std::invalid_argument);
}

// A malformed signature off the wire is an INVALID SIGNATURE, not an
// argument error: verify must return false, never throw — throwing on
// exactly the bytes an attacker controls hands them an exception path.
// (Go returns its normal verification error for the same input.)
TEST(NKeysTest, VerifyReturnsFalseOnMalformedSignature) {
    const auto kp = nkeys::CreateUser();
    const std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};
    const auto good = kp->sign(msg);

    const std::vector<uint8_t> tooShort(good.begin(), good.begin() + 63);
    const std::vector<uint8_t> empty;
    std::vector<uint8_t> tooLong = good;
    tooLong.push_back(0x00);

    EXPECT_FALSE(kp->verify(msg, tooShort));
    EXPECT_FALSE(kp->verify(msg, empty));
    EXPECT_FALSE(kp->verify(msg, tooLong));

    const auto pub = nkeys::FromPublicKey(kp->publicString());
    EXPECT_FALSE(pub->verify(msg, tooShort));
    EXPECT_TRUE(pub->verify(msg, good)) << "well-formed signatures still verify";
}

// Using a wiped key pair must be an error, not a silent signature from an
// all-zero secret key. Pre-fix, sign() after wipe() returned 64 plausible
// bytes derived from zeroed key material.
TEST(NKeysTest, SignAfterWipeThrows) {
    auto kp = nkeys::CreateUser();
    const std::vector<uint8_t> msg = {'x'};
    kp->wipe();
    EXPECT_THROW((void)kp->sign(msg), std::logic_error);
    EXPECT_THROW((void)kp->seedString(), std::logic_error);
    EXPECT_THROW((void)kp->publicString(), std::logic_error);
}

// FromRawSeed must reject non-public prefixes up front — pre-fix a
// Prefix::Seed or Private keypair constructed fine and only exploded later
// inside seedString()'s encoder, far from the actual mistake.
TEST(NKeysTest, FromRawSeedRejectsNonPublicPrefix) {
    std::array<std::uint8_t, nkeys::ED25519_SEED_SIZE> raw{};
    nkeys::secureRandomBytes(raw);
    EXPECT_THROW((void)nkeys::FromRawSeed(raw, nkeys::Prefix::Seed), std::invalid_argument);
    EXPECT_THROW((void)nkeys::FromRawSeed(raw, nkeys::Prefix::Private), std::invalid_argument);
    EXPECT_NO_THROW((void)nkeys::FromRawSeed(raw, nkeys::Prefix::User));
}

// Decoder strictness must match Go's — MEASURED against the Go library,
// not assumed: Go rejects lowercase and any '=' (NoPadding), but ACCEPTS
// non-canonical trailing slack bits (decodes them to the same key). This
// decoder previously accepted strings Go rejects (lowercase, embedded '='
// via silent truncation) — mixed-language systems could disagree about the
// validity of the same credential.
TEST(NKeysTest, DecodeStrictnessMatchesGo) {
    const auto kp = nkeys::CreateUser();
    const std::string pub = kp->publicString();

    // Lowercase: Go errors ("illegal base32 data at input byte 0").
    std::string lower = pub;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    EXPECT_THROW((void)codec::Decode(lower), std::invalid_argument);

    // '=' anywhere: Go's NoPadding treats it as illegal. The old decoder
    // BROKE at the first '=' — silently decoding a truncated prefix.
    EXPECT_THROW((void)codec::Decode(pub + "="), std::invalid_argument);

    // Non-canonical trailing slack bits: Go ACCEPTS these and decodes to
    // the same key (measured). We deliberately match — stricter would
    // reject credentials the reference implementation honors.
    std::string seed = kp->seedString();
    const std::string alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const auto idx = alph.find(seed.back());
    ASSERT_NE(idx, std::string::npos);
    std::string flipped = seed;
    flipped.back() = alph[idx ^ 0x01]; // lowest slack bit
    const auto a = codec::Decode(seed);
    const auto b = codec::Decode(flipped);
    EXPECT_EQ(a.payload, b.payload) << "slack-bit variant must decode to the same key, as Go does";

    EXPECT_NO_THROW((void)codec::Decode(pub));
}

// ---- M1: parity accessors (privateString, CreatePair, validators) ----

// Golden interop vector: the Go library's PrivateKey() for fixtures/test.seed.
// Monocypher's 64-byte secret key is seed‖pubkey — the SAME layout Go encodes
// — but that is exactly the kind of assumption this repo measures instead of
// trusting: this string came from running Go's PrivateKey() on the fixture.
TEST(NKeysTest, PrivateStringMatchesGoGoldenVector) {
    const auto kp = nkeys::FromSeed(
        "SUAKL3QNZFVCJTFW6O4IGGAEHCPVVCENDP2JCNCN3KKUEXDCKKZDRMKTLE");
    EXPECT_EQ(kp->privateString(),
              "PCS64DOJNISMZNXTXCBRQBBYT5NIRDI36SITITO2SVBFYYSSWI4LDY2ZH2YXQQ"
              "DGKQNDLFQKWHZBOA33FWUMPYTCKQJDHMYUINKKYBUGVX3Q");
}

TEST(NKeysTest, CreatePairPublicAndRejectsOthers) {
    for (auto p : {nkeys::Prefix::User, nkeys::Prefix::Account, nkeys::Prefix::Server,
                   nkeys::Prefix::Cluster, nkeys::Prefix::Operator}) {
        const auto kp = nkeys::CreatePair(p);
        EXPECT_EQ(kp->prefix(), p);
    }
    EXPECT_THROW((void)nkeys::CreatePair(nkeys::Prefix::Seed), std::invalid_argument);
    EXPECT_THROW((void)nkeys::CreatePair(nkeys::Prefix::Private), std::invalid_argument);
    // Curve pairs are a different type with a different factory (M3).
    EXPECT_THROW((void)nkeys::CreatePair(nkeys::Prefix::Curve), std::invalid_argument);
}

TEST(NKeysTest, PublicKeyValidators) {
    const auto user = nkeys::CreateUser();
    const auto account = nkeys::CreateAccount();
    const std::string upub = user->publicString();

    EXPECT_TRUE(nkeys::IsValidPublicKey(upub));
    EXPECT_TRUE(nkeys::IsValidPublicUserKey(upub));
    EXPECT_FALSE(nkeys::IsValidPublicAccountKey(upub));
    EXPECT_TRUE(nkeys::IsValidPublicAccountKey(account->publicString()));

    // Seeds, garbage, and truncation are invalid everywhere — and the
    // validators are noexcept: they answer, never throw.
    EXPECT_FALSE(nkeys::IsValidPublicKey(user->seedString()));
    EXPECT_FALSE(nkeys::IsValidPublicUserKey("not a key"));
    EXPECT_FALSE(nkeys::IsValidPublicKey(upub.substr(0, 40)));
    EXPECT_FALSE(nkeys::IsValidPublicKey(""));
}

// ---- M2: decorated creds parsing (all expectations MEASURED from Go) ----

namespace {
std::string readFixture(const char* name) {
    std::ifstream f(std::string(NKEYS_TEST_FIXTURES_DIR "/") + name, std::ios::binary);
    EXPECT_TRUE(f.is_open()) << "fixture " << name;
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
constexpr const char* kFixtureJwt =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJVRFJWU1BWUlBCQUdNVkEyR1dMQVZNUFNDNEJYV0xOSVk3UkdFVkFTR09aUklRMlVWUURJTU5EWiJ9.ZmFrZS1zaWduYXR1cmU";
constexpr const char* kFixturePub =
    "UDRVSPVRPBAGMVA2GWLAVMPSC4BXWLNIY7RGEVASGOZRIQ2UVQDIMNDZ";
} // namespace

TEST(CredsTest, ParsesJwtAndNKeyFromArmoredCreds) {
    const auto creds = readFixture("user.creds");
    EXPECT_EQ(nkeys::ParseDecoratedJWT(creds), kFixtureJwt);
    EXPECT_EQ(nkeys::ParseDecoratedNKey(creds)->publicString(), kFixturePub);
    EXPECT_EQ(nkeys::ParseDecoratedUserNKey(creds)->publicString(), kFixturePub);
}

TEST(CredsTest, UserNKeyRejectsAccountCreds) {
    const auto creds = readFixture("account.creds");
    EXPECT_EQ(nkeys::ParseDecoratedNKey(creds)->prefix(), nkeys::Prefix::Account);
    EXPECT_THROW((void)nkeys::ParseDecoratedUserNKey(creds), std::invalid_argument);
}

// Measured: Go returns non-armored content UNMODIFIED — trailing newline and all.
TEST(CredsTest, BareJwtPassesThroughByteExact) {
    EXPECT_EQ(nkeys::ParseDecoratedJWT("just-a-bare.jwt.token\n"), "just-a-bare.jwt.token\n");
}

TEST(CredsTest, UnarmoredSeedFileLineScan) {
    const std::string contents =
        std::string("# comment\n") + "SUAKL3QNZFVCJTFW6O4IGGAEHCPVVCENDP2JCNCN3KKUEXDCKKZDRMKTLE\n";
    EXPECT_EQ(nkeys::ParseDecoratedNKey(contents)->publicString(), kFixturePub);
}

// Measured Go quirk, matched deliberately: the line-scan tests the TRIMMED
// line for the SO/SA/SU prefix but keeps the RAW line, whose leading
// whitespace then fails the final prefix check — an indented unarmored seed
// errors in Go, so it errors here.
TEST(CredsTest, IndentedUnarmoredSeedErrorsLikeGo) {
    const std::string contents =
        std::string("  SUAKL3QNZFVCJTFW6O4IGGAEHCPVVCENDP2JCNCN3KKUEXDCKKZDRMKTLE\n");
    EXPECT_THROW((void)nkeys::ParseDecoratedNKey(contents), std::invalid_argument);
}

TEST(CredsTest, NoSeedAnywhereThrows) {
    EXPECT_THROW((void)nkeys::ParseDecoratedNKey("nothing here\n"), std::invalid_argument);
}

// ---- M3: typed CurveKeyPair (x25519, 'X'/'SX') ----

// Golden vector generated by Go's CreateCurveKeys(): this seed must derive
// exactly this public key — pins seed decode, x25519 derivation, and
// encoding against the reference implementation in one assertion.
TEST(XKeysTest, GoldenCurvePairFromGo) {
    const auto kp = nkeys::FromCurveSeed(
        "SXAHRVDTGWRFQRLVYUTCCYS3NCE2PKIKQFVQHFZNSJ5RETCVJUV2UPJJTU");
    EXPECT_EQ(kp->publicString(),
              "XBRMGQL4FWUF7HH5ZDDREO2I7L67FIFYHZJKFWYPBGJ5VLW4VLUCH2VI");
    EXPECT_EQ(kp->prefix(), nkeys::Prefix::Curve);
    EXPECT_EQ(kp->seedString(),
              "SXAHRVDTGWRFQRLVYUTCCYS3NCE2PKIKQFVQHFZNSJ5RETCVJUV2UPJJTU");
    EXPECT_EQ(kp->privateString().front(), 'P'); // curve private = 32-byte seed under 'P'
    EXPECT_TRUE(nkeys::IsValidPublicCurveKey(kp->publicString()));
}

TEST(XKeysTest, CreateCurveKeysShape) {
    const auto kp = nkeys::CreateCurveKeys();
    EXPECT_EQ(kp->seedString().substr(0, 2), "SX");
    EXPECT_EQ(kp->publicString().front(), 'X');
    EXPECT_EQ(kp->publicString().size(), nkeys::NKEYS_PUBLIC_KEY_ENCODED_SIZE);
    EXPECT_EQ(kp->seedString().size(), nkeys::NKEYS_SEED_ENCODED_SIZE);
}

// The typed divergence from Go, on purpose: Go's FromSeed dispatches curve
// seeds to a pair whose Sign/Verify error at runtime; here the types differ,
// so FromSeed refuses 'SX…' and points at FromCurveSeed.
TEST(XKeysTest, FromSeedRefusesCurveSeeds) {
    EXPECT_THROW(
        (void)nkeys::FromSeed("SXAHRVDTGWRFQRLVYUTCCYS3NCE2PKIKQFVQHFZNSJ5RETCVJUV2UPJJTU"),
        std::invalid_argument);
}

TEST(XKeysTest, FromCurveSeedRefusesSigningSeeds) {
    EXPECT_THROW(
        (void)nkeys::FromCurveSeed("SUAKL3QNZFVCJTFW6O4IGGAEHCPVVCENDP2JCNCN3KKUEXDCKKZDRMKTLE"),
        std::invalid_argument);
}

// Ed25519 verification must never accept an X key (isPublicPrefix invariant).
TEST(XKeysTest, FromPublicKeyRefusesCurveKeys) {
    EXPECT_THROW(
        (void)nkeys::FromPublicKey("XBRMGQL4FWUF7HH5ZDDREO2I7L67FIFYHZJKFWYPBGJ5VLW4VLUCH2VI"),
        std::invalid_argument);
}

TEST(XKeysTest, CurveWipeDisablesPair) {
    auto kp = nkeys::CreateCurveKeys();
    kp->wipe();
    EXPECT_THROW((void)kp->seedString(), std::logic_error);
    EXPECT_THROW((void)kp->publicString(), std::logic_error);
}


// ---------------------------------------------------------------------------
// XKeys Seal/Open — NaCl-box compatibility, gated on ciphertexts produced by
// the live Go library (probe xseal/xopen). The fixed-nonce vectors demand
// BYTE-IDENTICAL output, not just mutual decryptability.
// ---------------------------------------------------------------------------

namespace {

    std::vector<std::uint8_t> fromHex(std::string_view hex) {
        std::vector<std::uint8_t> out(hex.size() / 2);
        for (std::size_t i = 0; i < out.size(); ++i)
            out[i] = static_cast<std::uint8_t>(std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16));
        return out;
    }

    std::span<const std::uint8_t> asBytes(std::string_view s) {
        return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
    }

    // Pair A: the recorded Go golden pair; Pair B: generated by Go (probe xgen).
    constexpr std::string_view kSealSeedA = "SXAHRVDTGWRFQRLVYUTCCYS3NCE2PKIKQFVQHFZNSJ5RETCVJUV2UPJJTU";
    constexpr std::string_view kSealPubA  = "XBRMGQL4FWUF7HH5ZDDREO2I7L67FIFYHZJKFWYPBGJ5VLW4VLUCH2VI";
    constexpr std::string_view kSealSeedB = "SXAOMS4WC2HDMPXFOBPKW64IFOUYY7J3VI5ZVFMZCLT7ACT3PNR5DY6NYM";
    constexpr std::string_view kSealPubB  = "XAPZI5HDZ7RYGAOLQFZVRPDBKOAM3MIE2UTGKBR6FE4TTAWYCM4GOT4T";
    constexpr std::string_view kSealMsg   = "this is a test message for nkeys xkeys interop";
    // Nonce 000102…17; Go: probe xseal SEED_A PUB_B <nonce> <msg>
    constexpr std::string_view kGoldenCipherHex =
        "786b7631000102030405060708090a0b0c0d0e0f1011121314151617"
        "f2959468268a52c40b79825b4b1e193122454bf88d3c0436ac3e7cb9242f3a0c"
        "b40e66f0b3cdef3f9a2528f2a98d319e1c363a73d02cf78c13d07e3947a5";
    // Same nonce, empty message.
    constexpr std::string_view kGoldenEmptyCipherHex =
        "786b7631000102030405060708090a0b0c0d0e0f1011121314151617"
        "46c08e8b9695418caa4a30e5fd54ff39";

    nkeys::CurveKeyPair::Nonce fixedNonce() {
        nkeys::CurveKeyPair::Nonce n{};
        for (std::size_t i = 0; i < n.size(); ++i) n[i] = static_cast<std::uint8_t>(i);
        return n;
    }

} // namespace

TEST(XKeysSealTest, SealWithNonceMatchesGoByteForByte) {
    auto a = nkeys::FromCurveSeed(kSealSeedA);
    EXPECT_EQ(a->sealWithNonce(asBytes(kSealMsg), kSealPubB, fixedNonce()),
              fromHex(kGoldenCipherHex));
    EXPECT_EQ(a->sealWithNonce({}, kSealPubB, fixedNonce()),
              fromHex(kGoldenEmptyCipherHex));
}

TEST(XKeysSealTest, OpenGoldenCiphertextFromGo) {
    auto b = nkeys::FromCurveSeed(kSealSeedB);
    auto plain = b->open(fromHex(kGoldenCipherHex), kSealPubA);
    EXPECT_EQ(std::string(plain.begin(), plain.end()), kSealMsg);
    EXPECT_TRUE(b->open(fromHex(kGoldenEmptyCipherHex), kSealPubA).empty());
}

TEST(XKeysSealTest, SealOpenRoundTripWithRandomNonce) {
    auto a = nkeys::CreateCurveKeys();
    auto b = nkeys::CreateCurveKeys();
    auto ct = a->seal(asBytes(kSealMsg), b->publicString());
    auto plain = b->open(ct, a->publicString());
    EXPECT_EQ(std::string(plain.begin(), plain.end()), kSealMsg);
    // A stranger's key must not open it.
    auto mallory = nkeys::CreateCurveKeys();
    EXPECT_THROW((void)mallory->open(ct, a->publicString()), std::exception);
}

TEST(XKeysSealTest, OpenRejectsTamperedCiphertext) {
    auto b = nkeys::FromCurveSeed(kSealSeedB);
    auto ct = fromHex(kGoldenCipherHex);
    ct.back() ^= 0x01; // flip one ciphertext bit
    EXPECT_THROW((void)b->open(ct, kSealPubA), std::exception);
    auto tag = fromHex(kGoldenCipherHex);
    tag[nkeys::CURVE_VERSION_SIZE + nkeys::CURVE_NONCE_SIZE] ^= 0x01; // flip a tag bit
    EXPECT_THROW((void)b->open(tag, kSealPubA), std::exception);
}

TEST(XKeysSealTest, OpenRejectsWrongVersionAndShortInput) {
    auto b = nkeys::FromCurveSeed(kSealSeedB);
    auto ct = fromHex(kGoldenCipherHex);
    ct[0] = 'y'; // not "xkv1"
    EXPECT_THROW((void)b->open(ct, kSealPubA), std::exception);
    // Go: len(input) <= vlen+nonce is ErrInvalidEncrypted
    std::vector<std::uint8_t> tooShort(nkeys::CURVE_VERSION_SIZE + nkeys::CURVE_NONCE_SIZE, 0);
    EXPECT_THROW((void)b->open(tooShort, kSealPubA), std::exception);
}

TEST(XKeysSealTest, SealRejectsNonCurveRecipientAndOpenRejectsNonCurveSender) {
    auto a = nkeys::FromCurveSeed(kSealSeedA);
    auto user = nkeys::CreatePair(nkeys::Prefix::User);
    EXPECT_THROW((void)a->seal(asBytes(kSealMsg), user->publicString()), std::exception);
    auto b = nkeys::FromCurveSeed(kSealSeedB);
    EXPECT_THROW((void)b->open(fromHex(kGoldenCipherHex), user->publicString()), std::exception);
}
