#include <gtest/gtest.h>
#include <gmock/gmock.h>
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
    auto [pre, raw] = codec::Decode(encoded);
    EXPECT_EQ(pre, Prefix::User);
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
