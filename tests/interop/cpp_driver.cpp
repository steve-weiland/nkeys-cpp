// cpp_driver — the C++ half of the live interop matrix (see run.sh).
// Mode-for-mode mirror of the Go probe (main.go) so the matrix script can
// swap which side generates and which side checks:
//
//   gen <type>                          seed + public key, two lines
//   pub <seed>                          public key
//   priv <seed>                         encoded private key ('P…')
//   sign <seed> <file>                  base64url raw signature
//   verify <pub> <file> <b64url-sig>    prints CPP-VERIFY-OK or exits 1
//   xgen                                curve seed + public key, two lines
//   xpub <curve-seed>                   curve public key
//   xseal <seed> <recipientPub> <nonceHex|rand> <msgB64>   b64 ciphertext
//   xopen <seed> <senderPub> <cipherB64>                   b64 plaintext
//   jwt <credsfile>                     decorated JWT
//   nkey <credsfile>                    public key of the parsed nkey
//   usernkey <credsfile>                same, user-only
//
// Signatures are base64url (no padding) and seal payloads are standard
// base64, matching the Go probe's encodings.
#include <nkeys/nkeys.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

    std::string encodeBase(std::span<const std::uint8_t> data, const char* tbl, bool pad) {
        std::string out;
        std::size_t i = 0;
        for (; i + 2 < data.size(); i += 3) {
            std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
            out += tbl[(n >> 18) & 63];
            out += tbl[(n >> 12) & 63];
            out += tbl[(n >> 6) & 63];
            out += tbl[n & 63];
        }
        if (i + 1 == data.size()) {
            std::uint32_t n = data[i] << 16;
            out += tbl[(n >> 18) & 63];
            out += tbl[(n >> 12) & 63];
            if (pad) out += "==";
        } else if (i + 2 == data.size()) {
            std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
            out += tbl[(n >> 18) & 63];
            out += tbl[(n >> 12) & 63];
            out += tbl[(n >> 6) & 63];
            if (pad) out += "=";
        }
        return out;
    }

    std::vector<std::uint8_t> decodeBase(std::string_view s, const char* tbl) {
        std::vector<std::uint8_t> out;
        std::uint32_t buf = 0;
        int bits = 0;
        for (char c : s) {
            if (c == '=' || c == '\n' || c == '\r') continue;
            const char* p = std::char_traits<char>::find(tbl, 64, c);
            if (!p) throw std::invalid_argument(std::string("bad base64 char: ") + c);
            buf = (buf << 6) | static_cast<std::uint32_t>(p - tbl);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xff));
            }
        }
        return out;
    }

    constexpr const char* B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    constexpr const char* B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<std::uint8_t> readFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("cannot open " + path);
        std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)),
                                       std::istreambuf_iterator<char>());
        return data;
    }

    std::string readFileString(const std::string& path) {
        auto v = readFile(path);
        return {v.begin(), v.end()};
    }

    nkeys::Prefix prefixFor(std::string_view type) {
        if (type == "user") return nkeys::Prefix::User;
        if (type == "account") return nkeys::Prefix::Account;
        if (type == "server") return nkeys::Prefix::Server;
        if (type == "cluster") return nkeys::Prefix::Cluster;
        if (type == "operator") return nkeys::Prefix::Operator;
        throw std::invalid_argument("unknown key type: " + std::string(type));
    }

    nkeys::CurveKeyPair::Nonce nonceFromHex(std::string_view hex) {
        nkeys::CurveKeyPair::Nonce n{};
        if (hex.size() != 2 * n.size()) throw std::invalid_argument("nonce must be 24 bytes of hex");
        for (std::size_t i = 0; i < n.size(); ++i)
            n[i] = static_cast<std::uint8_t>(
                std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16));
        return n;
    }

} // namespace

int main(int argc, char* argv[]) try {
    const std::vector<std::string> a(argv + 1, argv + argc);
    if (a.empty()) throw std::invalid_argument("usage: cpp_driver <mode> [args…]");
    const std::string& mode = a[0];

    if (mode == "gen") {
        auto kp = nkeys::CreatePair(prefixFor(a.at(1)));
        std::cout << kp->seedString() << "\n" << kp->publicString() << "\n";
    } else if (mode == "pub") {
        std::cout << nkeys::FromSeed(a.at(1))->publicString() << "\n";
    } else if (mode == "priv") {
        std::cout << nkeys::FromSeed(a.at(1))->privateString() << "\n";
    } else if (mode == "sign") {
        auto sig = nkeys::FromSeed(a.at(1))->sign(readFile(a.at(2)));
        std::cout << encodeBase(sig, B64URL, false) << "\n";
    } else if (mode == "verify") {
        auto pub = nkeys::FromPublicKey(a.at(1));
        if (!pub->verify(readFile(a.at(2)), decodeBase(a.at(3), B64URL)))
            throw std::runtime_error("signature verification failed");
        std::cout << "CPP-VERIFY-OK\n";
    } else if (mode == "xgen") {
        auto kp = nkeys::CreateCurveKeys();
        std::cout << kp->seedString() << "\n" << kp->publicString() << "\n";
    } else if (mode == "xpub") {
        std::cout << nkeys::FromCurveSeed(a.at(1))->publicString() << "\n";
    } else if (mode == "xseal") {
        auto kp = nkeys::FromCurveSeed(a.at(1));
        auto msg = decodeBase(a.at(4), B64STD);
        auto out = (a.at(3) == "rand") ? kp->seal(msg, a.at(2))
                                       : kp->sealWithNonce(msg, a.at(2), nonceFromHex(a.at(3)));
        std::cout << encodeBase(out, B64STD, true) << "\n";
    } else if (mode == "xopen") {
        auto kp = nkeys::FromCurveSeed(a.at(1));
        auto plain = kp->open(decodeBase(a.at(3), B64STD), a.at(2));
        std::cout << encodeBase(plain, B64STD, true) << "\n";
    } else if (mode == "jwt") {
        std::cout << nkeys::ParseDecoratedJWT(readFileString(a.at(1))) << "\n";
    } else if (mode == "nkey") {
        std::cout << nkeys::ParseDecoratedNKey(readFileString(a.at(1)))->publicString() << "\n";
    } else if (mode == "usernkey") {
        std::cout << nkeys::ParseDecoratedUserNKey(readFileString(a.at(1)))->publicString() << "\n";
    } else {
        throw std::invalid_argument("unknown mode: " + mode);
    }
    return 0;
} catch (const std::exception& e) {
    std::cerr << "ERR: " << e.what() << "\n";
    return 1;
}
