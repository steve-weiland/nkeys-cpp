#include "nkeys/nkeys.hpp"
#include "cmd_args.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <algorithm>
#include <cctype>

/// Base64 URL Encoding (Raw, No Padding)
std::string base64UrlEncode(std::span<const uint8_t> data) {
    static constexpr char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);

    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        out.push_back(tbl[(n >> 6) & 0x3F]);
        out.push_back(tbl[n & 0x3F]);
    }

    // Handle remaining bytes
    if (i < data.size()) {
        uint32_t n = data[i] << 16;
        if (i + 1 < data.size()) {
            n |= data[i + 1] << 8;
        }
        out.push_back(tbl[(n >> 18) & 0x3F]);
        out.push_back(tbl[(n >> 12) & 0x3F]);
        if (i + 1 < data.size()) {
            out.push_back(tbl[(n >> 6) & 0x3F]);
        }
    }

    return out;
}

std::vector<uint8_t> base64UrlDecode(std::string_view encoded) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve((encoded.size() * 3) / 4);

    uint32_t buffer = 0;
    int bitsLeft = 0;

    for (char ch : encoded) {
        int v = val(ch);
        if (v < 0) {
            throw std::invalid_argument("Invalid Base64 URL character");
        }
        buffer = (buffer << 6) | v;
        bitsLeft += 6;
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF));
        }
    }

    // Validate no unexpected leftover bits (indicates malformed encoding)
    if (bitsLeft >= 6) {
        throw std::invalid_argument("Invalid Base64 encoding: unexpected padding or truncation");
    }
    // Any remaining bits should be zeros (proper padding)
    if (bitsLeft > 0 && (buffer & ((1 << bitsLeft) - 1)) != 0) {
        throw std::invalid_argument("Invalid Base64 encoding: non-zero padding bits");
    }

    return out;
}

template<typename... OpenModeArgs>
std::ifstream openFile(const std::string& filename, OpenModeArgs... modes) {
    std::ifstream file(filename, modes...);
    if (!file) {
        throw std::runtime_error("Cannot open file for reading: " + filename +
                                " (check file exists and permissions)");
    }
    return file;
}

std::vector<uint8_t> readFileContents(const std::string& filename) {
    auto file = openFile(filename, std::ios::binary | std::ios::ate);

    auto size = file.tellg();

    // Validate file size
    if (size < 0) {
        throw std::runtime_error("Failed to determine file size: " + filename);
    }
    if (size > static_cast<std::streamsize>(nkeys::MAX_FILE_SIZE)) {
        throw std::runtime_error("File too large (max 100MB): " + filename);
    }

    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }

    return buffer;
}

std::string readFileAsString(const std::string& filename) {
    auto file = openFile(filename);

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Trim whitespace
    return trim(content);
}

bool isValidKeyEncoding(std::string_view line) {
    // Valid keys are 56 chars (public) or 58 chars (seed)
    if (line.size() != nkeys::NKEYS_PUBLIC_KEY_ENCODED_SIZE &&
        line.size() != nkeys::NKEYS_SEED_ENCODED_SIZE) {
        return false;
    }

    // Must start with valid prefix
    if (line.empty()) return false;
    char first = line[0];
    if (first != 'S' && first != 'U' && first != 'A' &&
        first != 'N' && first != 'C' && first != 'O' && first != 'P' &&
        first != 'X') {
        return false;
    }

    // All characters must be Base32 alphabet [A-Z2-7]
    for (char ch : line) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7'))) {
            return false;
        }
    }

    return true;
}

std::string readKeyFile(const std::string& filename) {
    auto file = openFile(filename);

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (isValidKeyEncoding(line)) {
            return line;
        }
    }

    throw std::runtime_error("Could not find a valid key in file: " + filename);
}

nkeys::Prefix prefixForType(const std::string& type) {
    std::string lower = type;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    if (lower == "user") return nkeys::Prefix::User;
    if (lower == "account") return nkeys::Prefix::Account;
    if (lower == "server") return nkeys::Prefix::Server;
    if (lower == "cluster") return nkeys::Prefix::Cluster;
    if (lower == "operator") return nkeys::Prefix::Operator;

    if (lower == "curve" || lower == "x25519") return nkeys::Prefix::Curve;

    throw std::runtime_error("Invalid key type: " + type +
                            " (must be user, account, server, cluster, operator, or curve)");
}

void handleGenerate(const cmd_args& args) {
    auto typeOpt = args.get("gen");
    if (!typeOpt) {
        throw std::runtime_error("Missing key type for -gen");
    }

    nkeys::Prefix prefix = prefixForType(*typeOpt);

    if (prefix == nkeys::Prefix::Curve) {
        auto ckp = nkeys::CreateCurveKeys();
        std::cout << ckp->seedString() << "\n";
        if (args.get("pubout")) {
            std::cout << ckp->publicString() << "\n";
        }
        return;
    }

    std::unique_ptr<nkeys::KeyPair> kp;

    switch (prefix) {
        case nkeys::Prefix::User:
            kp = nkeys::CreateUser();
            break;
        case nkeys::Prefix::Account:
            kp = nkeys::CreateAccount();
            break;
        case nkeys::Prefix::Server:
            kp = nkeys::CreateServer();
            break;
        case nkeys::Prefix::Cluster:
            kp = nkeys::CreateCluster();
            break;
        case nkeys::Prefix::Operator:
            kp = nkeys::CreateOperator();
            break;
        default:
            throw std::runtime_error("Unsupported key type");
    }

    std::cout << kp->seedString() << "\n";

    if (args.get("pubout")) {
        std::cout << kp->publicString() << "\n";
    }
}

void handlePubout(const cmd_args& args) {
    auto keyFile = args.get("inkey");
    if (!keyFile) {
        throw std::runtime_error("Extracting public key requires --inkey <file>");
    }

    std::string seedStr = readKeyFile(*keyFile);
    if (seedStr.rfind("SX", 0) == 0) {
        std::cout << nkeys::FromCurveSeed(seedStr)->publicString() << "\n";
        return;
    }
    auto kp = nkeys::FromSeed(seedStr);
    std::cout << kp->publicString() << "\n";
}

void handleSign(const cmd_args& args) {
    auto signFile = args.get("sign");
    auto keyFile = args.get("inkey");

    if (!keyFile) {
        throw std::runtime_error("Sign requires both --sign <file> and --inkey <keyfile>");
    }

    std::string seedStr = readKeyFile(*keyFile);
    auto kp = nkeys::FromSeed(seedStr);

    auto content = readFileContents(*signFile);

    auto signature = kp->sign(content);

    std::string encoded = base64UrlEncode(signature);
    std::cout << encoded << "\n";
}

void handleVerify(const cmd_args& args) {
    auto verifyFile = args.get("verify");
    auto sigFile = args.get("sigfile");

    if (!sigFile) {
        throw std::runtime_error("Verify requires --verify <file>, --sigfile <file>, and either --inkey or --pubin");
    }

    auto keyFile = args.get("inkey");
    auto pubFile = args.get("pubin");

    if (!keyFile && !pubFile) {
        throw std::runtime_error("Verify requires either --inkey <file> or --pubin <file> for key verification");
    }

    // Read content and signature
    auto content = readFileContents(*verifyFile);
    std::string sigEncoded = readFileAsString(*sigFile);
    auto signature = base64UrlDecode(sigEncoded);

    // Validate signature length (Ed25519 signatures are always 64 bytes)
    if (signature.size() != nkeys::ED25519_SIGNATURE_SIZE) {
        throw std::runtime_error("Invalid signature length: expected 64 bytes, got " +
                                std::to_string(signature.size()));
    }

    // Verify with appropriate key type
    bool verified = false;

    if (keyFile) {
        // Verify with full keypair
        std::string seedStr = readKeyFile(*keyFile);
        auto kp = nkeys::FromSeed(seedStr);
        verified = kp->verify(content, signature);
    } else {
        // Verify with public key only
        std::string pubStr = readKeyFile(*pubFile);
        auto pub = nkeys::FromPublicKey(pubStr);
        verified = pub->verify(content, signature);
    }

    if (verified) {
        std::cout << "Verified OK\n";
    } else {
        throw std::runtime_error("Verification failed");
    }
}

void printUsage() {
    std::cerr << R"(Usage: nk++ [options]

Options:
    -v, --v               Show version
    --gen <type>          Generate key for [user|account|server|cluster|operator|curve]
    --sign <file>         Sign <file> with --inkey <keyfile>
    --verify <file>       Verify <file> with --inkey <keyfile> or --pubin <public> and --sigfile <file>
    --inkey <file>        Input key file (seed/private key)
    --pubin <file>        Public key file
    --sigfile <file>      Signature file
    --pubout              Output public key

Examples:
    # Generate a new user key pair
    nk++ --gen user

    # Generate a curve (x25519) encryption key pair
    nk++ --gen curve --pubout

    # Generate a user key and save both seed and public key
    nk++ --gen user --pubout > keys.txt

    # Extract public key from seed file
    nk++ --inkey user.seed --pubout > user.pub

    # Sign a file
    nk++ --sign data.txt --inkey user.seed > data.sig

    # Verify signature using seed file
    nk++ --verify data.txt --sigfile data.sig --inkey user.seed

    # Verify signature using public key only
    nk++ --verify data.txt --sigfile data.sig --pubin user.pub
)";
}

int main(int argc, char* argv[]) {
    try {
        auto args = cmd_args::parse(argc, argv);

        // Version
        if (args.get("v")) {
            std::cout << "nk++ version 0.1.0\n";
            return 0;
        }

        // Generate keys
        if (args.get("gen")) {
            handleGenerate(args);
            return 0;
        }

        // Sign
        if (args.get("sign")) {
            handleSign(args);
            return 0;
        }

        // Verify
        if (args.get("verify")) {
            handleVerify(args);
            return 0;
        }

        // Extract public key
        if (args.get("inkey") && args.get("pubout")) {
            handlePubout(args);
            return 0;
        }

        // No valid command
        printUsage();
        return 1;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
