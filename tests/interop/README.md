# Go interop probe

A tiny Go CLI over the reference [nats-io/nkeys](https://github.com/nats-io/nkeys)
library. Every compatibility claim in this repo is *measured* against it —
golden vectors in the unit tests were produced by these commands, and live
bidirectional checks (sign/verify, seal/open) run through it during review.

```sh
cd probe && go build -o probe .
```

`cpp_driver.cpp` (built by CMake alongside the tests) is the C++ mirror of the
probe, and `run.sh <build-dir>` runs the full live matrix between them — cross
key derivation, sign/verify and seal/open in both directions, byte-identical
fixed-nonce ciphertexts, and decorated-creds parity. CI runs it on every push.

| mode | args | prints |
|---|---|---|
| `pub` | seed | public key |
| `priv` | seed | encoded private key (`P…`) |
| `sign` | seed file | base64url signature |
| `verify` | pub file b64sig | `GO-VERIFY-OK` or exits 1 |
| `xgen` | — | fresh curve seed + public key |
| `xpub` | curve seed | curve public key |
| `xseal` | seed recipientPub nonceHex\|`rand` msgB64 | b64 ciphertext |
| `xopen` | seed senderPub cipherB64 | b64 plaintext |
| `jwt` / `nkey` / `usernkey` | creds file | JWT / parsed key's public key |

To probe an unreleased Go change, add a replace directive:

```sh
go mod edit -replace github.com/nats-io/nkeys=/path/to/nats-io/nkeys
```

Example — regenerate the fixed-nonce seal golden used by `XKeysSealTest`:

```sh
./probe xseal "$SEED_A" "$PUB_B" 000102030405060708090a0b0c0d0e0f1011121314151617 \
  "$(printf 'this is a test message for nkeys xkeys interop' | base64)"
```
