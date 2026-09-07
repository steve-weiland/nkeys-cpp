# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

nkeys-cpp is a C++20 port of the Go [NATS nkeys](https://github.com/nats-io/nkeys)
cryptographic key system: Ed25519 key generation, signing, and verification,
x25519 XKeys with NaCl-box seal/open, and decorated-creds parsing, all with
NATS's Base32 + CRC-16 key serialization. Wire/format compatibility with the Go
implementation is the defining requirement — verified live in both directions
(sign/verify and seal/open each way, byte-identical fixed-nonce ciphertexts,
plus seed→pubkey golden vectors).

Monocypher is vendored for the crypto. **It must be the `monocypher-ed25519`
unit** (SHA-512 Ed25519, RFC 8032); Monocypher's default EdDSA uses BLAKE2b and
is NOT interoperable with NATS.

## Conventions (violations are review-rejectable)

- **Compatibility is measured, never assumed.** Any behavioral question about
  encoding/decoding is settled by running the Go library, not by recalling it.
  Precedent: the decoder rejects lowercase and '=' because Go does, but ACCEPTS
  non-canonical trailing slack bits because Go does — a "stricter is safer"
  guess would have rejected credentials the reference implementation honors.
- **No silent wrong keys.** `FromSeed` only accepts real 'S…' seeds
  (`Decoded.isSeed` is the load-bearing field); `FromRawSeed` validates its
  prefix at the call site; using a wiped pair throws.
- **verify() is `noexcept` and returns false for malformed signatures** —
  signature bytes come off the wire; throwing on attacker-controlled input is
  an exception path handed to the attacker. The length check is also the
  memory-safety guard in front of Monocypher.
- **Key-material hygiene**: destruction wipes automatically; `wipe()` ends the
  material's lifetime early and disables the pair. `SecureGuard` covers stack
  temporaries and exception paths in creation/loading flows — anything that
  copies secret bytes into a local must guard or wipe that local.
- **Docs state measured truth only** — no security claims the code doesn't
  implement (history: "no swap", "constant-time CRC", and "works on Windows"
  were all once claimed and all false).

## Build & Test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `NKEYS_ENABLE_ASAN`, `NKEYS_ENABLE_UBSAN`, `NKEYS_ENABLE_HARDENING`
(default ON), `NKEYS_WARNINGS_AS_ERRORS`, `NKEYS_USE_SYSTEM_GTEST` (default ON).
Exceptions are required; there is no no-exceptions build.

**Gates before claiming done** (CI runs all of these on every push —
`.github/workflows/ci.yml` — but run them locally first; CI is the backstop,
not the first execution): full ctest on macOS AND a Linux container run —
the first-ever Linux build found two shipped breakages (missing `<algorithm>`,
unlinked gmock), so macOS-only green proves little:

```bash
docker run --rm -v "$PWD":/src:ro alpine:3.20 sh -c \
  'apk add -q build-base cmake linux-headers && cp -r /src /w && cd /w && \
   rm -rf build* cmake-build-* && cmake -S . -B b >/dev/null && \
   cmake --build b -j >/dev/null && ctest --test-dir b'
```

For codec/interop changes, also run the live Go cross-check:
`tests/interop/run.sh <build-dir>` — cross key derivation, sign/verify and
seal/open in both directions, byte-identical fixed-nonce ciphertexts, and
decorated-creds parity, driven through `cpp_driver` and the Go probe in
`tests/interop/probe/` (pinned to upstream nkeys; add a `replace` directive to
probe a local checkout).

Out-of-tree builds are first-class: tests locate fixtures via the
`NKEYS_TEST_FIXTURES_DIR` compile definition, not the CWD (a CWD-relative
lookup shipped and broke the first `/tmp` build). Sanitizer configs refuse the
system GTest — an uninstrumented GTest under ASAN reports a bogus
container-overflow before any test runs.

## Working discipline

- Red-first: a bug fix lands with the test that failed against the old code
  (the failure message should show the bad behavior, e.g. the wrongly-minted
  identity). Sabotage-verify new tests: break the code, watch the right
  assertion fail, restore — and verify the sabotage applied and the restore
  took (grep both ways).
- Minimal change per commit; every commit reviewed by a human first.

## Architecture

- `include/nkeys/nkeys.hpp` — public API: `KeyPair`/`Public` interfaces,
  factories (`Create*`, `FromSeed`, `FromRawSeed`, `FromPublicKey`), `codec`
  namespace. `Decoded{prefix, payload, isSeed}` — for seeds, `prefix` is the
  key TYPE and `isSeed` distinguishes it from a same-type public key.
- `src/nkeys.cpp` — impls, Base32 (RFC 4648 alphabet, no padding, Go-measured
  strictness), CRC-16/XMODEM appended little-endian, seed 2-byte prefix
  packing (bit-identical to Go's EncodeSeed), platform RNG. Also the vendored
  Salsa20 core (`namespace salsa`) — Monocypher is ChaCha-family and cannot do
  XSalsa20, so NaCl-box seal/open composes Monocypher's X25519 + Poly1305 with
  this core; it is validated byte-for-byte against Go ciphertexts, and only the
  Go-golden tests can catch a self-consistent wrong cipher (a broken core still
  round-trips with itself).
- `CurveKeyPair` is a separate type from `KeyPair` (Go dispatches at runtime;
  we use the type system): `FromSeed` refuses 'SX…', `FromCurveSeed` refuses
  signing seeds, `isPublicPrefix` deliberately EXCLUDES Curve so an x25519 key
  can never reach Ed25519 verify — while codec seed paths accept Curve as
  seedable. Curve `privateString()` encodes the 32-byte seed (Go quirk).
- `secureRandomBytes()`: `arc4random_buf` (macOS/BSD); `getrandom(2)` on Linux
  with `/dev/urandom` fallback (feof checked BEFORE fclose); anything else
  throws — there is deliberately NO `std::random_device` fallback (it is not
  guaranteed to be a CSPRNG). Windows backend not yet implemented: key
  generation throws there.
- `src/tools/nk-main.cpp` — `nk++` CLI (`--gen curve` supported; no vanity
  search, unlike Go's nk); signatures are base64 RawURL, matching Go's tool.
  Key files may contain comments; first valid 56/58-char key wins.

## Known gaps

Feature parity with the Go library is complete (XKeys, decorated creds,
`privateString`, `CreatePair`, validators — all landed 2026-09, Go-probe
gated), and CI automates every gate. Remaining are usability gaps, not parity
gaps: CMake package config (`find_package(nkeys)`), `BUILD_SHARED_LIBS`, a
typed error taxonomy (everything throws
`std::invalid_argument`/`logic_error` today), and the Windows RNG backend.
Port behavior from the Go source, verified by the probe, for anything that
touches the wire.

## When review catches you violating a convention

Fix the code, then encode the violated rule into this file so the class of
error dies, not the instance.
