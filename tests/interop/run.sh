#!/usr/bin/env sh
# run.sh — the live Go↔C++ interop matrix (the gate CI runs; also runnable
# locally). Every check pairs the C++ library against the reference Go nkeys
# through two mode-for-mode CLIs: cpp_driver (built by CMake with tests) and
# the Go probe in this directory.
#
#   usage: tests/interop/run.sh <cmake-build-dir>
#
# Eight checks:
#   1. signing keys: each side generates, the other derives the same public key
#   2. encoded private key ('P…') parity on a shared seed
#   3. signatures verify across: C++ sign → Go verify, Go sign → C++ verify
#   4. curve keys: each side generates, the other derives the same public key
#   5. fixed-nonce seal is BYTE-IDENTICAL both ways (47-byte and empty message)
#   6. live seal/open both directions with random nonces
#   7. Go→C++ open across keystream block boundaries (33/64/1000 bytes)
#   8. decorated creds: jwt/nkey/usernkey parity on the fixture file
#
# POSIX sh — CI runs it on ubuntu and macos runners.
set -eu

BUILD_DIR=${1:?usage: run.sh <cmake-build-dir>}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
CPP="$BUILD_DIR/cpp_driver"
[ -x "$CPP" ] || CPP="$BUILD_DIR/tests/interop/cpp_driver"
[ -x "$CPP" ] || { echo "cpp_driver not found under $BUILD_DIR (configure with BUILD_TESTING=ON)" >&2; exit 1; }

echo "interop: building Go probe"
( cd "$HERE/probe" && go build -o "$HERE/probe/probe" . )
GO="$HERE/probe/probe"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
check() { pass=$((pass+1)); echo "  ok $pass: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
line1() { printf '%s\n' "$1" | head -n 1; }
line2() { printf '%s\n' "$1" | sed -n 2p; }

# 1 ── signing keys: cross derivation
CG=$("$CPP" gen user); CSEED=$(line1 "$CG"); CPUB=$(line2 "$CG")
[ "$("$GO" pub "$CSEED")" = "$CPUB" ] || fail "Go derived a different public key from a C++ user seed"
GG=$("$GO" gen user); GSEED=$(line1 "$GG"); GPUB=$(line2 "$GG")
[ "$("$CPP" pub "$GSEED")" = "$GPUB" ] || fail "C++ derived a different public key from a Go user seed"
check "signing keys derive identically both ways"

# 2 ── encoded private key parity
[ "$("$CPP" priv "$GSEED")" = "$("$GO" priv "$GSEED")" ] || fail "privateString differs from Go's PrivateKey"
check "encoded private key ('P…') identical"

# 3 ── signatures verify across implementations
printf 'interop matrix payload' > "$TMP/msg"
"$GO" verify "$CPUB" "$TMP/msg" "$("$CPP" sign "$CSEED" "$TMP/msg")" >/dev/null \
    || fail "Go rejected a C++ signature"
"$CPP" verify "$GPUB" "$TMP/msg" "$("$GO" sign "$GSEED" "$TMP/msg")" >/dev/null \
    || fail "C++ rejected a Go signature"
check "signatures verify across: C++→Go and Go→C++"

# 4 ── curve keys: cross derivation
CXG=$("$CPP" xgen); CXSEED=$(line1 "$CXG"); CXPUB=$(line2 "$CXG")
[ "$("$GO" xpub "$CXSEED")" = "$CXPUB" ] || fail "Go derived a different curve public key from a C++ seed"
GXG=$("$GO" xgen); GXSEED=$(line1 "$GXG"); GXPUB=$(line2 "$GXG")
[ "$("$CPP" xpub "$GXSEED")" = "$GXPUB" ] || fail "C++ derived a different curve public key from a Go seed"
check "curve keys derive identically both ways"

# 5 ── fixed-nonce seal is byte-identical (the strongest cipher check: a
# self-consistent wrong cipher passes round-trips but cannot pass this)
NONCE=000102030405060708090a0b0c0d0e0f1011121314151617
MSG=$(b64 'this is a test message for nkeys xkeys interop')
[ "$("$CPP" xseal "$CXSEED" "$GXPUB" "$NONCE" "$MSG")" = "$("$GO" xseal "$CXSEED" "$GXPUB" "$NONCE" "$MSG")" ] \
    || fail "fixed-nonce ciphertexts differ (47-byte message)"
[ "$("$CPP" xseal "$CXSEED" "$GXPUB" "$NONCE" "")" = "$("$GO" xseal "$CXSEED" "$GXPUB" "$NONCE" "")" ] \
    || fail "fixed-nonce ciphertexts differ (empty message)"
check "fixed-nonce seal byte-identical (47-byte + empty message)"

# 6 ── live seal/open, random nonces, both directions
CT=$("$CPP" xseal "$CXSEED" "$GXPUB" rand "$MSG")
[ "$("$GO" xopen "$GXSEED" "$CXPUB" "$CT")" = "$MSG" ] || fail "Go could not open a C++ seal"
CT=$("$GO" xseal "$GXSEED" "$CXPUB" rand "$MSG")
[ "$("$CPP" xopen "$CXSEED" "$GXPUB" "$CT")" = "$MSG" ] || fail "C++ could not open a Go seal"
check "seal/open across: C++→Go and Go→C++"

# 7 ── sizes across keystream block boundaries (block 0 hands out 32 message
# bytes; later blocks 64 — 33 and 64 straddle the seams)
for n in 33 64 1000; do
    M=$(head -c "$n" /dev/urandom | base64 | tr -d '\n')
    CT=$("$GO" xseal "$GXSEED" "$CXPUB" rand "$M")
    [ "$("$CPP" xopen "$CXSEED" "$GXPUB" "$CT")" = "$M" ] || fail "size $n: C++ decrypted wrong bytes"
done
check "Go→C++ open across block boundaries (33/64/1000 bytes)"

# 8 ── decorated creds parity on the fixture
CREDS="$REPO/tests/fixtures/user.creds"
[ "$("$CPP" jwt "$CREDS")" = "$("$GO" jwt "$CREDS")" ] || fail "ParseDecoratedJWT differs"
[ "$("$CPP" nkey "$CREDS")" = "$("$GO" nkey "$CREDS")" ] || fail "ParseDecoratedNKey differs"
[ "$("$CPP" usernkey "$CREDS")" = "$("$GO" usernkey "$CREDS")" ] || fail "ParseDecoratedUserNKey differs"
check "decorated creds parse identically (jwt/nkey/usernkey)"

echo
echo "INTEROP PASS ($pass checks)"
