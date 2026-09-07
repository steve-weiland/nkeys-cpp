#!/usr/bin/env sh
# test.sh — the packaging gate (CI runs it; also runnable locally).
# Proves the library is consumable every way the README advertises:
#
#   1. install → find_package(nkeys) consumer builds, links nkeys::nkeys, runs
#   2. same, with BUILD_SHARED_LIBS=ON (and the consumer runs against the .so)
#   3. pkg-config: compile the consumer with `pkg-config --cflags --libs nkeys`
#   4. add_subdirectory embed: nkeys::nkeys alias resolves, and none of the
#      top-level-only targets (tests, nk++) leak into the parent project
#
# usage: tests/packaging/test.sh   (from anywhere; repo root is derived)
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
check() { pass=$((pass+1)); echo "  ok $pass: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

# 1 ── static install → find_package consumer
PREFIX="$WORK/prefix-static"
# CMAKE_INSTALL_PREFIX at configure time (not --install --prefix) so the
# generated pkg-config file carries the real prefix.
cmake -S "$REPO" -B "$WORK/b-static" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" -DNKEYS_BUILD_TESTS=OFF >/dev/null
cmake --build "$WORK/b-static" -j >/dev/null
cmake --install "$WORK/b-static" >/dev/null
cmake -S "$HERE/consumer" -B "$WORK/c-static" -DCMAKE_PREFIX_PATH="$PREFIX" >/dev/null
cmake --build "$WORK/c-static" -j >/dev/null
[ "$("$WORK/c-static/consumer")" = "CONSUMER-OK" ] || fail "static find_package consumer did not run"
check "find_package consumer builds and runs (static)"

# 2 ── shared install → find_package consumer
PREFIX="$WORK/prefix-shared"
cmake -S "$REPO" -B "$WORK/b-shared" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON -DNKEYS_BUILD_TESTS=OFF >/dev/null
cmake --build "$WORK/b-shared" -j >/dev/null
cmake --install "$WORK/b-shared" >/dev/null
# one of the two, per platform (ls fails if ANY glob misses, so test separately)
{ ls "$PREFIX"/lib*/libnkeys.so* >/dev/null 2>&1 || ls "$PREFIX"/lib*/libnkeys.*dylib >/dev/null 2>&1; } \
    || fail "BUILD_SHARED_LIBS=ON did not install a shared library"
cmake -S "$HERE/consumer" -B "$WORK/c-shared" -DCMAKE_PREFIX_PATH="$PREFIX" \
      -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON >/dev/null
cmake --build "$WORK/c-shared" -j >/dev/null
[ "$("$WORK/c-shared/consumer")" = "CONSUMER-OK" ] || fail "shared find_package consumer did not run"
check "find_package consumer builds and runs (BUILD_SHARED_LIBS=ON)"

# 3 ── pkg-config consumer (against the static install)
if command -v pkg-config >/dev/null 2>&1; then
    PREFIX="$WORK/prefix-static"
    PC_DIR=$(dirname "$(find "$PREFIX" -name nkeys.pc)")
    # shellcheck disable=SC2046
    PKG_CONFIG_PATH="$PC_DIR" c++ -std=c++20 "$HERE/consumer/main.cpp" \
        $(PKG_CONFIG_PATH="$PC_DIR" pkg-config --cflags --libs nkeys) -o "$WORK/pc-consumer"
    [ "$("$WORK/pc-consumer")" = "CONSUMER-OK" ] || fail "pkg-config consumer did not run"
    check "pkg-config consumer builds and runs"
else
    check "pkg-config not present — skipped (CI covers it)"
fi

# 4 ── add_subdirectory embed: alias works, top-level-only targets stay out
mkdir -p "$WORK/embed"
cp "$HERE/consumer/main.cpp" "$WORK/embed/main.cpp"
cat > "$WORK/embed/CMakeLists.txt" <<EOF
cmake_minimum_required(VERSION 3.21)
project(embed CXX)
add_subdirectory("$REPO" nkeys)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE nkeys::nkeys)
# Embedded builds must not drag in the repo's tests or CLI.
foreach(_t nkeys_test cmd_args_test cpp_driver nk++)
    if (TARGET \${_t})
        message(FATAL_ERROR "top-level-only target \${_t} leaked into the embed")
    endif()
endforeach()
EOF
cmake -S "$WORK/embed" -B "$WORK/embed-b" >/dev/null
cmake --build "$WORK/embed-b" -j >/dev/null
[ "$("$WORK/embed-b/consumer")" = "CONSUMER-OK" ] || fail "embedded consumer did not run"
check "add_subdirectory embed: alias resolves, no test/CLI targets leak"

echo
echo "PACKAGING PASS ($pass checks)"
