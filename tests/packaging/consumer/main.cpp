// Exercises one call from each API family so the gate proves linkage and
// basic behavior, not just that headers were found.
#include <nkeys/nkeys.hpp>
#include <cstdio>
#include <vector>

int main() {
    auto user = nkeys::CreatePair(nkeys::Prefix::User);
    std::vector<std::uint8_t> msg = {'p', 'k', 'g'};
    if (!user->verify(msg, user->sign(msg))) return 1;
    if (!nkeys::IsValidPublicUserKey(user->publicString())) return 1;

    auto a = nkeys::CreateCurveKeys();
    auto b = nkeys::CreateCurveKeys();
    if (b->open(a->seal(msg, b->publicString()), a->publicString()) != msg) return 1;

    std::puts("CONSUMER-OK");
    return 0;
}
