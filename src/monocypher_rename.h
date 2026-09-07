#pragma once

// Force-included (-include / /FI) into every TU of the nkeys library target.
// Renames ALL of vendored Monocypher's exported symbols to an nkeys-owned
// prefix so libnkeys never collides with — or is silently serviced by — a
// Monocypher the consumer links themselves (measured: with an unprefixed
// archive, link order decided WHICH copy of the crypto ran).
//
// The list is the measured export set of monocypher.o + monocypher-ed25519.o:
// every defined external symbol, DATA INCLUDED (crypto_argon2_no_extras is a
// const struct, not a function — the first draft harvested only 'T' symbols
// and the coexistence link still collided on it). The packaging gate fails
// if libnkeys ever exports an unprefixed crypto_* again — e.g. after a
// Monocypher upgrade adds one. Regenerate with:
//   nm -gU monocypher*.o | awk 'NF==3{sub(/^_/,"",$3); print $3}' | sort -u

#define crypto_aead_init_djb nkeys__crypto_aead_init_djb
#define crypto_aead_init_ietf nkeys__crypto_aead_init_ietf
#define crypto_aead_init_x nkeys__crypto_aead_init_x
#define crypto_aead_lock nkeys__crypto_aead_lock
#define crypto_aead_read nkeys__crypto_aead_read
#define crypto_aead_unlock nkeys__crypto_aead_unlock
#define crypto_aead_write nkeys__crypto_aead_write
#define crypto_argon2 nkeys__crypto_argon2
#define crypto_argon2_no_extras nkeys__crypto_argon2_no_extras
#define crypto_blake2b nkeys__crypto_blake2b
#define crypto_blake2b_final nkeys__crypto_blake2b_final
#define crypto_blake2b_init nkeys__crypto_blake2b_init
#define crypto_blake2b_keyed nkeys__crypto_blake2b_keyed
#define crypto_blake2b_keyed_init nkeys__crypto_blake2b_keyed_init
#define crypto_blake2b_update nkeys__crypto_blake2b_update
#define crypto_chacha20_djb nkeys__crypto_chacha20_djb
#define crypto_chacha20_h nkeys__crypto_chacha20_h
#define crypto_chacha20_ietf nkeys__crypto_chacha20_ietf
#define crypto_chacha20_x nkeys__crypto_chacha20_x
#define crypto_ed25519_check nkeys__crypto_ed25519_check
#define crypto_ed25519_key_pair nkeys__crypto_ed25519_key_pair
#define crypto_ed25519_ph_check nkeys__crypto_ed25519_ph_check
#define crypto_ed25519_ph_sign nkeys__crypto_ed25519_ph_sign
#define crypto_ed25519_sign nkeys__crypto_ed25519_sign
#define crypto_eddsa_check nkeys__crypto_eddsa_check
#define crypto_eddsa_check_equation nkeys__crypto_eddsa_check_equation
#define crypto_eddsa_key_pair nkeys__crypto_eddsa_key_pair
#define crypto_eddsa_mul_add nkeys__crypto_eddsa_mul_add
#define crypto_eddsa_reduce nkeys__crypto_eddsa_reduce
#define crypto_eddsa_scalarbase nkeys__crypto_eddsa_scalarbase
#define crypto_eddsa_sign nkeys__crypto_eddsa_sign
#define crypto_eddsa_to_x25519 nkeys__crypto_eddsa_to_x25519
#define crypto_eddsa_trim_scalar nkeys__crypto_eddsa_trim_scalar
#define crypto_elligator_key_pair nkeys__crypto_elligator_key_pair
#define crypto_elligator_map nkeys__crypto_elligator_map
#define crypto_elligator_rev nkeys__crypto_elligator_rev
#define crypto_poly1305 nkeys__crypto_poly1305
#define crypto_poly1305_final nkeys__crypto_poly1305_final
#define crypto_poly1305_init nkeys__crypto_poly1305_init
#define crypto_poly1305_update nkeys__crypto_poly1305_update
#define crypto_sha512 nkeys__crypto_sha512
#define crypto_sha512_final nkeys__crypto_sha512_final
#define crypto_sha512_hkdf nkeys__crypto_sha512_hkdf
#define crypto_sha512_hkdf_expand nkeys__crypto_sha512_hkdf_expand
#define crypto_sha512_hmac nkeys__crypto_sha512_hmac
#define crypto_sha512_hmac_final nkeys__crypto_sha512_hmac_final
#define crypto_sha512_hmac_init nkeys__crypto_sha512_hmac_init
#define crypto_sha512_hmac_update nkeys__crypto_sha512_hmac_update
#define crypto_sha512_init nkeys__crypto_sha512_init
#define crypto_sha512_update nkeys__crypto_sha512_update
#define crypto_verify16 nkeys__crypto_verify16
#define crypto_verify32 nkeys__crypto_verify32
#define crypto_verify64 nkeys__crypto_verify64
#define crypto_wipe nkeys__crypto_wipe
#define crypto_x25519 nkeys__crypto_x25519
#define crypto_x25519_dirty_fast nkeys__crypto_x25519_dirty_fast
#define crypto_x25519_dirty_small nkeys__crypto_x25519_dirty_small
#define crypto_x25519_inverse nkeys__crypto_x25519_inverse
#define crypto_x25519_public_key nkeys__crypto_x25519_public_key
#define crypto_x25519_to_eddsa nkeys__crypto_x25519_to_eddsa
