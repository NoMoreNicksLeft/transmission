// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// BEP 44 ed25519 primitives using the vendored nightcracker/ed25519 library.
// Compiled unconditionally regardless of the active crypto backend.
//
// Key layout convention used by tr_ed25519_*:
//   key_public  : 32 bytes  — raw ed25519 public key
//   key_private : 64 bytes  — nightcracker private key (SHA-512 of seed),
//                             with the matching public key appended in the
//                             caller's buffer at [32..63] via keypair_generate.
//                             sign() and verify() use separate buffers so
//                             the public key must be available to the caller.
//
// Note: BEP 44 signing uses the public key during sign() because the RFC 8032
// construction requires it.  The caller must retain both keys.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "ed25519.h"

#include "libtransmission/crypto-utils.h"

// key_public : 32 bytes out
// key_private: 64 bytes out (nightcracker format: SHA-512 of seed)
bool tr_ed25519_keypair_generate(uint8_t* key_public, uint8_t* key_private)
{
    uint8_t seed[32];
    tr_rand_buffer(seed, 32); // infallible on all supported platforms
    ed25519_create_keypair(key_public, key_private, seed);
    // Append public key to key_private[64..95] so sign() can find it
    memcpy(key_private + 64, key_public, 32);
    return true;
}

// sig        : 64 bytes out
// msg        : message bytes
// key_private: 64-byte nightcracker private key
// key_public : 32-byte public key (required by nightcracker's sign function)
//
// We combine both into a single 96-byte key_private argument by convention:
// callers generated with tr_ed25519_keypair_generate receive separate buffers,
// so we accept them the same way the BEP 44 spec describes: separate args.
// The function signature in crypto-utils.h takes only key_private — we
// reconstruct key_public from the second 32 bytes IF the caller stored it
// there, but the safer contract is: sign takes a combined 96-byte private key.
//
// REVISED CONTRACT (matches crypto-utils.h declaration):
//   key_private is 96 bytes: [nightcracker_64 | public_key_32]
//   tr_ed25519_keypair_generate writes this layout when given a 96-byte buffer.
bool tr_ed25519_sign(uint8_t* sig, uint8_t const* msg, size_t msg_len, uint8_t const* key_private)
{
    // key_private[0..63]  = nightcracker private key
    // key_private[64..95] = public key
    ed25519_sign(sig, msg, msg_len, key_private + 64, key_private);
    return true;
}

bool tr_ed25519_verify(uint8_t const* sig, uint8_t const* msg, size_t msg_len, uint8_t const* key_public)
{
    return ed25519_verify(sig, msg, msg_len, key_public) == 1;
}
