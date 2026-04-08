// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// ---------------------------------------------------------------------------
// BEP 46 btpk: publishing utilities
//
// Key layout (matches crypto-utils-ed25519.cc convention):
//   BtpkPublicKey  : 32 bytes  — raw ed25519 public key
//   BtpkPrivateKey : 96 bytes  — [nightcracker_expanded_64 | public_key_32]
//
// The private key is only needed at publish time. It should never be written
// to disk by the application without explicit user consent. After signing,
// callers should call tr_btpk_zero_key() to erase it from memory.
//
// Export format: a custom PEM-like block using the header
//   "-----BEGIN BTPK PRIVATE KEY-----"
// which is deliberately distinct from standard PKCS#8 / OpenSSH formats to
// prevent confusion. The body is standard base64 of the 96 raw bytes.
// ---------------------------------------------------------------------------

namespace libtransmission
{

using BtpkPublicKey = std::array<uint8_t, 32>;
using BtpkPrivateKey = std::array<uint8_t, 96>;

// ---------------------------------------------------------------------------
// Key generation

// Generate a fresh ed25519 keypair.
// Both output arrays are filled; key_private also contains the public key
// appended at [64..95] for use with tr_ed25519_sign().
void tr_btpk_key_generate(BtpkPublicKey& key_public_out, BtpkPrivateKey& key_private_out);

// ---------------------------------------------------------------------------
// Hex encoding / decoding

// Encode public key as 64 lowercase hex chars (no separator, no newline).
[[nodiscard]] std::string tr_btpk_public_key_to_hex(BtpkPublicKey const& key);

// Encode private key as 192 lowercase hex chars.
[[nodiscard]] std::string tr_btpk_private_key_to_hex(BtpkPrivateKey const& key);

// Decode a 64-char hex string into a public key.
// Returns nullopt if the string is not exactly 64 valid hex chars.
[[nodiscard]] std::optional<BtpkPublicKey> tr_btpk_public_key_from_hex(std::string_view hex);

// Decode a 192-char hex string into a private key.
// Returns nullopt if the string is not exactly 192 valid hex chars.
[[nodiscard]] std::optional<BtpkPrivateKey> tr_btpk_private_key_from_hex(std::string_view hex);

// ---------------------------------------------------------------------------
// PEM encoding / decoding
// Format: "-----BEGIN BTPK PRIVATE KEY-----\n<base64>\n-----END BTPK PRIVATE KEY-----\n"
// Line length: 64 chars per base64 line (standard PEM convention).

[[nodiscard]] std::string tr_btpk_private_key_to_pem(BtpkPrivateKey const& key);

// Parse a PEM block. Tolerates leading/trailing whitespace and both LF and CRLF.
// Returns nullopt if the block is missing, malformed, or wrong length after decode.
[[nodiscard]] std::optional<BtpkPrivateKey> tr_btpk_private_key_from_pem(std::string_view pem);

// ---------------------------------------------------------------------------
// Fingerprint
// Returns a short, human-readable identifier for the public key:
// the first 8 bytes encoded as 16 uppercase hex chars, separated by colons
// in pairs — e.g. "A3:F8:C2:01:9E:44:BB:20". Suitable for display in the UI.

[[nodiscard]] std::string tr_btpk_fingerprint(BtpkPublicKey const& key);

// ---------------------------------------------------------------------------
// Secure erasure
// Overwrites key material with zeros using a compiler-barrier-safe mechanism.
// Call this immediately after signing is complete.

void tr_btpk_zero_key(BtpkPrivateKey& key);

// Encode a 20-byte infohash as the BEP 46 DHT value: d1:ih20:<bytes>e
std::string tr_btpk_encode_v(std::array<uint8_t, 20> const& infohash);

} // namespace libtransmission

#ifdef __TRANSMISSION__
// Internal: sign a BEP 46 value and push it to the DHT.
// Only callable from libtransmission (requires tr-dht.h).
class tr_dht;
namespace libtransmission
{
bool tr_btpk_sign_and_put(::tr_dht& dht,
                          uint8_t const* v,
                          int v_len,
                          BtpkPublicKey const& pubKey,
                          BtpkPrivateKey const& privKey,
                          std::string_view salt,
                          int64_t seq);
} // namespace libtransmission
#endif
