// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#define __TRANSMISSION__

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include "libtransmission/btpk-utils.h"
#include "libtransmission/crypto-utils.h" // tr_ed25519_keypair_generate

using namespace std::literals;

namespace libtransmission
{

// ---------------------------------------------------------------------------
// Internal helpers

namespace
{

static constexpr auto HexChars = "0123456789abcdef"sv;

// Encode raw bytes to lowercase hex.
std::string bytes_to_hex(uint8_t const* data, size_t len)
{
    std::string out;
    out.reserve(len * 2U);
    for (size_t i = 0U; i < len; ++i)
    {
        out += HexChars[data[i] >> 4U];
        out += HexChars[data[i] & 0xFU];
    }
    return out;
}

// Decode a hex string into bytes. Returns false if invalid.
bool hex_to_bytes(std::string_view hex, uint8_t* out, size_t expected_len)
{
    if (hex.size() != expected_len * 2U)
    {
        return false;
    }
    auto nibble = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0U; i < expected_len; ++i)
    {
        int const hi = nibble(hex[i * 2U]);
        int const lo = nibble(hex[i * 2U + 1U]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Base64 alphabet (standard, not URL-safe).
static constexpr auto Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"sv;

// Encode bytes to base64.
std::string base64_encode(uint8_t const* data, size_t len)
{
    std::string out;
    out.reserve(((len + 2U) / 3U) * 4U);
    for (size_t i = 0U; i < len; i += 3U)
    {
        uint32_t const b0 = data[i];
        uint32_t const b1 = (i + 1U < len) ? data[i + 1U] : 0U;
        uint32_t const b2 = (i + 2U < len) ? data[i + 2U] : 0U;
        uint32_t const triple = (b0 << 16U) | (b1 << 8U) | b2;
        out += Base64Chars[(triple >> 18U) & 0x3FU];
        out += Base64Chars[(triple >> 12U) & 0x3FU];
        out += (i + 1U < len) ? Base64Chars[(triple >> 6U) & 0x3FU] : '=';
        out += (i + 2U < len) ? Base64Chars[(triple >> 0U) & 0x3FU] : '=';
    }
    return out;
}

// Decode base64 (ignores whitespace). Returns decoded bytes or empty on error.
std::vector<uint8_t> base64_decode(std::string_view input)
{
    // Build reverse lookup table.
    std::array<int8_t, 256> rev{};
    rev.fill(-1);
    for (size_t i = 0U; i < Base64Chars.size(); ++i)
    {
        rev[static_cast<uint8_t>(Base64Chars[i])] = static_cast<int8_t>(i);
    }
    rev[static_cast<uint8_t>('=')] = 0; // padding

    std::vector<uint8_t> out;
    out.reserve((input.size() / 4U) * 3U);

    uint32_t buf = 0U;
    int bits = 0;
    int padding = 0;

    for (char const c : input)
    {
        if (std::isspace(static_cast<unsigned char>(c)))
        {
            continue;
        }
        if (c == '=')
        {
            ++padding;
            buf = (buf << 6U);
            bits += 6;
        }
        else
        {
            int8_t const val = rev[static_cast<uint8_t>(c)];
            if (val < 0)
            {
                return {}; // invalid char
            }
            buf = (buf << 6U) | static_cast<uint32_t>(val);
            bits += 6;
        }
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFFU));
        }
    }

    // Remove bytes that were padding-induced
    if (padding > 0 && !out.empty())
    {
        out.resize(out.size() - static_cast<size_t>(padding));
    }

    return out;
}

static constexpr auto PemHeader = "-----BEGIN BTPK PRIVATE KEY-----"sv;
static constexpr auto PemFooter = "-----END BTPK PRIVATE KEY-----"sv;
static constexpr size_t PemLineLen = 64U;

} // namespace

// ---------------------------------------------------------------------------
// Key generation

void tr_btpk_key_generate(BtpkPublicKey& key_public_out, BtpkPrivateKey& key_private_out)
{
    // tr_ed25519_keypair_generate writes:
    //   key_public_out[0..31]   = public key
    //   key_private_out[0..63]  = nightcracker private key
    //   key_private_out[64..95] = copy of public key (appended by our impl)
    tr_ed25519_keypair_generate(key_public_out.data(), key_private_out.data());
}

// ---------------------------------------------------------------------------
// Hex

std::string tr_btpk_public_key_to_hex(BtpkPublicKey const& key)
{
    return bytes_to_hex(key.data(), key.size());
}

std::string tr_btpk_private_key_to_hex(BtpkPrivateKey const& key)
{
    return bytes_to_hex(key.data(), key.size());
}

std::optional<BtpkPublicKey> tr_btpk_public_key_from_hex(std::string_view hex)
{
    BtpkPublicKey key{};
    if (!hex_to_bytes(hex, key.data(), key.size()))
    {
        return std::nullopt;
    }
    return key;
}

std::optional<BtpkPrivateKey> tr_btpk_private_key_from_hex(std::string_view hex)
{
    BtpkPrivateKey key{};
    if (!hex_to_bytes(hex, key.data(), key.size()))
    {
        return std::nullopt;
    }
    return key;
}

// ---------------------------------------------------------------------------
// PEM

std::string tr_btpk_private_key_to_pem(BtpkPrivateKey const& key)
{
    auto const b64 = base64_encode(key.data(), key.size());
    std::string out;
    out.reserve(PemHeader.size() + 1U + b64.size() + b64.size() / PemLineLen + 2U + PemFooter.size() + 1U);
    out += PemHeader;
    out += '\n';
    for (size_t i = 0U; i < b64.size(); i += PemLineLen)
    {
        out += b64.substr(i, PemLineLen);
        out += '\n';
    }
    out += PemFooter;
    out += '\n';
    return out;
}

std::optional<BtpkPrivateKey> tr_btpk_private_key_from_pem(std::string_view pem)
{
    // Strip leading/trailing whitespace
    while (!pem.empty() && std::isspace(static_cast<unsigned char>(pem.front())))
    {
        pem.remove_prefix(1U);
    }
    while (!pem.empty() && std::isspace(static_cast<unsigned char>(pem.back())))
    {
        pem.remove_suffix(1U);
    }

    // Find header and footer
    auto const hpos = pem.find(PemHeader);
    auto const fpos = pem.find(PemFooter);
    if (hpos == std::string_view::npos || fpos == std::string_view::npos || fpos <= hpos)
    {
        return std::nullopt;
    }

    // Extract the body between header and footer
    auto body = pem.substr(hpos + PemHeader.size(), fpos - hpos - PemHeader.size());

    // Decode base64 (base64_decode ignores whitespace including newlines)
    auto const decoded = base64_decode(body);
    if (decoded.size() != 96U)
    {
        return std::nullopt;
    }

    BtpkPrivateKey key{};
    std::copy_n(decoded.data(), 96U, key.data());
    return key;
}

// ---------------------------------------------------------------------------
// Fingerprint

std::string tr_btpk_fingerprint(BtpkPublicKey const& key)
{
    // First 8 bytes as colon-separated uppercase hex pairs: "A3:F8:C2:01:9E:44:BB:20"
    static constexpr auto UpperHex = "0123456789ABCDEF"sv;
    std::string out;
    out.reserve(23U); // 8 * 2 + 7 colons
    for (size_t i = 0U; i < 8U; ++i)
    {
        if (i > 0U)
        {
            out += ':';
        }
        out += UpperHex[key[i] >> 4U];
        out += UpperHex[key[i] & 0xFU];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Secure erasure

void tr_btpk_zero_key(BtpkPrivateKey& key)
{
    // volatile pointer prevents the compiler from optimising this away.
    // On platforms where explicit_bzero is available it would be preferable,
    // but this is portable and sufficient for our threat model (key is
    // short-lived in memory; we are not defending against cold-boot attacks).
    auto* volatile p = reinterpret_cast<uint8_t volatile*>(key.data());
    for (size_t i = 0U; i < key.size(); ++i)
    {
        p[i] = 0U;
    }
}

} // namespace libtransmission
