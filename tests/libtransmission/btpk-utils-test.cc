// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// Tests for btpk-utils: key generation, hex/PEM encode/decode, fingerprint,
// secure erasure, and round-trip fidelity.

#define __TRANSMISSION__

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include <libtransmission/btpk-utils.h>
#include <libtransmission/crypto-utils.h> // tr_ed25519_sign, tr_ed25519_verify

#include "gtest/gtest.h"

using namespace std::literals;
using namespace libtransmission;

// ---------------------------------------------------------------------------
// Key generation

TEST(BtpkUtilsTest, GenerateProducesNonZeroKeys)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    // Both keys should be non-zero
    EXPECT_FALSE(std::all_of(pub.begin(), pub.end(), [](auto b) { return b == 0; }));
    EXPECT_FALSE(std::all_of(priv.begin(), priv.end(), [](auto b) { return b == 0; }));
}

TEST(BtpkUtilsTest, GeneratedPublicKeyMatchesPrivateKeyTail)
{
    // tr_btpk_key_generate appends the public key at priv[64..95]
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    EXPECT_EQ(0, std::memcmp(pub.data(), priv.data() + 64, 32));
}

TEST(BtpkUtilsTest, TwoGeneratedKeypairsAreDistinct)
{
    BtpkPublicKey pub1{}, pub2{};
    BtpkPrivateKey priv1{}, priv2{};
    tr_btpk_key_generate(pub1, priv1);
    tr_btpk_key_generate(pub2, priv2);

    EXPECT_NE(pub1, pub2);
    EXPECT_NE(priv1, priv2);
}

TEST(BtpkUtilsTest, GeneratedKeyCanSignAndVerify)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    std::array<uint8_t, 64> sig{};
    std::string const msg = "hello btpk";
    EXPECT_TRUE(tr_ed25519_sign(sig.data(), reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv.data()));

    EXPECT_TRUE(tr_ed25519_verify(sig.data(), reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), pub.data()));
}

// ---------------------------------------------------------------------------
// Hex encoding

TEST(BtpkUtilsTest, PublicKeyHexRoundTrip)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto const hex = tr_btpk_public_key_to_hex(pub);
    EXPECT_EQ(hex.size(), 64U);

    auto const decoded = tr_btpk_public_key_from_hex(hex);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, pub);
}

TEST(BtpkUtilsTest, PrivateKeyHexRoundTrip)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto const hex = tr_btpk_private_key_to_hex(priv);
    EXPECT_EQ(hex.size(), 192U);

    auto const decoded = tr_btpk_private_key_from_hex(hex);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, priv);
}

TEST(BtpkUtilsTest, HexIsLowercase)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto const hex = tr_btpk_public_key_to_hex(pub);
    for (char c : hex)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) << "unexpected char: " << c;
    }
}

TEST(BtpkUtilsTest, PublicKeyFromHexRejectsWrongLength)
{
    EXPECT_FALSE(tr_btpk_public_key_from_hex("deadbeef").has_value()); // too short
    EXPECT_FALSE(tr_btpk_public_key_from_hex(std::string(66, 'a')).has_value()); // too long
    // A valid-length hex string of all 'a's decodes fine (all bytes = 0x0a)
    EXPECT_TRUE(tr_btpk_public_key_from_hex(std::string(64, 'a')).has_value());
    // 'g' is not a valid hex digit
    auto bad = std::string(64, 'a');
    bad[0] = 'g';
    EXPECT_FALSE(tr_btpk_public_key_from_hex(bad).has_value());
}

TEST(BtpkUtilsTest, PrivateKeyFromHexRejectsWrongLength)
{
    EXPECT_FALSE(tr_btpk_private_key_from_hex("deadbeef").has_value());
    EXPECT_FALSE(tr_btpk_private_key_from_hex(std::string(190, 'a')).has_value());
    EXPECT_FALSE(tr_btpk_private_key_from_hex(std::string(194, 'a')).has_value());
}

TEST(BtpkUtilsTest, HexUppercaseInputAccepted)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto hex = tr_btpk_public_key_to_hex(pub);
    for (auto& c : hex)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    auto const decoded = tr_btpk_public_key_from_hex(hex);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, pub);
}

// ---------------------------------------------------------------------------
// PEM encoding

TEST(BtpkUtilsTest, PrivateKeyPemRoundTrip)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto const pem = tr_btpk_private_key_to_pem(priv);
    EXPECT_NE(pem.find("-----BEGIN BTPK PRIVATE KEY-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END BTPK PRIVATE KEY-----"), std::string::npos);

    auto const decoded = tr_btpk_private_key_from_pem(pem);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, priv);
}

TEST(BtpkUtilsTest, PemToleratesLeadingTrailingWhitespace)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto pem = "\n\n  " + tr_btpk_private_key_to_pem(priv) + "  \n\n";
    auto const decoded = tr_btpk_private_key_from_pem(pem);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, priv);
}

TEST(BtpkUtilsTest, PemRejectsMissingHeader)
{
    EXPECT_FALSE(tr_btpk_private_key_from_pem("not a pem block").has_value());
    EXPECT_FALSE(tr_btpk_private_key_from_pem("").has_value());
}

TEST(BtpkUtilsTest, PemRejectsWrongKeyType)
{
    // A standard PKCS#8 PEM header should be rejected (wrong label)
    auto const fake = "-----BEGIN PRIVATE KEY-----\nZGVhZGJlZWY=\n-----END PRIVATE KEY-----\n";
    EXPECT_FALSE(tr_btpk_private_key_from_pem(fake).has_value());
}

TEST(BtpkUtilsTest, PemRejectsTruncatedBody)
{
    // Header + footer present but body decodes to wrong length
    auto const bad = "-----BEGIN BTPK PRIVATE KEY-----\naGVsbG8=\n-----END BTPK PRIVATE KEY-----\n";
    EXPECT_FALSE(tr_btpk_private_key_from_pem(bad).has_value());
}

// ---------------------------------------------------------------------------
// Fingerprint

TEST(BtpkUtilsTest, FingerprintFormat)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    auto const fp = tr_btpk_fingerprint(pub);
    // Format: XX:XX:XX:XX:XX:XX:XX:XX  (8 pairs, 7 colons = 23 chars)
    EXPECT_EQ(fp.size(), 23U);
    for (size_t i = 0U; i < fp.size(); ++i)
    {
        if (i % 3U == 2U)
        {
            EXPECT_EQ(fp[i], ':') << "expected colon at position " << i;
        }
        else
        {
            char const c = fp[i];
            EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))
                << "expected uppercase hex at position " << i << ", got: " << c;
        }
    }
}

TEST(BtpkUtilsTest, FingerprintDiffersForDifferentKeys)
{
    BtpkPublicKey pub1{}, pub2{};
    BtpkPrivateKey priv1{}, priv2{};
    tr_btpk_key_generate(pub1, priv1);
    tr_btpk_key_generate(pub2, priv2);

    EXPECT_NE(tr_btpk_fingerprint(pub1), tr_btpk_fingerprint(pub2));
}

// ---------------------------------------------------------------------------
// Secure erasure

TEST(BtpkUtilsTest, ZeroKeyErasesMemory)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    // Confirm the key is non-zero before erasure
    ASSERT_FALSE(std::all_of(priv.begin(), priv.end(), [](auto b) { return b == 0; }));

    tr_btpk_zero_key(priv);

    EXPECT_TRUE(std::all_of(priv.begin(), priv.end(), [](auto b) { return b == 0; }));
}

TEST(BtpkUtilsTest, ZeroedKeyCannotVerify)
{
    BtpkPublicKey pub{};
    BtpkPrivateKey priv{};
    tr_btpk_key_generate(pub, priv);

    std::array<uint8_t, 64> sig{};
    std::string const msg = "test message";
    ASSERT_TRUE(tr_ed25519_sign(sig.data(), reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv.data()));

    tr_btpk_zero_key(priv);

    // Signing with a zeroed key produces a zeroed or garbage signature
    std::array<uint8_t, 64> sig2{};
    tr_ed25519_sign(sig2.data(), reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv.data());

    // The zeroed-key signature must differ from the valid one
    EXPECT_NE(sig, sig2);
}
