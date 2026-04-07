// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// Tests for BEP 46 btpk: URI parsing and serialization in tr_magnet_metainfo.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <libtransmission/magnet-metainfo.h>

#include "gtest/gtest.h"

using namespace std::literals;

namespace libtransmission::test
{
namespace
{

// A valid 64-char hex public key (32 bytes of 0x01..0x20)
auto constexpr GoodKeyHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"sv;

// Corresponding byte array
tr_magnet_metainfo::BtpkKey make_good_key()
{
    tr_magnet_metainfo::BtpkKey k{};
    for (uint8_t i = 0; i < 32; ++i)
    {
        k[i] = i + 1;
    }
    return k;
}

// A valid v1 info-hash to satisfy parseMagnet's got_hash requirement
auto constexpr GoodHash = "aabbccddeeff00112233aabbccddeeff00112233"sv;

// Build a magnet URI with btpk and optional salt
std::string make_magnet(std::string_view key_hex, std::string_view salt = ""sv)
{
    auto uri = "magnet:?xt=urn:btih:"s + std::string{ GoodHash } + "&xs=urn:btpk:" + std::string{ key_hex };
    if (!salt.empty())
    {
        uri += "&s=" + std::string{ salt };
    }
    return uri;
}

// ---------------------------------------------------------------------------
// Tests

// A well-formed btpk URI is parsed and key bytes are correct.
TEST(MagnetBtpkTest, ParsesValidKey)
{
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(make_magnet(GoodKeyHex)));
    ASSERT_TRUE(m.has_btpk());
    EXPECT_EQ(*m.btpk_key(), make_good_key());
    EXPECT_TRUE(m.btpk_salt().empty());
}

// Key with uppercase hex is accepted.
TEST(MagnetBtpkTest, ParsesUppercaseHex)
{
    auto upper = std::string{ GoodKeyHex };
    for (auto& c : upper)
        c = static_cast<char>(std::toupper(c));
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(make_magnet(upper)));
    ASSERT_TRUE(m.has_btpk());
    EXPECT_EQ(*m.btpk_key(), make_good_key());
}

// Salt parameter is parsed correctly.
TEST(MagnetBtpkTest, ParsesSalt)
{
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(make_magnet(GoodKeyHex, "mysalt"sv)));
    ASSERT_TRUE(m.has_btpk());
    EXPECT_EQ(m.btpk_salt(), "mysalt");
}

// Percent-encoded salt is decoded.
TEST(MagnetBtpkTest, ParsesEncodedSalt)
{
    auto m = tr_magnet_metainfo{};
    // "my salt" percent-encoded as "my%20salt"
    ASSERT_TRUE(m.parseMagnet(make_magnet(GoodKeyHex, "my%20salt"sv)));
    ASSERT_TRUE(m.has_btpk());
    EXPECT_EQ(m.btpk_salt(), "my salt");
}

// A key that is too short (not 64 hex chars) is rejected — has_btpk() stays false.
TEST(MagnetBtpkTest, RejectsTooShortKey)
{
    auto m = tr_magnet_metainfo{};
    // 62 hex chars = 31 bytes — invalid
    ASSERT_TRUE(m.parseMagnet(make_magnet("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"sv)));
    EXPECT_FALSE(m.has_btpk());
}

// A key with invalid hex chars is rejected.
TEST(MagnetBtpkTest, RejectsInvalidHex)
{
    auto m = tr_magnet_metainfo{};
    // Replace last two chars with 'ZZ'
    auto bad = std::string{ GoodKeyHex };
    bad[62] = 'Z';
    bad[63] = 'Z';
    ASSERT_TRUE(m.parseMagnet(make_magnet(bad)));
    EXPECT_FALSE(m.has_btpk());
}

// A URI without xs=urn:btpk: leaves has_btpk() false.
TEST(MagnetBtpkTest, NoBtpkWhenAbsent)
{
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet("magnet:?xt=urn:btih:"s + std::string{ GoodHash }));
    EXPECT_FALSE(m.has_btpk());
    EXPECT_TRUE(m.btpk_salt().empty());
}

// Round-trip: parse a URI containing btpk, then magnet() re-serializes it.
TEST(MagnetBtpkTest, RoundTripKey)
{
    auto const uri = make_magnet(GoodKeyHex);
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(uri));
    ASSERT_TRUE(m.has_btpk());

    auto const serialized = m.magnet();
    // The serialized form must contain the xs=urn:btpk: parameter with the same key
    EXPECT_NE(serialized.find("xs=urn:btpk:" + std::string{ GoodKeyHex }), std::string::npos);
    // And must NOT contain a salt parameter
    EXPECT_EQ(serialized.find("&s="), std::string::npos);
}

// Round-trip with salt.
TEST(MagnetBtpkTest, RoundTripKeyAndSalt)
{
    auto const uri = make_magnet(GoodKeyHex, "mysalt"sv);
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(uri));
    ASSERT_TRUE(m.has_btpk());
    EXPECT_EQ(m.btpk_salt(), "mysalt");

    auto const serialized = m.magnet();
    EXPECT_NE(serialized.find("xs=urn:btpk:" + std::string{ GoodKeyHex }), std::string::npos);
    EXPECT_NE(serialized.find("&s=mysalt"), std::string::npos);
}

// btpk and a v1 info-hash can coexist in the same URI.
TEST(MagnetBtpkTest, CoexistsWithInfoHash)
{
    auto m = tr_magnet_metainfo{};
    ASSERT_TRUE(m.parseMagnet(make_magnet(GoodKeyHex)));
    EXPECT_TRUE(m.has_btpk());
    // info_hash must also be populated
    static auto constexpr ZeroHash = tr_sha1_digest_t{};
    EXPECT_NE(m.info_hash(), ZeroHash);
}

} // namespace
} // namespace libtransmission::test
