// This file Copyright (C) 2013-2022 Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#include <array>
#include <cassert>
#include <cstddef> // std::byte, size_t
#include <cstdint> // uint8_t
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>

#include <ed25519.h>

#include <libtransmission/peer-mse.h>
#include <libtransmission/crypto-utils.h>
#include <libtransmission/tr-macros.h>
#include <libtransmission/utils.h>

#include "gtest/gtest.h"

using namespace std::literals;

namespace
{

auto constexpr SomeHash = tr_sha1_digest_t{
    std::byte{ 0 },  std::byte{ 1 },  std::byte{ 2 },  std::byte{ 3 },  std::byte{ 4 },  std::byte{ 5 },  std::byte{ 6 },
    std::byte{ 7 },  std::byte{ 8 },  std::byte{ 9 },  std::byte{ 10 }, std::byte{ 11 }, std::byte{ 12 }, std::byte{ 13 },
    std::byte{ 14 }, std::byte{ 15 }, std::byte{ 16 }, std::byte{ 17 }, std::byte{ 18 }, std::byte{ 19 },
};

template<size_t N>
std::string toString(std::array<std::byte, N> const& array)
{
    auto ostr = std::ostringstream{};
    ostr << '[';
    for (auto const b : array)
    {
        ostr << static_cast<unsigned>(b) << ' ';
    }
    ostr << ']';
    return ostr.str();
}

} // namespace

TEST(Crypto, DH)
{
    auto a = tr_message_stream_encryption::DH{ tr_message_stream_encryption::DH::randomPrivateKey() };
    auto b = tr_message_stream_encryption::DH{ tr_message_stream_encryption::DH::randomPrivateKey() };

    a.setPeerPublicKey(b.publicKey());
    b.setPeerPublicKey(a.publicKey());
    EXPECT_EQ(toString(a.secret()), toString(b.secret()));
    EXPECT_EQ(a.secret(), b.secret());
    EXPECT_EQ(96U, std::size(a.secret()));

    auto c = tr_message_stream_encryption::DH{ tr_message_stream_encryption::DH::randomPrivateKey() };
    c.setPeerPublicKey(b.publicKey());
    EXPECT_NE(a.secret(), c.secret());
    EXPECT_NE(toString(a.secret()), toString(c.secret()));
}

TEST(Crypto, encryptDecrypt)
{
    auto a_dh = tr_message_stream_encryption::DH{ tr_message_stream_encryption::DH::randomPrivateKey() };
    auto b_dh = tr_message_stream_encryption::DH{ tr_message_stream_encryption::DH::randomPrivateKey() };

    a_dh.setPeerPublicKey(b_dh.publicKey());
    b_dh.setPeerPublicKey(a_dh.publicKey());

    auto constexpr Input1 = "test1"sv;
    auto encrypted1 = std::array<char, 128>{};
    auto decrypted1 = std::array<char, 128>{};

    auto a = tr_message_stream_encryption::Filter{};
    a.encrypt_init(false, a_dh, SomeHash);
    a.encrypt(std::data(Input1), std::size(Input1), std::data(encrypted1));
    auto b = tr_message_stream_encryption::Filter{};
    b.decrypt_init(true, b_dh, SomeHash);
    b.decrypt(std::data(encrypted1), std::size(Input1), std::data(decrypted1));
    EXPECT_EQ(Input1, std::data(decrypted1)) << "Input1 " << Input1 << " decrypted1 " << std::data(decrypted1);

    auto constexpr Input2 = "@#)C$@)#(*%bvkdjfhwbc039bc4603756VB3)"sv;
    auto encrypted2 = std::array<char, 128>{};
    auto decrypted2 = std::array<char, 128>{};

    b.encrypt_init(true, b_dh, SomeHash);
    b.encrypt(std::data(Input2), std::size(Input2), std::data(encrypted2));
    a.decrypt_init(false, a_dh, SomeHash);
    a.decrypt(std::data(encrypted2), std::size(Input2), std::data(decrypted2));
    EXPECT_EQ(Input2, std::data(decrypted2)) << "Input2 " << Input2 << " decrypted2 " << std::data(decrypted2);
}

TEST(Crypto, sha1)
{
    auto hash1 = tr_sha1::digest("test"sv);
    EXPECT_EQ(0,
              memcmp(std::data(hash1),
                     "\xa9\x4a\x8f\xe5\xcc\xb1\x9b\xa6\x1c\x4c\x08\x73\xd3\x91\xe9\x87\x98\x2f\xbb\xd3",
                     std::size(hash1)));

    auto hash2 = tr_sha1::digest("test"sv);
    EXPECT_EQ(hash1, hash2);

    hash1 = tr_sha1::digest("1"sv, "22"sv, "333"sv);
    hash2 = tr_sha1::digest("1"sv, "22"sv, "333"sv);
    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(0,
              memcmp(std::data(hash1),
                     "\x1f\x74\x64\x8e\x50\xa6\xa6\x70\x8e\xc5\x4a\xb3\x27\xa1\x63\xd5\x53\x6b\x7c\xed",
                     std::size(hash1)));

    auto const hash3 = tr_sha1::digest("test"sv);
    EXPECT_EQ("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"sv, tr_sha1_to_string(hash3));

    auto const hash4 = tr_sha1::digest("te"sv, "st"sv);
    EXPECT_EQ("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"sv, tr_sha1_to_string(hash4));

    auto const hash5 = tr_sha1::digest("t"sv, "e"sv, std::string{ "s" }, std::array<char, 1>{ { 't' } });
    EXPECT_EQ("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"sv, tr_sha1_to_string(hash5));
}

TEST(Crypto, ssha1)
{
    struct LocalTest
    {
        std::string_view plain_text;
        std::string_view ssha1;
    };

    static auto constexpr Tests = std::array<LocalTest, 2>{ {
        { "test"sv, "{15ad0621b259a84d24dcd4e75b09004e98a3627bAMbyRHJy"sv },
        { "QNY)(*#$B)!_X$B !_B#($^!)*&$%CV!#)&$C!@$(P*)"sv, "{10e2d7acbb104d970514a147cd16d51dfa40fb3c0OSwJtOL"sv },
    } };

    static auto constexpr HashCount = size_t{ 4U } * 1024U;

    for (auto const& [plain_text, ssha1] : Tests)
    {
        auto hashes = std::unordered_set<std::string>{};
        hashes.reserve(HashCount);

        EXPECT_TRUE(tr_ssha1_matches(ssha1, plain_text));

        for (size_t j = 0; j < HashCount; ++j)
        {
            auto const hash = tr_ssha1(plain_text);
            EXPECT_TRUE(tr_ssha1_matches(hash, plain_text));
            hashes.insert(hash);
        }

        // confirm all hashes are different
        EXPECT_EQ(HashCount, hashes.size());

        /* exchange two first chars */
        auto phrase = std::string{ plain_text };
        std::swap(phrase[0], phrase[1]);

        for (auto const& hash : hashes)
        {
            /* changed phrase doesn't match the hashes */
            EXPECT_FALSE(tr_ssha1_matches(hash, phrase));
        }
    }

    /* should work with different salt lengths as well */
    EXPECT_TRUE(tr_ssha1_matches("{a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "test"));
    EXPECT_TRUE(tr_ssha1_matches("{d209a21d3bc4f8fc4f8faf347e69f3def597eb170pySy4ai1ZPMjeU1", "test"));
}

TEST(Crypto, sha1FromString)
{
    // bad lengths
    EXPECT_FALSE(tr_sha1_from_string(""));
    EXPECT_FALSE(tr_sha1_from_string("a94a8fe5ccb19ba61c4c0873d391e987982fbbd"sv));
    EXPECT_FALSE(tr_sha1_from_string("a94a8fe5ccb19ba61c4c0873d391e987982fbbd33"sv));
    // nonhex
    EXPECT_FALSE(tr_sha1_from_string("a94a8fe5ccb19ba61c4cz873d391e987982fbbd3"sv));
    EXPECT_FALSE(tr_sha1_from_string("a94a8fe5ccb19  61c4c0873d391e987982fbbd3"sv));

    // lowercase hex
    auto const baseline = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"sv;
    auto const lc = tr_sha1_from_string(baseline);
    EXPECT_TRUE(lc.has_value());
    assert(lc.has_value());
    EXPECT_EQ(baseline, tr_sha1_to_string(*lc));

    // uppercase hex should yield the same result
    auto const uc = tr_sha1_from_string(tr_strupper(baseline));
    EXPECT_TRUE(uc.has_value());
    assert(uc.has_value());
    EXPECT_EQ(*lc, *uc);
}

TEST(Crypto, sha256FromString)
{
    // bad lengths
    EXPECT_FALSE(tr_sha256_from_string(""));
    EXPECT_FALSE(tr_sha256_from_string("a94a8fe5ccb19ba61c4c0873d391e987982fbbd"sv));
    EXPECT_FALSE(tr_sha256_from_string("a94a8fe5ccb19ba61c4c0873d391e987982fbbd33"sv));
    EXPECT_FALSE(tr_sha256_from_string("05d58dfd14ed21d33add137eb7a2c5d4ef5aaa4a945e654363d32b7c4bf5c92"sv));
    EXPECT_FALSE(tr_sha256_from_string("05d58dfd14ed21d33add137eb7a2c5d4ef5aaa4a945e654363d32b7c4bf5c9299"sv));
    // nonhex
    EXPECT_FALSE(tr_sha256_from_string("a94a8fe5ccb19ba61c4cz873d391e987982fbbd3aaaaaaaaaaaaaaaaaaaaaaa"sv));
    EXPECT_FALSE(tr_sha256_from_string("05  8dfd14ed21d33add137eb7a2c5d4ef5aaa4a945e654363d32b7c4bf5c92"sv));

    // lowercase hex
    auto const baseline = "05d58dfd14ed21d33add137eb7a2c5d4ef5aaa4a945e654363d32b7c4bf5c929"sv;
    auto const lc = tr_sha256_from_string(baseline);
    EXPECT_TRUE(lc.has_value());
    assert(lc.has_value());
    EXPECT_EQ(baseline, tr_sha256_to_string(*lc));

    // uppercase hex should yield the same result
    auto const uc = tr_sha256_from_string(tr_strupper(baseline));
    EXPECT_TRUE(uc.has_value());
    assert(uc.has_value());
    EXPECT_EQ(*lc, *uc);
}

TEST(Crypto, random)
{
    /* test that tr_rand_int() stays in-bounds */
    for (int i = 0; i < 100000; ++i)
    {
        auto const val = tr_rand_int(100U);
        EXPECT_LE(0U, val);
        EXPECT_LT(val, 100U);
    }
}

using CryptoRandBufferTest = ::testing::TestWithParam<size_t>;

TEST_P(CryptoRandBufferTest, randBuf)
{
    static auto constexpr Iterations = 1000U;

    auto const width = GetParam();
    auto const empty = std::vector<uint8_t>(width, 0);

    auto buf = empty;

    for (size_t i = 0; i < Iterations; ++i)
    {
        auto tmp = buf;
        tr_rand_buffer(std::data(tmp), std::size(tmp));
        EXPECT_NE(tmp, empty);
        EXPECT_NE(tmp, buf);
        buf = tmp;
    }

    for (size_t i = 0; i < Iterations; ++i)
    {
        auto tmp = buf;
        EXPECT_TRUE(tr_rand_buffer_crypto(std::data(tmp), std::size(tmp)));
        EXPECT_NE(tmp, empty);
        EXPECT_NE(tmp, buf);
        buf = tmp;
    }

    for (size_t i = 0; i < Iterations; ++i)
    {
        auto tmp = buf;
        tr_rand_buffer_std(std::data(tmp), std::size(tmp));
        EXPECT_NE(tmp, empty);
        EXPECT_NE(tmp, buf);
        buf = tmp;
    }
}

INSTANTIATE_TEST_SUITE_P(Crypto,
                         CryptoRandBufferTest,
                         ::testing::Values(32, 100, 1024, 3000),
                         ::testing::PrintToStringParamName{});

TEST(Crypto, base64)
{
    auto raw = std::string_view{ "YOYO!"sv };
    auto encoded = tr_base64_encode(raw);
    EXPECT_EQ("WU9ZTyE="sv, encoded);
    EXPECT_EQ(raw, tr_base64_decode(encoded));

    EXPECT_EQ(""sv, tr_base64_encode(""sv));
    EXPECT_EQ(""sv, tr_base64_decode(""sv));

    static auto constexpr MaxBufSize = size_t{ 1024 };
    for (size_t i = 1; i <= MaxBufSize; ++i)
    {
        auto buf = std::string{};
        for (size_t j = 0; j < i; ++j)
        {
            buf += static_cast<char>(tr_rand_int(256U));
        }
        EXPECT_EQ(buf, tr_base64_decode(tr_base64_encode(buf)));

        buf = std::string{};
        for (size_t j = 0; j < i; ++j)
        {
            buf += static_cast<char>(1U + tr_rand_int(255U));
        }
        EXPECT_EQ(buf, tr_base64_decode(tr_base64_encode(buf)));
    }
}

// ── BEP 44 ed25519 tests ─────────────────────────────────────────────────────

// Test vectors from BEP 44 spec
// https://www.bittorrent.org/beps/bep_0044.html

TEST(Crypto, Ed25519KeypairGenerate)
{
    uint8_t pub[32], priv[64];
    EXPECT_TRUE(tr_ed25519_keypair_generate(pub, priv));

    // Two generations must produce different keys
    uint8_t pub2[32], priv2[64];
    EXPECT_TRUE(tr_ed25519_keypair_generate(pub2, priv2));
    EXPECT_NE(memcmp(pub, pub2, 32), 0);
}

TEST(Crypto, Ed25519SignVerifyRoundTrip)
{
    uint8_t pub[32], priv[96];
    ASSERT_TRUE(tr_ed25519_keypair_generate(pub, priv));

    auto const msg = std::string_view{ "3:seqi1e1:v12:Hello World!" };
    uint8_t sig[64];
    ASSERT_TRUE(tr_ed25519_sign(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv));
    EXPECT_TRUE(tr_ed25519_verify(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), pub));
}

TEST(Crypto, Ed25519VerifyFailsOnTamperedMessage)
{
    uint8_t pub[32], priv[96];
    ASSERT_TRUE(tr_ed25519_keypair_generate(pub, priv));

    auto msg = std::string{ "3:seqi1e1:v12:Hello World!" };
    uint8_t sig[64];
    ASSERT_TRUE(tr_ed25519_sign(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv));

    msg[0] = 'X'; // tamper
    EXPECT_FALSE(tr_ed25519_verify(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), pub));
}

TEST(Crypto, Ed25519VerifyFailsOnTamperedSignature)
{
    uint8_t pub[32], priv[96];
    ASSERT_TRUE(tr_ed25519_keypair_generate(pub, priv));

    auto const msg = std::string_view{ "3:seqi1e1:v12:Hello World!" };
    uint8_t sig[64];
    ASSERT_TRUE(tr_ed25519_sign(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), priv));

    sig[0] ^= 0xFF; // tamper
    EXPECT_FALSE(tr_ed25519_verify(sig, reinterpret_cast<uint8_t const*>(msg.data()), msg.size(), pub));
}

// BEP 44 spec test vector 1 (mutable, no salt)
// public key:  77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548
// private key: e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74d
//              b7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d
// signing buf: 3:seqi1e1:v12:Hello World!
// signature:   305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff
//              1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01
static auto hexdecode(std::string_view hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        auto byte = std::string{ hex.substr(i, 2) };
        out.push_back(static_cast<uint8_t>(std::stoul(byte, nullptr, 16)));
    }
    return out;
}

TEST(Crypto, Ed25519BEP44TestVector1)
{
    auto const pub_hex = std::string_view{ "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548" };
    auto const priv_hex = std::string_view{ "e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74d" };
    auto const sig_hex = std::string_view{
        "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff"
        "1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01"
    };

    auto pub_bytes = hexdecode(pub_hex);
    auto seed_bytes = hexdecode(priv_hex); // spec "private key" is the 32-byte seed
    auto expected_sig = hexdecode(sig_hex);

    ASSERT_EQ(32U, pub_bytes.size());
    ASSERT_EQ(32U, seed_bytes.size());
    ASSERT_EQ(64U, expected_sig.size());

    auto const signing_buf = std::string_view{ "3:seqi1e1:v12:Hello World!" };

    // Verify the known signature against the known public key
    EXPECT_TRUE(tr_ed25519_verify(expected_sig.data(),
                                  reinterpret_cast<uint8_t const*>(signing_buf.data()),
                                  signing_buf.size(),
                                  pub_bytes.data()));

    // Reconstruct the 96-byte private key from the spec seed,
    // then sign and verify with our own signature.
    uint8_t reconstructed_pub[32];
    uint8_t reconstructed_priv[96];
    ed25519_create_keypair(reconstructed_pub, reconstructed_priv, seed_bytes.data());
    memcpy(reconstructed_priv + 64, reconstructed_pub, 32);

    uint8_t sig[64];
    ASSERT_TRUE(
        tr_ed25519_sign(sig, reinterpret_cast<uint8_t const*>(signing_buf.data()), signing_buf.size(), reconstructed_priv));

    EXPECT_TRUE(
        tr_ed25519_verify(sig, reinterpret_cast<uint8_t const*>(signing_buf.data()), signing_buf.size(), reconstructed_pub));
}

// BEP 44 spec test vector 2 (mutable, with salt "foobar")
// signing buf: 4:salt6:foobar3:seqi1e1:v12:Hello World!
// same keys, different expected signature
TEST(Crypto, Ed25519BEP44TestVector2)
{
    auto const pub_hex = std::string_view{ "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548" };
    auto const sig_hex = std::string_view{
        "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17d"
        "df9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08"
    };

    auto pub = hexdecode(pub_hex);
    auto expected_sig = hexdecode(sig_hex);

    auto const signing_buf = std::string_view{ "4:salt6:foobar3:seqi1e1:v12:Hello World!" };

    EXPECT_TRUE(tr_ed25519_verify(expected_sig.data(),
                                  reinterpret_cast<uint8_t const*>(signing_buf.data()),
                                  signing_buf.size(),
                                  pub.data()));
}
