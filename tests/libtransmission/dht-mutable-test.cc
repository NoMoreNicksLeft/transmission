// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// Tests for tr_mutable_resolver (Layer 3): BEP 46 item decoding, signature
// verification, sequence-number gating, and infohash callback behaviour.

#include <array>
#include <cinttypes>
#include <cstddef> // std::byte
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

#include <dht/dht.h> // dht_bep44_item, DHT_BEP44_KEY_LEN, DHT_BEP44_SIG_LEN

#include <libtransmission/crypto-utils.h> // tr_sha1, tr_ed25519_keypair_generate, tr_ed25519_sign
#include <libtransmission/tr-dht-mutable.h>
#include <libtransmission/tr-macros.h> // tr_sha1_digest_t = std::array<std::byte, 20>

#include "gtest/gtest.h"

using namespace std::literals;

namespace libtransmission::test
{
namespace
{

// ---------------------------------------------------------------------------
// Helpers

// Build a minimal BEP 46 bencoded value: d1:ih20:<hash>e
// ih is std::array<std::byte, 20>; we need raw bytes in the output vector.
std::vector<uint8_t> make_bep46_v(tr_sha1_digest_t const& ih)
{
    std::vector<uint8_t> v;
    // prefix: "d1:ih20:"
    char const* prefix = "d2:ih20:";
    for (int i = 0; i < 8; ++i)
    {
        v.push_back(static_cast<uint8_t>(prefix[i]));
    }
    // 20 infohash bytes
    for (auto b : ih)
    {
        v.push_back(static_cast<uint8_t>(b));
    }
    // suffix: "e"
    v.push_back(static_cast<uint8_t>('e'));
    return v;
}

// Build the BEP 44 signing buffer and sign it, then populate a dht_bep44_item.
bool make_signed_item(uint8_t const* key_public,
                      uint8_t const* key_private,
                      uint8_t const* salt,
                      int const salt_len,
                      int64_t const seq,
                      tr_sha1_digest_t const& ih,
                      dht_bep44_item& out)
{
    auto const v = make_bep46_v(ih);

    // Signing buffer: [4:saltN:<salt>]3:seqi<seq>e1:v<vlen>:<v>
    char sign_buf[1100];
    int i = 0;
    if (salt != nullptr && salt_len > 0)
    {
        int rc = snprintf(sign_buf + i, sizeof(sign_buf) - i, "4:salt%d:", salt_len);
        if (rc < 0 || rc >= static_cast<int>(sizeof(sign_buf) - i))
        {
            return false;
        }
        i += rc;
        if (i + salt_len >= static_cast<int>(sizeof(sign_buf)))
        {
            return false;
        }
        memcpy(sign_buf + i, salt, salt_len);
        i += salt_len;
    }
    {
        int rc = snprintf(sign_buf + i, sizeof(sign_buf) - i, "3:seqi%" PRId64 "e1:v%d:", seq, static_cast<int>(v.size()));
        if (rc < 0 || rc >= static_cast<int>(sizeof(sign_buf) - i))
        {
            return false;
        }
        i += rc;
    }
    if (i + static_cast<int>(v.size()) >= static_cast<int>(sizeof(sign_buf)))
    {
        return false;
    }
    memcpy(sign_buf + i, v.data(), v.size());
    i += static_cast<int>(v.size());

    // Sign
    std::array<uint8_t, DHT_BEP44_SIG_LEN> sig{};
    if (!tr_ed25519_sign(sig.data(), reinterpret_cast<uint8_t const*>(sign_buf), static_cast<size_t>(i), key_private))
    {
        return false;
    }

    // Populate item
    out = {};
    out.mutable_item = 1;
    out.seq = seq;
    memcpy(out.key, key_public, DHT_BEP44_KEY_LEN);
    memcpy(out.sig, sig.data(), DHT_BEP44_SIG_LEN);
    if (salt != nullptr && salt_len > 0)
    {
        memcpy(out.salt, salt, salt_len);
        out.salt_len = salt_len;
    }
    memcpy(out.v, v.data(), v.size());
    out.v_len = static_cast<int>(v.size());

    return true;
}

// Compute BEP 44 target = SHA1(key || salt) for test assertions.
std::array<uint8_t, 20> compute_target(uint8_t const* key, uint8_t const* salt, int salt_len)
{
    auto ctx = tr_sha1{};
    ctx.add(key, DHT_BEP44_KEY_LEN);
    if (salt != nullptr && salt_len > 0)
    {
        ctx.add(salt, salt_len);
    }
    auto const digest = ctx.finish(); // std::array<std::byte, 20>
    std::array<uint8_t, 20> out{};
    for (int i = 0; i < 20; ++i)
    {
        out[i] = static_cast<uint8_t>(digest[i]);
    }
    return out;
}

// Fill item.target from a uint8_t[20] array.
void set_target(dht_bep44_item& item, std::array<uint8_t, 20> const& t)
{
    memcpy(item.target, t.data(), 20);
}

// ---------------------------------------------------------------------------
// Fixture

class MutableResolverTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(tr_ed25519_keypair_generate(pub_.data(), priv_.data()));
        target_nosalt_ = compute_target(pub_.data(), nullptr, 0);
    }

    std::array<uint8_t, DHT_BEP44_KEY_LEN> pub_{};
    std::array<uint8_t, 96> priv_{};
    std::array<uint8_t, 20> target_nosalt_{};
};

// Convenience: make a tr_sha1_digest_t (std::array<std::byte,20>) filled with a byte value.
tr_sha1_digest_t make_ih(uint8_t val)
{
    tr_sha1_digest_t ih{};
    ih.fill(std::byte{ val });
    return ih;
}

// ---------------------------------------------------------------------------
// Tests

// A well-formed, correctly signed item is accepted and fires the callback.
TEST_F(MutableResolverTest, AcceptsValidItem)
{
    std::optional<tr_sha1_digest_t> got;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const& h) { got = h; } };

    auto const ih = make_ih(0x42);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    set_target(item, target_nosalt_);

    // Debug: print both targets to confirm they match
    auto const& rt = resolver.target();
    printf("item.target:     ");
    for (int i = 0; i < 20; ++i)
        printf("%02x", item.target[i]);
    printf("\n");
    printf("resolver.target: ");
    for (int i = 0; i < 20; ++i)
        printf("%02x", rt[i]);
    printf("\n");
    printf("pub_[0..3]: %02x %02x %02x %02x\n", pub_[0], pub_[1], pub_[2], pub_[3]);

    EXPECT_TRUE(resolver.on_dht_item(item));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, ih);
    EXPECT_EQ(resolver.last_seq(), 1);
}

// An item with a stale or equal sequence number is rejected.
TEST_F(MutableResolverTest, RejectsStaleSeq)
{
    int cb_count = 0;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++cb_count; } };

    auto const ih = make_ih(0x11);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 5, ih, item));
    set_target(item, target_nosalt_);

    EXPECT_TRUE(resolver.on_dht_item(item));
    EXPECT_EQ(cb_count, 1);

    // Same seq — rejected
    EXPECT_FALSE(resolver.on_dht_item(item));
    EXPECT_EQ(cb_count, 1);

    // Lower seq — also rejected
    dht_bep44_item old_item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 3, ih, old_item));
    set_target(old_item, target_nosalt_);
    EXPECT_FALSE(resolver.on_dht_item(old_item));
    EXPECT_EQ(cb_count, 1);
}

// A newer item with a changed infohash fires the callback again.
TEST_F(MutableResolverTest, UpdatedInfohashFiresCallback)
{
    std::vector<tr_sha1_digest_t> received;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const& h) { received.push_back(h); } };

    auto const ih1 = make_ih(0xAA);
    auto const ih2 = make_ih(0xBB);

    dht_bep44_item item1{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih1, item1));
    set_target(item1, target_nosalt_);

    dht_bep44_item item2{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 2, ih2, item2));
    set_target(item2, target_nosalt_);

    EXPECT_TRUE(resolver.on_dht_item(item1));
    EXPECT_TRUE(resolver.on_dht_item(item2));

    ASSERT_EQ(received.size(), 2U);
    EXPECT_EQ(received[0], ih1);
    EXPECT_EQ(received[1], ih2);
}

// A newer item with the same infohash advances last_seq but does NOT re-fire the callback.
TEST_F(MutableResolverTest, SameInfohashNoCallback)
{
    int cb_count = 0;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++cb_count; } };

    auto const ih = make_ih(0x55);

    dht_bep44_item item1{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item1));
    set_target(item1, target_nosalt_);

    dht_bep44_item item2{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 2, ih, item2));
    set_target(item2, target_nosalt_);

    EXPECT_TRUE(resolver.on_dht_item(item1));
    EXPECT_EQ(cb_count, 1);

    EXPECT_TRUE(resolver.on_dht_item(item2)); // accepted but no new callback
    EXPECT_EQ(cb_count, 1);
    EXPECT_EQ(resolver.last_seq(), 2);
}

// An item with a corrupted signature is rejected.
TEST_F(MutableResolverTest, RejectsBadSignature)
{
    int cb_count = 0;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++cb_count; } };

    auto const ih = make_ih(0x77);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    set_target(item, target_nosalt_);

    item.sig[0] ^= 0xFF; // corrupt one byte

    EXPECT_FALSE(resolver.on_dht_item(item));
    EXPECT_EQ(cb_count, 0);
}

// An immutable item (mutable_item == 0) is rejected outright.
TEST_F(MutableResolverTest, RejectsImmutableItem)
{
    int cb_count = 0;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++cb_count; } };

    auto const ih = make_ih(0x33);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    set_target(item, target_nosalt_);
    item.mutable_item = 0;

    EXPECT_FALSE(resolver.on_dht_item(item));
    EXPECT_EQ(cb_count, 0);
}

// An item whose target does not match this resolver's target is rejected.
TEST_F(MutableResolverTest, RejectsWrongTarget)
{
    int cb_count = 0;
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++cb_count; } };

    auto const ih = make_ih(0x22);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    memset(item.target, 0xDE, 20); // wrong target

    EXPECT_FALSE(resolver.on_dht_item(item));
    EXPECT_EQ(cb_count, 0);
}

// With a salt, target = SHA1(key || salt) and the signed buffer must include the salt prefix.
TEST_F(MutableResolverTest, SaltedItemAccepted)
{
    std::string const salt = "mysalt";
    auto const target_salted = compute_target(pub_.data(),
                                              reinterpret_cast<uint8_t const*>(salt.data()),
                                              static_cast<int>(salt.size()));

    std::optional<tr_sha1_digest_t> got;
    auto resolver = tr_mutable_resolver{ pub_, salt, [&](tr_sha1_digest_t const& h) { got = h; } };

    // Resolver's target() returns std::array<uint8_t,20> — compare element-by-element
    auto const& rt = resolver.target();
    EXPECT_EQ(rt, target_salted);

    auto const ih = make_ih(0x99);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(),
                                 priv_.data(),
                                 reinterpret_cast<uint8_t const*>(salt.data()),
                                 static_cast<int>(salt.size()),
                                 7,
                                 ih,
                                 item));
    set_target(item, target_salted);

    EXPECT_TRUE(resolver.on_dht_item(item));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, ih);
}

// target() returns the correct SHA1(key) value when no salt is used.
TEST_F(MutableResolverTest, TargetComputedCorrectly)
{
    auto resolver = tr_mutable_resolver{ pub_, ""sv, [](tr_sha1_digest_t const&) {} };
    EXPECT_EQ(resolver.target(), target_nosalt_);
}

} // namespace
} // namespace libtransmission::test
