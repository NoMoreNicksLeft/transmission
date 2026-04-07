// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// Layer 5 integration tests: DhtMediator subscription registry.
//
// Tests the wiring layer that connects tr_mutable_resolver (Layer 3) to the
// session/torrent lifecycle without requiring a full tr_session. We exercise
// the subscription map and on_bep44_item routing through a lightweight
// stand-alone harness built from the public resolver API.

#include <array>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

#include <dht/dht.h>

#include <libtransmission/crypto-utils.h>
#include <libtransmission/magnet-metainfo.h>
#include <libtransmission/tr-dht-mutable.h>
#include <libtransmission/tr-macros.h>
#include <libtransmission/transmission.h> // tr_torrent_id_t

#include "gtest/gtest.h"

using namespace std::literals;

namespace libtransmission::test
{

// ---------------------------------------------------------------------------
// Helpers — shared with dht-mutable-test.cc (duplicated to keep files
// self-contained per project convention)

std::vector<uint8_t> make_bep46_v(tr_sha1_digest_t const& ih)
{
    std::vector<uint8_t> v;
    char const* prefix = "d2:ih20:";
    for (int i = 0; i < 8; ++i)
        v.push_back(static_cast<uint8_t>(prefix[i]));
    for (auto b : ih)
        v.push_back(static_cast<uint8_t>(b));
    v.push_back(static_cast<uint8_t>('e'));
    return v;
}

bool make_signed_item(uint8_t const* pub,
                      uint8_t const* priv,
                      uint8_t const* salt,
                      int salt_len,
                      int64_t seq,
                      tr_sha1_digest_t const& ih,
                      dht_bep44_item& out)
{
    auto const v = make_bep46_v(ih);
    char sign_buf[1100];
    int i = 0;
    if (salt != nullptr && salt_len > 0)
    {
        int rc = snprintf(sign_buf + i, sizeof(sign_buf) - i, "4:salt%d:", salt_len);
        if (rc < 0)
            return false;
        i += rc;
        memcpy(sign_buf + i, salt, salt_len);
        i += salt_len;
    }
    {
        int rc = snprintf(sign_buf + i, sizeof(sign_buf) - i, "3:seqi%" PRId64 "e1:v%d:", seq, (int)v.size());
        if (rc < 0)
            return false;
        i += rc;
    }
    memcpy(sign_buf + i, v.data(), v.size());
    i += (int)v.size();

    std::array<uint8_t, DHT_BEP44_SIG_LEN> sig{};
    if (!tr_ed25519_sign(sig.data(), reinterpret_cast<uint8_t const*>(sign_buf), (size_t)i, priv))
        return false;

    out = {};
    out.mutable_item = 1;
    out.seq = seq;
    memcpy(out.key, pub, DHT_BEP44_KEY_LEN);
    memcpy(out.sig, sig.data(), DHT_BEP44_SIG_LEN);
    if (salt != nullptr && salt_len > 0)
    {
        memcpy(out.salt, salt, salt_len);
        out.salt_len = salt_len;
    }
    memcpy(out.v, v.data(), v.size());
    out.v_len = (int)v.size();
    return true;
}

std::array<uint8_t, 20> compute_target(uint8_t const* key, uint8_t const* salt = nullptr, int salt_len = 0)
{
    auto ctx = tr_sha1{};
    ctx.add(key, DHT_BEP44_KEY_LEN);
    if (salt != nullptr && salt_len > 0)
        ctx.add(salt, salt_len);
    auto d = ctx.finish();
    std::array<uint8_t, 20> out{};
    for (int i = 0; i < 20; ++i)
        out[i] = static_cast<uint8_t>(d[i]);
    return out;
}

tr_sha1_digest_t make_ih(uint8_t val)
{
    tr_sha1_digest_t ih{};
    ih.fill(std::byte{ val });
    return ih;
}

// ---------------------------------------------------------------------------
// Minimal subscription registry — mirrors DhtMediator::btpk_subscriptions_
// so we can test the routing logic without a full tr_session.
// (Defined outside anonymous namespace so the test fixture can access it.)

class SubscriptionRegistry
{
public:
    // Returns the callback that was registered for tor_id, or nullopt.
    void add(tr_torrent_id_t tor_id,
             tr_magnet_metainfo::BtpkKey const& key,
             std::string_view salt,
             tr_mutable_resolver::InfohashCallback cb)
    {
        subscriptions_.erase(tor_id);
        subscriptions_.emplace(std::piecewise_construct,
                               std::forward_as_tuple(tor_id),
                               std::forward_as_tuple(key, salt, std::move(cb)));
    }

    void remove(tr_torrent_id_t tor_id)
    {
        subscriptions_.erase(tor_id);
    }

    // Route item to matching resolver; return true if consumed.
    bool route(dht_bep44_item const& item)
    {
        for (auto& [id, resolver] : subscriptions_)
            if (resolver.on_dht_item(item))
                return true;
        return false;
    }

    [[nodiscard]] bool has(tr_torrent_id_t id) const
    {
        return subscriptions_.count(id) > 0;
    }

    [[nodiscard]] size_t size() const
    {
        return subscriptions_.size();
    }

private:
    std::map<tr_torrent_id_t, tr_mutable_resolver> subscriptions_;
};

// ---------------------------------------------------------------------------
// Fixture

class Layer5Test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(tr_ed25519_keypair_generate(pub_.data(), priv_.data()));
        ASSERT_TRUE(tr_ed25519_keypair_generate(pub2_.data(), priv2_.data()));
    }

    using BtpkKey = tr_magnet_metainfo::BtpkKey;

    BtpkKey pub_{};
    std::array<uint8_t, 96> priv_{};
    BtpkKey pub2_{};
    std::array<uint8_t, 96> priv2_{};
};

// ---------------------------------------------------------------------------
// Tests

// Adding a subscription registers it and it can be looked up.
TEST_F(Layer5Test, AddSubscriptionRegisters)
{
    SubscriptionRegistry reg;
    EXPECT_EQ(reg.size(), 0U);

    reg.add(1, pub_, ""sv, [](tr_sha1_digest_t const&) {});
    EXPECT_TRUE(reg.has(1));
    EXPECT_EQ(reg.size(), 1U);
}

// Removing a subscription unregisters it.
TEST_F(Layer5Test, RemoveSubscriptionUnregisters)
{
    SubscriptionRegistry reg;
    reg.add(1, pub_, ""sv, [](tr_sha1_digest_t const&) {});
    EXPECT_TRUE(reg.has(1));

    reg.remove(1);
    EXPECT_FALSE(reg.has(1));
    EXPECT_EQ(reg.size(), 0U);
}

// Removing a non-existent subscription is a no-op.
TEST_F(Layer5Test, RemoveNonExistentIsNoop)
{
    SubscriptionRegistry reg;
    EXPECT_NO_FATAL_FAILURE(reg.remove(42));
    EXPECT_EQ(reg.size(), 0U);
}

// Adding a subscription for the same torrent id replaces the old one.
TEST_F(Layer5Test, DuplicateSubscriptionReplaces)
{
    SubscriptionRegistry reg;
    int first_fired = 0;
    int second_fired = 0;

    reg.add(1, pub_, ""sv, [&](tr_sha1_digest_t const&) { ++first_fired; });
    reg.add(1, pub_, ""sv, [&](tr_sha1_digest_t const&) { ++second_fired; });
    EXPECT_EQ(reg.size(), 1U);

    auto target = compute_target(pub_.data());
    auto const ih = make_ih(0x11);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    memcpy(item.target, target.data(), 20);

    EXPECT_TRUE(reg.route(item));
    EXPECT_EQ(first_fired, 0); // old callback gone
    EXPECT_EQ(second_fired, 1); // new callback fired
}

// An incoming item is routed to the correct resolver when multiple subscriptions exist.
TEST_F(Layer5Test, RoutingDeliversToCorrectSubscription)
{
    SubscriptionRegistry reg;
    std::optional<tr_sha1_digest_t> got1, got2;

    reg.add(1, pub_, ""sv, [&](tr_sha1_digest_t const& h) { got1 = h; });
    reg.add(2, pub2_, ""sv, [&](tr_sha1_digest_t const& h) { got2 = h; });

    auto target1 = compute_target(pub_.data());
    auto target2 = compute_target(pub2_.data());

    auto const ih1 = make_ih(0xAA);
    auto const ih2 = make_ih(0xBB);

    dht_bep44_item item1{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih1, item1));
    memcpy(item1.target, target1.data(), 20);

    dht_bep44_item item2{};
    ASSERT_TRUE(make_signed_item(pub2_.data(), priv2_.data(), nullptr, 0, 1, ih2, item2));
    memcpy(item2.target, target2.data(), 20);

    EXPECT_TRUE(reg.route(item1));
    ASSERT_TRUE(got1.has_value());
    EXPECT_EQ(*got1, ih1);
    EXPECT_FALSE(got2.has_value()); // item1 did not bleed into subscription 2

    EXPECT_TRUE(reg.route(item2));
    ASSERT_TRUE(got2.has_value());
    EXPECT_EQ(*got2, ih2);
}

// An item that matches no subscription returns false from route().
TEST_F(Layer5Test, UnknownItemNotRouted)
{
    SubscriptionRegistry reg;
    reg.add(1, pub_, ""sv, [](tr_sha1_digest_t const&) {});

    // Build an item signed with pub2_ which has no subscription
    auto target2 = compute_target(pub2_.data());
    auto const ih = make_ih(0x55);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub2_.data(), priv2_.data(), nullptr, 0, 1, ih, item));
    memcpy(item.target, target2.data(), 20);

    EXPECT_FALSE(reg.route(item));
}

// After removal the subscription no longer receives items.
TEST_F(Layer5Test, RemovedSubscriptionNoLongerReceives)
{
    SubscriptionRegistry reg;
    int fired = 0;
    reg.add(1, pub_, ""sv, [&](tr_sha1_digest_t const&) { ++fired; });

    auto target = compute_target(pub_.data());
    auto const ih = make_ih(0x33);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih, item));
    memcpy(item.target, target.data(), 20);

    reg.remove(1);
    EXPECT_FALSE(reg.route(item));
    EXPECT_EQ(fired, 0);
}

// Multiple subscriptions can coexist; each receives only its own items.
TEST_F(Layer5Test, MultipleSubscriptionsCoexist)
{
    SubscriptionRegistry reg;
    std::vector<tr_sha1_digest_t> got1, got2;

    reg.add(10, pub_, ""sv, [&](tr_sha1_digest_t const& h) { got1.push_back(h); });
    reg.add(20, pub2_, ""sv, [&](tr_sha1_digest_t const& h) { got2.push_back(h); });

    auto target1 = compute_target(pub_.data());
    auto target2 = compute_target(pub2_.data());

    // Send two updates to subscription 1, one to subscription 2
    for (int seq = 1; seq <= 2; ++seq)
    {
        auto ih = make_ih(static_cast<uint8_t>(seq * 0x10));
        dht_bep44_item item{};
        ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, seq, ih, item));
        memcpy(item.target, target1.data(), 20);
        EXPECT_TRUE(reg.route(item));
    }
    {
        auto ih = make_ih(0xCC);
        dht_bep44_item item{};
        ASSERT_TRUE(make_signed_item(pub2_.data(), priv2_.data(), nullptr, 0, 1, ih, item));
        memcpy(item.target, target2.data(), 20);
        EXPECT_TRUE(reg.route(item));
    }

    EXPECT_EQ(got1.size(), 2U);
    EXPECT_EQ(got2.size(), 1U);
}

// Salted subscription uses SHA1(key||salt) as target and routes correctly.
TEST_F(Layer5Test, SaltedSubscriptionRoutesCorrectly)
{
    std::string const salt = "channel";
    SubscriptionRegistry reg;
    std::optional<tr_sha1_digest_t> got;

    reg.add(5, pub_, salt, [&](tr_sha1_digest_t const& h) { got = h; });

    auto target_salted = compute_target(pub_.data(), reinterpret_cast<uint8_t const*>(salt.data()), (int)salt.size());

    auto const ih = make_ih(0x77);
    dht_bep44_item item{};
    ASSERT_TRUE(make_signed_item(pub_.data(),
                                 priv_.data(),
                                 reinterpret_cast<uint8_t const*>(salt.data()),
                                 (int)salt.size(),
                                 1,
                                 ih,
                                 item));
    memcpy(item.target, target_salted.data(), 20);

    EXPECT_TRUE(reg.route(item));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, ih);
}

// update_btpk_infohash logic: callback fires only on actual change.
// Tested directly through the resolver's state (no tr_torrent needed).
TEST_F(Layer5Test, CallbackFiresOnlyOnHashChange)
{
    int fire_count = 0;
    tr_mutable_resolver resolver{ pub_, ""sv, [&](tr_sha1_digest_t const&) { ++fire_count; } };

    auto target = compute_target(pub_.data());
    auto const ih1 = make_ih(0x01);
    auto const ih2 = make_ih(0x02);

    dht_bep44_item item1{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 1, ih1, item1));
    memcpy(item1.target, target.data(), 20);

    // seq=2, same ih1
    dht_bep44_item item1b{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 2, ih1, item1b));
    memcpy(item1b.target, target.data(), 20);

    // seq=3, new ih2
    dht_bep44_item item2{};
    ASSERT_TRUE(make_signed_item(pub_.data(), priv_.data(), nullptr, 0, 3, ih2, item2));
    memcpy(item2.target, target.data(), 20);

    resolver.on_dht_item(item1); // fires (new hash)
    EXPECT_EQ(fire_count, 1);

    resolver.on_dht_item(item1b); // accepted (newer seq) but same hash — no fire
    EXPECT_EQ(fire_count, 1);

    resolver.on_dht_item(item2); // fires (hash changed)
    EXPECT_EQ(fire_count, 2);
}

} // namespace libtransmission::test
