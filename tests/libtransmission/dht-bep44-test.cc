// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// BEP 44 tests — exercises dht_put_mutable / dht_put_immutable / dht_get
// through the tr_dht::API mock layer, consistent with the rest of the suite.
// Separate from dht-test.cc to keep that file's scope focused on BEP 5.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <dht/dht.h>

#include <libtransmission/crypto-utils.h>
#include <libtransmission/session-thread.h>
#include <libtransmission/timer.h>
#include <libtransmission/timer-ev.h>
#include <libtransmission/tr-dht.h>
#include <libtransmission/tr-macros.h>
#include <event2/event.h>

#include "gtest/gtest.h"
#include "test-fixtures.h"

using namespace std::literals;

namespace libtransmission::test
{
namespace
{

auto hexdecode(std::string_view hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(std::string{ hex.substr(i, 2) }, nullptr, 16)));
    return out;
}

// Minimal MockDht that records BEP44 calls — reuses the same pattern as
// the full DhtTest suite but only includes what BEP44 tests need.
class MockBep44Dht final : public tr_dht::API
{
public:
    struct GetCall
    {
        std::array<uint8_t, 20> target;
        int64_t seq_known;
    };
    struct PutCall
    {
        std::array<uint8_t, 32> key;
        int64_t seq;
        int salt_len;
        int v_len;
    };

    std::vector<GetCall> gets_;
    std::vector<PutCall> puts_;
    dht_bep44_item last_item_{};
    bool item_received_ = false;

    // ── BEP 44 overrides ────────────────────────────────────────────────────
    int bep44_get(unsigned char const* target, int64_t seq_known, dht_bep44_callback cb, void* closure) override
    {
        GetCall c;
        std::copy_n(target, 20, c.target.begin());
        c.seq_known = seq_known;
        gets_.push_back(c);
        // Immediately fire callback with stored item if present
        if (cb && item_received_)
            cb(closure, &last_item_);
        return 0;
    }

    int bep44_put_mutable(unsigned char const* key,
                          unsigned char const* /*sig*/,
                          unsigned char const* /*salt*/,
                          int salt_len,
                          int64_t seq,
                          unsigned char const* /*v*/,
                          int v_len,
                          dht_bep44_callback /*cb*/,
                          void* /*closure*/) override
    {
        PutCall c;
        std::copy_n(key, 32, c.key.begin());
        c.seq = seq;
        c.salt_len = salt_len;
        c.v_len = v_len;
        puts_.push_back(c);
        return 0;
    }

    int bep44_put_immutable(unsigned char const* v, int v_len, dht_bep44_callback cb, void* closure) override
    {
        // Build a synthetic item so callers can verify the callback fires
        dht_bep44_item item{};
        item.mutable_item = 0;
        item.v_len = v_len;
        if (v_len > 0 && v_len <= DHT_BEP44_VALUE_MAX)
            memcpy(item.v, v, v_len);
        if (cb)
            cb(closure, &item);
        return 0;
    }

    // ── Stub out BEP 5 methods (not exercised here) ──────────────────────────
    int get_nodes(sockaddr_in* /*sin*/, int* /*max*/, sockaddr_in6* /*sin6*/, int* /*max6*/) override
    {
        return 0;
    }
    int nodes(int, int* g, int* d, int* c, int* i) override
    {
        if (g)
            *g = 50;
        if (d)
            *d = 0;
        if (c)
            *c = 0;
        if (i)
            *i = 10;
        return 0;
    }
    int periodic(void const*, size_t, sockaddr const*, int, time_t*, dht_callback_t, void*) override
    {
        return 0;
    }
    int ping_node(sockaddr const*, int) override
    {
        return 0;
    }
    int search(unsigned char const*, int, int, dht_callback_t, void*) override
    {
        return 0;
    }
    int init(int, int, unsigned char const*, unsigned char const*) override
    {
        return 0;
    }
    int uninit() override
    {
        return 0;
    }
};

// Minimal mediator that wires MockBep44Dht
class Bep44Mediator final : public tr_dht::Mediator
{
public:
    explicit Bep44Mediator(struct event_base* evb)
        : timer_maker_{ evb }
    {
    }

    [[nodiscard]] std::vector<tr_torrent_id_t> torrents_allowing_dht() const override
    {
        return {};
    }
    [[nodiscard]] tr_sha1_digest_t torrent_info_hash(tr_torrent_id_t) const override
    {
        return {};
    }
    [[nodiscard]] std::string_view config_dir() const override
    {
        return config_dir_;
    }
    [[nodiscard]] libtransmission::TimerMaker& timer_maker() override
    {
        return timer_maker_;
    }
    [[nodiscard]] tr_dht::API& api() override
    {
        return mock_;
    }
    void add_pex(tr_sha1_digest_t const&, tr_pex const*, size_t) override
    {
    }
    void on_bep44_item(dht_bep44_item const& item) override
    {
        last_item_ = item;
        item_received_ = true;
    }

    std::string config_dir_;
    MockBep44Dht mock_;
    dht_bep44_item last_item_{};
    bool item_received_ = false;

private:
    EvTimerMaker timer_maker_;
};

} // namespace

class DhtBep44Test : public SandboxedTest
{
protected:
    void SetUp() override
    {
        SandboxedTest::SetUp();
        tr_session_thread::tr_evthread_init();
        event_base_ = event_base_new();
    }

    void TearDown() override
    {
        event_base_free(event_base_);
        event_base_ = nullptr;
        SandboxedTest::TearDown();
    }

    static auto constexpr ArbitrarySock4 = tr_socket_t{ 404 };
    static auto constexpr ArbitrarySock6 = tr_socket_t{ 418 };
    static auto constexpr ArbitraryPort = tr_port::from_host(909);

    struct event_base* event_base_ = nullptr;
};

// ── get_item forwards target and seq_known ────────────────────────────────────

TEST_F(DhtBep44Test, GetItemForwardsTargetAndSeq)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);

    auto target = tr_rand_obj<std::array<uint8_t, 20>>();
    dht->get_item(target.data(), 7LL);

    ASSERT_EQ(1U, mediator.mock_.gets_.size());
    EXPECT_EQ(target, mediator.mock_.gets_.front().target);
    EXPECT_EQ(7LL, mediator.mock_.gets_.front().seq_known);
}

TEST_F(DhtBep44Test, GetItemWithUnknownSeq)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);

    auto target = tr_rand_obj<std::array<uint8_t, 20>>();
    dht->get_item(target.data(), -1LL);

    ASSERT_EQ(1U, mediator.mock_.gets_.size());
    EXPECT_EQ(-1LL, mediator.mock_.gets_.front().seq_known);
}

// ── get_item callback propagates through mediator ─────────────────────────────

TEST_F(DhtBep44Test, GetItemCallbackReachesMediator)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    // Pre-load a synthetic item into the mock so the callback fires immediately
    mediator.mock_.item_received_ = true;
    memcpy(mediator.mock_.last_item_.v, "12:Hello World!", 15);
    mediator.mock_.last_item_.v_len = 15;
    mediator.mock_.last_item_.mutable_item = 1;
    mediator.mock_.last_item_.seq = 3;

    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);
    auto target = tr_rand_obj<std::array<uint8_t, 20>>();
    dht->get_item(target.data(), -1LL);

    EXPECT_TRUE(mediator.item_received_);
    EXPECT_EQ(15, mediator.last_item_.v_len);
    EXPECT_EQ(3LL, mediator.last_item_.seq);
}

// ── put_mutable forwards key, seq, salt_len ───────────────────────────────────

TEST_F(DhtBep44Test, PutMutableForwardsFields)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);

    auto key = tr_rand_obj<std::array<uint8_t, 32>>();
    auto sig = tr_rand_obj<std::array<uint8_t, 64>>();
    auto const v = std::string_view{ "12:Hello World!" };
    int64_t const seq = 42;

    dht->put_mutable(key.data(),
                     sig.data(),
                     nullptr,
                     0,
                     seq,
                     reinterpret_cast<uint8_t const*>(v.data()),
                     static_cast<int>(v.size()));

    ASSERT_EQ(1U, mediator.mock_.puts_.size());
    EXPECT_EQ(key, mediator.mock_.puts_.front().key);
    EXPECT_EQ(42LL, mediator.mock_.puts_.front().seq);
    EXPECT_EQ(0, mediator.mock_.puts_.front().salt_len);
    EXPECT_EQ(static_cast<int>(v.size()), mediator.mock_.puts_.front().v_len);
}

TEST_F(DhtBep44Test, PutMutableWithSaltForwardsSaltLen)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);

    auto key = tr_rand_obj<std::array<uint8_t, 32>>();
    auto sig = tr_rand_obj<std::array<uint8_t, 64>>();
    auto const salt = std::string_view{ "foobar" };
    auto const v = std::string_view{ "12:Hello World!" };

    dht->put_mutable(key.data(),
                     sig.data(),
                     reinterpret_cast<uint8_t const*>(salt.data()),
                     static_cast<int>(salt.size()),
                     1,
                     reinterpret_cast<uint8_t const*>(v.data()),
                     static_cast<int>(v.size()));

    ASSERT_EQ(1U, mediator.mock_.puts_.size());
    EXPECT_EQ(6, mediator.mock_.puts_.front().salt_len);
}

// ── Multiple sequential gets accumulate ──────────────────────────────────────

TEST_F(DhtBep44Test, MultipleGetsAccumulate)
{
    auto mediator = Bep44Mediator{ event_base_ };
    mediator.config_dir_ = sandboxDir();
    auto dht = tr_dht::create(mediator, ArbitraryPort, ArbitrarySock4, ArbitrarySock6);

    for (int i = 0; i < 5; ++i)
    {
        auto t = tr_rand_obj<std::array<uint8_t, 20>>();
        dht->get_item(t.data(), static_cast<int64_t>(i));
    }

    EXPECT_EQ(5U, mediator.mock_.gets_.size());
}

} // namespace libtransmission::test
