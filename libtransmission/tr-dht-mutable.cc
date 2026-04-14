// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#include <cinttypes> // PRId64
#include <cstdio> // snprintf
#include <cstring> // std::memcmp, std::memcpy
#include <optional>
#include <string_view>

#include <dht/dht.h> // dht_bep44_item, DHT_BEP44_KEY_LEN

#include "libtransmission/crypto-utils.h" // tr_sha1, tr_sha1_digest_t, tr_ed25519_verify
#include "libtransmission/quark.h" // TR_KEY_ih
#include "libtransmission/tr-dht-mutable.h"
#include "libtransmission/variant.h" // tr_variant_serde, tr_variantDictFindRaw

namespace libtransmission
{

// ---------------------------------------------------------------------------
// Construction

tr_mutable_resolver::tr_mutable_resolver(std::array<uint8_t, DHT_BEP44_KEY_LEN> const& key,
                                         std::string_view salt,
                                         InfohashCallback on_infohash)
    : key_{ key }
    , salt_{ salt }
    , on_infohash_{ std::move(on_infohash) }
{
    compute_target();
}

// ---------------------------------------------------------------------------
// target = SHA1(key || salt)  [BEP 44 §5]

void tr_mutable_resolver::compute_target()
{
    auto ctx = tr_sha1{};
    ctx.add(key_.data(), key_.size());
    if (!salt_.empty())
    {
        ctx.add(salt_.data(), salt_.size());
    }
    auto const digest = ctx.finish();
    static_assert(sizeof(digest) == 20);
    std::memcpy(target_.data(), digest.data(), 20);
}

// ---------------------------------------------------------------------------
// Build BEP 44 signing buffer: [4:saltN:<salt>]3:seqi<seq>e1:v<vlen>:<v>
// Mirrors the static bep44_signing_buf() in dht.c.

int tr_mutable_resolver::build_signing_buf(uint8_t const* salt,
                                           int const salt_len,
                                           int64_t const seq,
                                           uint8_t const* v,
                                           int const v_len,
                                           char* buf,
                                           int const bufmax)
{
    int i = 0;

    if (salt != nullptr && salt_len > 0)
    {
        int rc = snprintf(buf + i, bufmax - i, "4:salt%d:", salt_len);
        if (rc < 0 || rc >= bufmax - i)
        {
            return -1;
        }
        i += rc;
        if (i + salt_len >= bufmax)
        {
            return -1;
        }
        std::memcpy(buf + i, salt, salt_len);
        i += salt_len;
    }

    {
        int rc = snprintf(buf + i, bufmax - i, "3:seqi%" PRId64 "e1:v%d:", seq, v_len);
        if (rc < 0 || rc >= bufmax - i)
        {
            return -1;
        }
        i += rc;
    }

    if (i + v_len >= bufmax)
    {
        return -1;
    }
    std::memcpy(buf + i, v, v_len);
    i += v_len;

    return i;
}

// ---------------------------------------------------------------------------
// Decode BEP 46 value: bencoded d1:ih20:<bytes>e → 20-byte infohash

std::optional<tr_sha1_digest_t> tr_mutable_resolver::decode_v(uint8_t const* v, int const v_len)
{
    if (v == nullptr || v_len <= 0)
    {
        return std::nullopt;
    }

    auto const sv = std::string_view{ reinterpret_cast<char const*>(v), static_cast<size_t>(v_len) };
    auto var = tr_variant_serde::benc().parse(sv);
    if (!var)
    {
        return std::nullopt;
    }

    std::byte const* raw = nullptr;
    size_t raw_len = 0;
    if (!tr_variantDictFindRaw(&*var, TR_KEY_ih, &raw, &raw_len) || raw_len != 20)
    {
        return std::nullopt;
    }

    tr_sha1_digest_t digest;
    std::memcpy(digest.data(), raw, 20);
    return digest;
}

// ---------------------------------------------------------------------------
// on_dht_item: verify → check seq → decode → callback

bool tr_mutable_resolver::on_dht_item(dht_bep44_item const& item)
{
    auto dbg = [&](char const* reason) {
    };
    // Must be a mutable item
    if (!item.mutable_item)
    {
        dbg("not mutable"); return false;
    }

    // Target must match what we are resolving
    if (std::memcmp(item.target, target_.data(), 20) != 0)
    {
        dbg("target mismatch"); return false;
    }

    // Reject stale or same sequence numbers
    if (item.seq <= last_seq_)
    {
        dbg("stale seq"); return false;
    }

    // Build the signing buffer and verify the ed25519 signature (BEP 44 §5).
    // Buffer format: [4:saltN:<salt>]3:seqi<seq>e1:v<vlen>:<v>
    char sign_buf[1100]; // DHT_BEP44_VALUE_MAX (1000) + overhead
    int const sign_len = build_signing_buf(item.salt_len > 0 ? item.salt : nullptr,
                                           item.salt_len,
                                           item.seq,
                                           item.v,
                                           item.v_len,
                                           sign_buf,
                                           static_cast<int>(sizeof(sign_buf)));
    if (sign_len <= 0)
    {
        return false;
    }

    {
        bool const verify_ok = tr_ed25519_verify(item.sig,
                                                 reinterpret_cast<uint8_t const*>(sign_buf),
                                                 static_cast<size_t>(sign_len),
                                                 item.key);
        if (!verify_ok)
        {
            dbg("sig verify"); return false;
        }
    }

    // Decode the bencoded value to extract the infohash
    auto const maybe_hash = decode_v(item.v, item.v_len);
    if (!maybe_hash)
    {
        dbg("decode_v"); return false;
    }

    // Accept: update state
    last_seq_ = item.seq;

    // Fire callback only when the infohash actually changes (or on first resolution)
    if (last_infohash_ != maybe_hash)
    {
        last_infohash_ = maybe_hash;
        on_infohash_(*maybe_hash, item.seq);
    }

    return true;
}

} // namespace libtransmission
