// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#pragma once

#include <array>
#include <cstddef> // size_t
#include <cstdint> // uint8_t
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "libtransmission/announce-list.h"
#include "libtransmission/crypto-utils.h"
#include "libtransmission/tr-macros.h" // TR_CONSTEXPR20, tr_sha1_digest_t

struct tr_error;

class tr_magnet_metainfo
{
    friend struct MetainfoHandler;

public:
    bool parseMagnet(std::string_view magnet_link, tr_error* error = nullptr);

    [[nodiscard]] std::string magnet() const;

    [[nodiscard]] constexpr auto const& info_hash() const noexcept
    {
        return info_hash_;
    }

    [[nodiscard]] constexpr auto const& name() const noexcept
    {
        return name_;
    }

    [[nodiscard]] TR_CONSTEXPR20 auto webseed_count() const noexcept
    {
        return std::size(webseed_urls_);
    }

    [[nodiscard]] TR_CONSTEXPR20 auto const& webseed(size_t i) const
    {
        return webseed_urls_.at(i);
    }

    [[nodiscard]] constexpr auto& announce_list() noexcept
    {
        return announce_list_;
    }

    [[nodiscard]] constexpr auto const& announce_list() const noexcept
    {
        return announce_list_;
    }

    [[nodiscard]] constexpr auto const& info_hash_string() const noexcept
    {
        return info_hash_str_;
    }

    [[nodiscard]] constexpr auto const& info_hash2_string() const noexcept
    {
        return info_hash2_str_;
    }

    void set_name(std::string_view name);

    void add_webseed(std::string_view webseed);

    // BEP 46: update the parsed infohash (used when mutable DHT resolves a new version).
    void set_info_hash(tr_sha1_digest_t const& hash)
    {
        info_hash_ = hash;
        info_hash_str_ = tr_sha1_to_string(hash);
    }

    // BEP 46: mutable torrent public key (32 bytes) and optional salt.
    // Present when the magnet URI contains an xs=urn:btpk:<hex-key> parameter.
    static constexpr size_t BtpkKeyLen = 32U;
    using BtpkKey = std::array<uint8_t, BtpkKeyLen>;

    [[nodiscard]] bool has_btpk() const noexcept
    {
        return btpk_key_.has_value();
    }

    [[nodiscard]] std::optional<BtpkKey> const& btpk_key() const noexcept
    {
        return btpk_key_;
    }

    [[nodiscard]] std::string const& btpk_salt() const noexcept
    {
        return btpk_salt_;
    }

    void set_btpk(BtpkKey const& key, std::string_view salt = {})
    {
        btpk_key_ = key;
        btpk_salt_ = salt;
    }

protected:
    tr_announce_list announce_list_;
    std::vector<std::string> webseed_urls_;
    tr_sha1_digest_t info_hash_ = {};
    tr_sha256_digest_t info_hash2_ = {};
    tr_sha1_string info_hash_str_;
    tr_sha256_string info_hash2_str_;
    std::string name_;

    // BEP 46 mutable torrent key (xs=urn:btpk:)
    std::optional<BtpkKey> btpk_key_;
    std::string btpk_salt_;
};
