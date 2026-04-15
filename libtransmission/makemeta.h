// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#pragma once

#include <array>
#include <cstddef> // std::byte
#include <cstdint>
#include <future>
#include <string>
#include <string_view>
#include <utility> // std::pair
#include <vector>

#include "libtransmission/transmission.h"

#include "libtransmission/announce-list.h"
#include "libtransmission/block-info.h"
#include "libtransmission/error.h"
#include "libtransmission/file.h"
#include "libtransmission/torrent-files.h"
#include "libtransmission/btpk-types.h" // tr_btpk_history_entry
#include "libtransmission/tr-macros.h" // TR_CONSTEXPR20

class tr_metainfo_builder
{
public:
    explicit tr_metainfo_builder(std::string_view single_file_or_parent_directory);

    ~tr_metainfo_builder() = default;

    tr_metainfo_builder(tr_metainfo_builder&&) = delete;
    tr_metainfo_builder(tr_metainfo_builder const&) = delete;
    tr_metainfo_builder& operator=(tr_metainfo_builder&&) = delete;
    tr_metainfo_builder& operator=(tr_metainfo_builder const&) = delete;

    // Generate piece checksums asynchronously.
    // - This must be done before calling `benc()` or `save()`.
    // - Runs in a worker thread because it can be time-consuming.
    // - Can be cancelled with `cancelChecksums()` and polled with `checksumStatus()`
    // - Resolves with a `tr_error` which is set on failure or empty on success.
    std::future<tr_error> make_checksums()
    {
        return std::async(std::launch::async,
                          [this]()
                          {
                              auto error = tr_error{};
                              blocking_make_checksums(&error);
                              return error;
                          });
    }

    // Returns the status of a `makeChecksums()` call:
    // The current piece being tested and the total number of pieces in the torrent.
    [[nodiscard]] constexpr std::pair<tr_piece_index_t, tr_piece_index_t> checksum_status() const noexcept
    {
        return std::make_pair(checksum_piece_, block_info_.piece_count());
    }

    // Tell the `makeChecksums()` worker thread to cleanly exit ASAP.
    constexpr void cancel_checksums() noexcept
    {
        cancel_ = true;
    }

    // generate the metainfo
    [[nodiscard]] std::string benc(tr_error* error = nullptr) const;

    // generate the metainfo and save it to a torrent file
    bool save(std::string_view filename, tr_error* error = nullptr) const;

    /// setters

    void set_announce_list(tr_announce_list announce)
    {
        announce_ = std::move(announce);
    }

    // whether or not to include User-Agent and creation time
    constexpr void set_anonymize(bool anonymize) noexcept
    {
        anonymize_ = anonymize;
    }

    void set_comment(std::string_view comment)
    {
        comment_ = comment;
    }

    bool set_piece_size(uint32_t piece_size) noexcept;

    constexpr void set_private(bool is_private) noexcept
    {
        is_private_ = is_private;
    }

    void set_source(std::string_view source)
    {
        source_ = source;
    }

    void set_webseeds(std::vector<std::string> webseeds)
    {
        webseeds_ = std::move(webseeds);
    }

    // BEP 46: optional btpk public key.  When set, magnet_link() appends
    // xs=urn:btpk:<hex> so subscribers can track updates via the DHT.
    // The matching private key is never stored here — callers hold it.
    void set_btpk_public_key(std::array<uint8_t, 32> const& key)
    {
        btpk_public_key_ = key;
    }

    void set_btpk_salt(std::string_view salt)
    {
        btpk_salt_ = salt;
    }

    void set_btpk_history(std::vector<tr_btpk_history_entry> history)
    {
        btpk_history_ = std::move(history);
    }

    [[nodiscard]] auto const& btpk_history() const noexcept
    {
        return btpk_history_;
    }

    void clear_btpk()
    {
        btpk_public_key_.reset();
        btpk_salt_.clear();
        btpk_history_.clear();
    }

    [[nodiscard]] constexpr bool has_btpk() const noexcept
    {
        return btpk_public_key_.has_value();
    }

    // Returns std::optional<std::array<uint8_t,32>> — the ed25519 public key.
    [[nodiscard]] constexpr auto const& btpk_public_key() const noexcept
    {
        return btpk_public_key_;
    }

    [[nodiscard]] constexpr auto const& btpk_salt() const noexcept
    {
        return btpk_salt_;
    }

    // Return the btpk: magnet URI for this torrent.
    // Requires make_checksums() to have completed (same as benc()/save()).
    // Returns empty string on error.
    // Format: magnet:?xt=urn:btih:<hex>&dn=<name>&xs=urn:btpk:<hex>[&s=<salt>]
    [[nodiscard]] std::string magnet_link(tr_error* error = nullptr) const;

    /// getters

    [[nodiscard]] constexpr auto const& announce_list() const noexcept
    {
        return announce_;
    }

    [[nodiscard]] constexpr auto const& anonymize() const noexcept
    {
        return anonymize_;
    }

    [[nodiscard]] constexpr auto const& comment() const noexcept
    {
        return comment_;
    }

    [[nodiscard]] TR_CONSTEXPR20 auto file_count() const noexcept
    {
        return files_.file_count();
    }

    [[nodiscard]] TR_CONSTEXPR20 auto file_size(tr_file_index_t i) const noexcept
    {
        return files_.file_size(i);
    }

    [[nodiscard]] constexpr auto is_private() const noexcept
    {
        return is_private_;
    }

    [[nodiscard]] auto name() const noexcept
    {
        return tr_sys_path_basename(top_);
    }

    [[nodiscard]] auto const& path(tr_file_index_t i) const noexcept
    {
        return files_.path(i);
    }

    [[nodiscard]] constexpr auto piece_size() const noexcept
    {
        return block_info_.piece_size();
    }

    [[nodiscard]] constexpr auto piece_count() const noexcept
    {
        return block_info_.piece_count();
    }

    [[nodiscard]] constexpr auto const& source() const noexcept
    {
        return source_;
    }

    [[nodiscard]] constexpr auto const& top() const noexcept
    {
        return top_;
    }

    [[nodiscard]] constexpr auto total_size() const noexcept
    {
        return files_.total_size();
    }

    [[nodiscard]] constexpr auto const& webseeds() const noexcept
    {
        return webseeds_;
    }

    ///

    [[nodiscard]] static uint32_t default_piece_size(uint64_t total_size) noexcept;

    [[nodiscard]] constexpr static bool is_legal_piece_size(uint32_t x)
    {
        // It must be a power of two and at least 16KiB
        auto constexpr MinSize = uint32_t{ 1024U * 16U };
        auto const is_power_of_two = (x & (x - 1)) == 0;
        return x >= MinSize && is_power_of_two;
    }

private:
    bool blocking_make_checksums(tr_error* error = nullptr);

    std::string top_;
    tr_torrent_files files_;
    tr_announce_list announce_;
    tr_block_info block_info_;
    std::vector<std::byte> piece_hashes_;
    std::vector<std::string> webseeds_;

    std::string comment_;
    std::string source_;

    // BEP 46: optional btpk public key and salt
    std::optional<std::array<uint8_t, 32>> btpk_public_key_; // ed25519 public key for BEP 46
    std::string btpk_salt_;
    std::vector<tr_btpk_history_entry> btpk_history_; // prior version (seq, infohash) pairs

    tr_piece_index_t checksum_piece_ = 0;

    bool is_private_ = false;
    bool anonymize_ = false;
    bool cancel_ = false;
};
