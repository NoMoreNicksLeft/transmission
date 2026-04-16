// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#include <algorithm>
#include <array>
#include <cstring>
#include <future>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fmt/format.h>

#include "libtransmission/transmission.h"

#include "libtransmission/announce-list.h"
#include "libtransmission/btpk-publish.h"
#include "libtransmission/btpk-types.h"
#include "libtransmission/btpk-utils.h"
#include "libtransmission/error.h"
#include "libtransmission/file.h"
#include "libtransmission/log.h"
#include "libtransmission/makemeta.h"
#include "libtransmission/torrent.h"
#include "libtransmission/torrent-metainfo.h"
#include "libtransmission/utils.h"

using namespace std::literals;

void tr_torrentPublishBtpkUpdate(
    tr_torrent* tor,
    uint8_t* private_key_96,
    std::string content_path,
    tr_btpk_publish_done_func callback)
{
    if (tor == nullptr || private_key_96 == nullptr || callback == nullptr)
    {
        if (callback)
            callback({ false, {}, "Invalid arguments" });
        return;
    }

    // --- Capture torrent properties on the calling thread ---
    auto const view = tr_torrentView(tor);
    bool const is_private = view.is_private;
    auto const comment = std::string{ view.comment ? view.comment : "" };
    auto const source = std::string{ view.source ? view.source : "" };
    auto const tracker_list = tr_torrentGetTrackerList(tor);

    // btpk public key
    uint8_t pub_key[32] = {};
    if (!tr_torrentBtpkGetPublicKey(tor, pub_key))
    {
        std::memset(private_key_96, 0, 96);
        callback({ false, {}, "Torrent has no btpk public key" });
        return;
    }

    // btpk salt
    char salt_buf[256] = {};
    size_t const salt_len = tr_torrentBtpkGetSalt(tor, salt_buf, sizeof(salt_buf));
    auto const salt = std::string{ salt_buf, salt_len };

    int64_t const last_seq = tr_torrentBtpkSeq(tor);

    // Build cumulative history
    auto history = tr_torrentBtpkHistory(tor);
    {
        tr_btpk_history_entry current_entry;
        current_entry.seq = (last_seq < 0) ? 0 : last_seq;
        current_entry.infohash = tr_torrentInfoHash(tor);
        history.push_back(current_entry);
        std::sort(history.begin(), history.end(),
            [](auto const& a, auto const& b) { return a.seq < b.seq; });
    }

    // Content path
    if (content_path.empty())
    {
        auto const current_dir = std::string{ tor->current_dir() };
        auto const name = std::string{ tor->name() };
        content_path = current_dir + "/" + name;
    }

    // Copy private key for the background thread (will be zeroed after use)
    auto priv_key = std::array<uint8_t, 96>{};
    std::memcpy(priv_key.data(), private_key_96, 96);
    std::memset(private_key_96, 0, 96); // zero caller's copy immediately

    auto const tor_id = tor->id();
    auto* const session = tor->session;

    // --- Background thread: build metainfo and hash pieces ---
    std::thread([=, priv_key_copy = std::move(priv_key), hist = std::move(history)]() mutable
    {
        // Step 1: build metainfo
        auto builder = tr_metainfo_builder{ content_path };
        builder.set_private(is_private);
        if (!comment.empty())
            builder.set_comment(comment);
        if (!source.empty())
            builder.set_source(source);
        if (!tracker_list.empty())
        {
            tr_announce_list announce_list;
            announce_list.parse(tracker_list);
            builder.set_announce_list(std::move(announce_list));
        }
        {
            std::array<uint8_t, 32> pub;
            std::memcpy(pub.data(), pub_key, 32);
            builder.set_btpk_public_key(pub);
        }
        if (!salt.empty())
            builder.set_btpk_salt(salt);
        if (!hist.empty())
            builder.set_btpk_history(hist);

        // Step 2: hash pieces (slow)
        auto checksum_future = builder.make_checksums();
        auto error = checksum_future.get();
        if (error)
        {
            auto msg = fmt::format("Piece hashing failed: {}", error.message());
            std::memset(priv_key_copy.data(), 0, 96);
            session->run_in_session_thread([cb = callback, m = std::move(msg)]()
            {
                cb({ false, {}, m });
            });
            return;
        }

        // Step 3: generate bencoded metainfo
        tr_error benc_error;
        auto const benc_data = builder.benc(&benc_error);
        if (benc_data.empty())
        {
            auto msg = benc_error ? fmt::format("Benc encoding failed: {}", benc_error.message())
                                  : std::string{ "Failed to encode metainfo" };
            std::memset(priv_key_copy.data(), 0, 96);
            session->run_in_session_thread([cb = callback, m = std::move(msg)]()
            {
                cb({ false, {}, m });
            });
            return;
        }

        // Step 4: parse to get new infohash
        auto new_metainfo = tr_torrent_metainfo{};
        if (!new_metainfo.parse_benc({ benc_data.data(), benc_data.size() }))
        {
            std::memset(priv_key_copy.data(), 0, 96);
            session->run_in_session_thread([cb = callback]()
            {
                cb({ false, {}, "Failed to parse new metainfo" });
            });
            return;
        }

        // Step 5: encode BEP 46 DHT value
        auto const& new_hash = new_metainfo.info_hash();
        std::array<uint8_t, 20> hash_bytes;
        std::memcpy(hash_bytes.data(), new_hash.data(), 20);
        auto const v = libtransmission::tr_btpk_encode_v(hash_bytes);

        int64_t const new_seq = (last_seq < 0 ? 0 : last_seq) + 1;
        auto const magnet = builder.magnet_link();

        // Capture benc_data for the session thread
        auto benc_copy = std::vector<char>{ benc_data.begin(), benc_data.end() };

        // Package everything needed for the session thread into a shared struct
        struct SessionWork
        {
            tr_torrent_id_t tor_id;
            tr_session* session;
            std::array<uint8_t, 96> priv;
            std::string salt;
            int64_t new_seq;
            std::string v;
            std::vector<char> benc;
            std::string magnet;
            tr_btpk_publish_done_func cb;
        };

        auto work = std::make_shared<SessionWork>();
        work->tor_id = tor_id;
        work->session = session;
        work->priv = std::move(priv_key_copy);
        work->salt = salt;
        work->new_seq = new_seq;
        work->v = v;
        work->benc = std::move(benc_copy);
        work->magnet = magnet;
        work->cb = callback;

        // Step 6-9: sign, publish, swap metainfo — must happen on session thread
        session->run_in_session_thread([work]()
        {
            auto* tor = work->session->torrents().get(work->tor_id);
            if (tor == nullptr)
            {
                std::memset(work->priv.data(), 0, 96);
                work->cb({ false, {}, "Torrent was removed during publish" });
                return;
            }

            uint8_t pk[32] = {};
            tr_torrentBtpkGetPublicKey(tor, pk);

            // Step 6: sign and put to DHT
            bool const sign_ok = tr_torrentBtpkSignAndPut(
                tor, pk, work->priv.data(),
                work->salt.c_str(), static_cast<int>(work->salt.size()),
                work->new_seq,
                reinterpret_cast<uint8_t const*>(work->v.data()),
                static_cast<int>(work->v.size()));

            std::memset(work->priv.data(), 0, 96);

            if (!sign_ok)
            {
                work->cb({ false, {}, "Failed to sign and publish to DHT (DHT not running?)" });
                return;
            }

            // Step 7: swap metainfo
            auto parsed = tr_torrent_metainfo{};
            if (parsed.parse_benc({ work->benc.data(), work->benc.size() }))
            {
                if (!tr_torrentReplaceBtpkMetainfo(tor, std::move(parsed)))
                {
                    tr_logAddError("btpk publish: metainfo swap failed");
                }
                else
                {
                    tr_torrentSetBtpkSeq(tor, work->new_seq);

                    // Step 8: overwrite .torrent file on disk
                    auto const torrent_path = tr_torrentFilename(tor);
                    tr_error write_err;
                    tr_file_save(torrent_path,
                        std::string_view{ work->benc.data(), work->benc.size() },
                        &write_err);
                    if (write_err)
                    {
                        tr_logAddError(fmt::format(
                            "btpk publish: couldn\'t overwrite \'{}\': {}",
                            torrent_path, write_err.message()));
                    }
                }
            }

            // Step 9: return success
            work->cb({ true, work->magnet, {} });
        });
    }).detach();
}
