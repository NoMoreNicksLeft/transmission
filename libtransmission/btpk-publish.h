// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#pragma once

#include <cstdint>
#include <functional>
#include <string>

struct tr_torrent;

// Result of a btpk publish operation
struct tr_btpk_publish_result
{
    bool success = false;
    std::string magnet_link;  // the btpk: magnet URI on success
    std::string error_message; // human-readable error on failure
};

// Callback invoked when publish completes (on the session thread).
using tr_btpk_publish_done_func = std::function<void(tr_btpk_publish_result const&)>;

// Publish a btpk update for the given torrent.
//
// This is the canonical publish flow, usable by all platforms:
//   1. Builds new metainfo from the torrent's content path
//   2. Hashes all pieces (slow — runs on a background thread)
//   3. Signs the new infohash with the provided private key
//   4. Publishes the signed value to DHT (BEP 44 mutable put)
//   5. Swaps the torrent's metainfo to the new version
//   6. Overwrites the .torrent file on disk
//   7. Invokes the callback with the result
//
// private_key_96: 96-byte ed25519 private key (nightcracker format:
//   [64-byte expanded private key | 32-byte public key]).
//   The key is zeroed after use.
//
// The callback is invoked on the calling thread (via the session's
// run_in_session_thread mechanism for thread safety).
//
// The content_path should be the torrent's current data location
// (the folder or file on disk). If empty, it is derived from the torrent.
void tr_torrentPublishBtpkUpdate(
    tr_torrent* tor,
    uint8_t* private_key_96,
    std::string content_path,
    tr_btpk_publish_done_func callback);
