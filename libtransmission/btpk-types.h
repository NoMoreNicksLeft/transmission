// This file Copyright © Transmission authors and contributors.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#pragma once

#include <cstdint>

#include "libtransmission/tr-macros.h" // tr_sha1_digest_t

// One entry in the btpk version history embedded in a torrent's info dict.
// Allows any subscriber to discover and re-seed older versions by infohash,
// without out-of-band communication.
struct tr_btpk_history_entry
{
    int64_t seq = 0;
    tr_sha1_digest_t infohash = {};
};
