// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#pragma once

#ifndef __TRANSMISSION__
#error only libtransmission should #include this header.
#endif

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <dht/dht.h> // dht_bep44_item, DHT_BEP44_KEY_LEN

#include "libtransmission/tr-macros.h" // tr_sha1_digest_t

namespace libtransmission
{

// Resolves a BEP 46 mutable torrent subscription (a btpk: public key + optional salt)
// to a series of infohashes via the DHT BEP 44 get mechanism.
//
// Lifecycle:
//   1. Caller constructs with key, optional salt, and an infohash callback.
//   2. Caller calls target() to get the 20-byte DHT target for the initial get.
//   3. As DHT responses arrive, caller feeds them to on_dht_item().
//   4. When a valid, newer item is found, the callback fires with the new infohash.
//   5. resolve() should be re-issued periodically (~15 min) to poll for updates.
class tr_mutable_resolver
{
public:
    using InfohashCallback = std::function<void(tr_sha1_digest_t const& info_hash)>;

    // key must be exactly DHT_BEP44_KEY_LEN (32) bytes.
    tr_mutable_resolver(std::array<uint8_t, DHT_BEP44_KEY_LEN> const& key, std::string_view salt, InfohashCallback on_infohash);

    // Returns the 20-byte SHA-1 BEP 44 target = SHA1(key || salt).
    [[nodiscard]] std::array<uint8_t, 20> const& target() const noexcept
    {
        return target_;
    }

    // Returns the last known sequence number (-1 = none seen yet).
    [[nodiscard]] int64_t last_seq() const noexcept
    {
        return last_seq_;
    }

    // Feed an incoming BEP 44 DHT item to this resolver.
    // Verifies signature, checks seq, decodes infohash, fires callback on change.
    // Returns true if the item was accepted (valid, newer, well-formed).
    bool on_dht_item(dht_bep44_item const& item);

private:
    std::array<uint8_t, DHT_BEP44_KEY_LEN> key_;
    std::string salt_;
    std::array<uint8_t, 20> target_;
    int64_t last_seq_ = -1;
    std::optional<tr_sha1_digest_t> last_infohash_;
    InfohashCallback on_infohash_;

    void compute_target();

    // Builds the BEP 44 signing buffer: [4:saltN:<salt>]3:seqi<seq>e1:v<vlen>:<v>
    // Returns the number of bytes written, or -1 on error.
    static int build_signing_buf(uint8_t const* salt,
                                 int salt_len,
                                 int64_t seq,
                                 uint8_t const* v,
                                 int v_len,
                                 char* buf,
                                 int bufmax);

    // Decodes BEP 46 value d1:ih20:<bytes>e and extracts the 20-byte infohash.
    static std::optional<tr_sha1_digest_t> decode_v(uint8_t const* v, int v_len);
};

} // namespace libtransmission
