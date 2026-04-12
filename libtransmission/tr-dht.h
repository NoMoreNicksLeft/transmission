// This file Copyright © Juliusz Chroboczek.
// It may be used under the MIT (SPDX: MIT) license.
// License text can be found in the licenses/ folder.

#pragma once

#ifndef __TRANSMISSION__
#error only libtransmission should #include this header.
#endif

#include <cstddef> // size_t
#include <ctime>
#include <memory>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

#include <dht/dht.h> // dht_callback_t, dht_bep44_item, dht_bep44_callback

#include "libtransmission/transmission.h"

#include "libtransmission/net.h" // tr_port
#include "libtransmission/tr-macros.h"

struct tr_pex;

namespace libtransmission
{
class TimerMaker;
} // namespace libtransmission

class tr_dht
{
public:
    // Wrapper around DHT library.
    // This calls `jech/dht` in production, but makes it possible for tests to inject a mock.
    struct API
    {
        virtual ~API() = default;

        virtual int get_nodes(struct sockaddr_in* sin, int* num, struct sockaddr_in6* sin6, int* num6)
        {
            return ::dht_get_nodes(sin, num, sin6, num6);
        }

        virtual int nodes(int af, int* good_return, int* dubious_return, int* cached_return, int* incoming_return)
        {
            return ::dht_nodes(af, good_return, dubious_return, cached_return, incoming_return);
        }

        virtual int periodic(void const* buf,
                             size_t buflen,
                             struct sockaddr const* from,
                             int fromlen,
                             time_t* tosleep,
                             dht_callback_t callback,
                             void* closure)
        {
            return ::dht_periodic(buf, buflen, from, fromlen, tosleep, callback, closure);
        }

        virtual int ping_node(struct sockaddr const* sa, int salen)
        {
            return ::dht_ping_node(sa, salen);
        }

        virtual int insert_node(unsigned char const* id, struct sockaddr* sa, int salen)
        {
            return ::dht_insert_node(id, sa, salen);
        }

        virtual int get_add_hint(unsigned char const* target, struct sockaddr const* sa, int salen)
        {
            return ::dht_get_add_hint(target, sa, salen);
        }

        virtual int search(unsigned char const* id, int port, int af, dht_callback_t callback, void* closure)
        {
            return ::dht_search(id, port, af, callback, closure);
        }

        virtual int bep44_get(unsigned char const* target, int64_t seq_known, dht_bep44_callback callback, void* closure)
        {
            return ::dht_get(target, seq_known, callback, closure);
        }

        virtual int bep44_put_mutable(unsigned char const* key,
                                      unsigned char const* sig,
                                      unsigned char const* salt,
                                      int salt_len,
                                      int64_t seq,
                                      unsigned char const* v,
                                      int v_len,
                                      dht_bep44_callback callback,
                                      void* closure)
        {
            return ::dht_put_mutable(key, sig, salt, salt_len, seq, v, v_len, callback, closure);
        }

        virtual int bep44_put_immutable(unsigned char const* v, int v_len, dht_bep44_callback callback, void* closure)
        {
            return ::dht_put_immutable(v, v_len, callback, closure);
        }

        virtual int init(int s, int s6, unsigned char const* id, unsigned char const* v)
        {
            return ::dht_init(s, s6, id, v);
        }

        virtual int uninit()
        {
            return ::dht_uninit();
        }

        virtual int get_bep44_items(struct dht_bep44_item* out, int max)
        {
            return ::dht_get_bep44_items(out, max);
        }

        virtual void set_bep44_items(struct dht_bep44_item const* in, int count)
        {
            ::dht_set_bep44_items(in, count);
        }
    };

    class Mediator
    {
    public:
        virtual ~Mediator() = default;

        [[nodiscard]] virtual std::vector<tr_torrent_id_t> torrents_allowing_dht() const = 0;
        [[nodiscard]] virtual tr_sha1_digest_t torrent_info_hash(tr_torrent_id_t) const = 0;

        [[nodiscard]] virtual std::string_view config_dir() const = 0;
        [[nodiscard]] virtual libtransmission::TimerMaker& timer_maker() = 0;
        [[nodiscard]] virtual API& api()
        {
            return api_;
        }

        virtual void add_pex(tr_sha1_digest_t const&, tr_pex const* pex, size_t n_pex) = 0;

        // Called when a BEP 44 get resolves a mutable item
        virtual void on_bep44_item(struct dht_bep44_item const& item)
        {
        }

    private:
        API api_;
    };

    [[nodiscard]] static std::unique_ptr<tr_dht> create(Mediator& mediator,
                                                        tr_port peer_port,
                                                        tr_socket_t udp4_socket,
                                                        tr_socket_t udp6_socket);
    virtual ~tr_dht() = default;

    virtual void maybe_add_node(tr_address const& address, tr_port port) = 0;
    virtual void add_hint_node(tr_address const& address, tr_port port) = 0;
    virtual void handle_message(unsigned char const* msg, size_t msglen, struct sockaddr* from, socklen_t fromlen) = 0;

    // BEP 44
    virtual void get_item(unsigned char const* target, int64_t seq_known) = 0;
    virtual void put_mutable(unsigned char const* key,
                             unsigned char const* sig,
                             unsigned char const* salt,
                             int salt_len,
                             int64_t seq,
                             unsigned char const* v,
                             int v_len) = 0;
};
