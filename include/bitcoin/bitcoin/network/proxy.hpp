/**
 * Copyright (c) 2011-2015 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * libbitcoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_NETWORK_PROXY_HPP
#define LIBBITCOIN_NETWORK_PROXY_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <boost/array.hpp>
#include <boost/date_time.hpp>
#include <boost/iostreams/stream.hpp>
#include <bitcoin/bitcoin/compat.hpp>
#include <bitcoin/bitcoin/config/authority.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/math/checksum.hpp>
#include <bitcoin/bitcoin/messages.hpp>
#include <bitcoin/bitcoin/network/message_subscriber.hpp>
#include <bitcoin/bitcoin/network/timeout.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/dispatcher.hpp>
#include <bitcoin/bitcoin/utility/logger.hpp>
#include <bitcoin/bitcoin/utility/deadline.hpp>
#include <bitcoin/bitcoin/utility/dispatcher.hpp>
#include <bitcoin/bitcoin/utility/subscriber.hpp>
#include <bitcoin/bitcoin/utility/threadpool.hpp>

namespace libbitcoin {
namespace network {

class BC_API proxy
  : public std::enable_shared_from_this<proxy>, track<proxy>
{
public:
    typedef std::shared_ptr<proxy> ptr;
    typedef std::function<void(const code&)> handler;
    typedef std::function<void(const code&)> stop_handler;
    typedef subscriber<const code&> stop_subscriber;

    proxy(asio::socket_ptr socket, threadpool& pool,
        const timeout& timeouts=timeout::defaults);
    ~proxy();

    /// This class is not copyable.
    proxy(const proxy&) = delete;
    void operator=(const proxy&) = delete;

    template <class Message, typename Handler>
    void send(Message&& packet, Handler&& handler)
    {
        if (stopped())
        {
            handler(error::channel_stopped);
            return;
        }

        const auto& command = packet.command;
        const auto bytes = message::serialize(std::forward<Message>(packet));
        const auto callback = std::forward<Handler>(handler);
        dispatch_.ordered(&proxy::do_send,
            shared_from_this(), bytes, callback, command);
    }

    template <class Message, typename Handler>
    void subscribe(Handler&& handler)
    {
        if (stopped())
        {
            handler(error::channel_stopped, Message());
            return;
        }

        // Subscribing must be immediate, we cannot switch thread contexts.
        message_subscriber_.subscribe<Message>(std::forward<Handler>(handler));
    }

    config::authority address() const;
    bool stopped() const;

    void start();
    void stop(const code& ec);
    void subscribe_stop(stop_handler handler);

    // TODO: move to channel.
    void reset_revival();
    void set_revival_handler(handler handler);

private:
    typedef byte_source<message::heading::buffer> heading_source;
    typedef boost::iostreams::stream<heading_source> heading_stream;

    typedef byte_source<data_chunk> payload_source;
    typedef boost::iostreams::stream<payload_source> payload_stream;

    void stop(const boost_code& ec);
    void do_stop(const code& ec);

    void start_timers();
    void clear_timers();

    void start_expiration();
    void handle_expiration(const code& ec);

    void start_inactivity();
    void handle_inactivity(const code& ec);

    void start_revival();
    void handle_revival(const code& ec);
    
    void read_heading();
    void handle_read_heading(const boost_code& ec, size_t);

    void read_payload(const message::heading& head);
    void handle_read_payload(const boost_code& ec, size_t,
        const message::heading& heading);

    void call_handle_send(const boost_code& ec, handler handler);
    void do_send(const data_chunk& message, handler handler,
        const std::string& command);

    asio::socket_ptr socket_;
    config::authority authority_;
    message::heading::buffer heading_buffer_;
    data_chunk payload_buffer_;
    dispatcher dispatch_;
    const timeout& timeouts_;
    deadline::ptr expiration_;
    deadline::ptr inactivity_;
    deadline::ptr revival_;
    handler revival_handler_;
    bool stopped_;
    message_subscriber message_subscriber_;
    stop_subscriber::ptr stop_subscriber_;
};

} // namespace network
} // namespace libbitcoin

#endif

