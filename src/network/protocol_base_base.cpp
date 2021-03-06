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
#include <bitcoin/bitcoin/network/protocol_base_base.hpp>

#include <functional>
#include <memory>
#include <string>
#include <bitcoin/bitcoin/config/authority.hpp>
#include <bitcoin/bitcoin/error.hpp>
#include <bitcoin/bitcoin/network/asio.hpp>
#include <bitcoin/bitcoin/network/channel.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>
#include <bitcoin/bitcoin/utility/deadline.hpp>
#include <bitcoin/bitcoin/utility/dispatcher.hpp>
#include <bitcoin/bitcoin/utility/threadpool.hpp>

namespace libbitcoin {
namespace network {

using std::placeholders::_1;

protocol_base_base::protocol_base_base(channel::ptr channel, threadpool& pool,
    const std::string& name, handler complete)
  : channel_(channel),
    dispatch_(pool),
    name_(name),
    callback_(complete),
    stopped_(false)
{
    start_ = [this]()
    {
        subscribe_stop();
    };
}

protocol_base_base::protocol_base_base(channel::ptr channel, threadpool& pool,
    const asio::duration& timeout, const std::string& name, handler complete)
  : protocol_base_base(channel, pool, name, complete)
{
    start_ = [this, &pool, &timeout]()
    {
        subscribe_timer(pool, timeout);
    };
}

config::authority protocol_base_base::authority() const
{
    return channel_->address();
}

// If an error code is passed to the callback the channel is also stopped.
void protocol_base_base::callback(const code& ec) const
{
    if (callback_ != nullptr)
        callback_(ec);
}

// This must only be called from start() and before any subscriptions.
// Ideally avoid this, but it works around no self-closure in construct.
void protocol_base_base::set_callback(handler complete)
{
    BITCOIN_ASSERT_MSG(callback_ == nullptr, "The callback cannot be reset.");
    if (callback_ == nullptr)
        callback_ = complete;
}

void protocol_base_base::set_identifier(uint64_t value)
{
    channel_->set_identifier(value);
}

// Startup is deferred until after construct in order to use shared_from_this.
// We could simplify this by using boost::enable_shared_from_this which can be
// called from construct, but that requires use of boost::share_ptr as well.
void protocol_base_base::start()
{
    BITCOIN_ASSERT_MSG(start_ != nullptr, "The protocol cannot be restarted.");
    if (start_ == nullptr)
        return;

    start_();
    start_ = nullptr;
}

void protocol_base_base::stop(const code& ec)
{
    if (!stopped())
        channel_->stop(ec);
}

bool protocol_base_base::stopped() const
{
    return stopped_;
}

void protocol_base_base::subscribe_stop()
{
    channel_->subscribe_stop(
        std::bind(&protocol_base_base::handle_stop,
            shared_from_this(), _1));
}

void protocol_base_base::subscribe_timer(threadpool& pool,
    const asio::duration& timeout)
{
    deadline_ = std::make_shared<deadline>(pool, timeout);
    deadline_->start(
        std::bind(&protocol_base_base::handle_timer,
            shared_from_this(), _1));
}
    
void protocol_base_base::handle_stop(const code& ec)
{
    if (stopped())
        return;

    log_debug(LOG_PROTOCOL)
        << "Stopped " << name_ << " protocol on [" << authority() << "] "
        << ec.message();

    stopped_ = true;
    if (deadline_)
        deadline_->cancel();

    callback(ec);
}

void protocol_base_base::handle_timer(const code& ec)
{
    if (stopped() || deadline::canceled(ec))
        return;

    log_debug(LOG_PROTOCOL)
        << "Fired " << name_ << " protocol timer on [" << authority() << "] "
        << ec.message();

    callback(error::channel_timeout);
}

} // namespace network
} // namespace libbitcoin
