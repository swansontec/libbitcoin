/*
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
#ifndef LIBBITCOIN_MESSAGE_NONCE_HPP
#define LIBBITCOIN_MESSAGE_NONCE_HPP

#include <cstdint>
#include <istream>
#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/deserializer.hpp>
#include <bitcoin/bitcoin/utility/serializer.hpp>

namespace libbitcoin {
namespace message {

// TODO: Satoshi peers will might 0-length nonces as of 0.10.
// Allow the ping & pong payloads to be any size.

class BC_API nonce_base
{
public:

    nonce_base();

    nonce_base(const uint64_t nonce);

    nonce_base(std::istream& stream);

    uint64_t nonce() const;

    void nonce(uint64_t value);

    data_chunk to_data() const;

    size_t satoshi_size() const;

    static size_t satoshi_fixed_size();

private:

    uint64_t nonce_;
};

class BC_API ping : public nonce_base
{
public:

    static const std::string satoshi_command;

    ping();

    ping(std::istream& stream);

    static size_t satoshi_fixed_size();
};

class BC_API pong : public nonce_base
{
public:

    static const std::string satoshi_command;

    pong();

    pong(std::istream& stream);

    static size_t satoshi_fixed_size();
};

} // end message
} // end libbitcoin

#endif