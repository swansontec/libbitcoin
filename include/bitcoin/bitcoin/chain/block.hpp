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
#ifndef LIBBITCOIN_CHAIN_BLOCK_HPP
#define LIBBITCOIN_CHAIN_BLOCK_HPP

#include <istream>
#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/chain/block_header.hpp>
#include <bitcoin/bitcoin/chain/transaction.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/deserializer.hpp>
#include <bitcoin/bitcoin/utility/serializer.hpp>

namespace libbitcoin {
namespace chain {

class BC_API block
{
public:

    static const std::string satoshi_command;

    block();

    block(const block_header& header, const transaction_list& transactions);

    block(std::istream& stream);

    block_header& header();

    const block_header& header() const;

    void header(const block_header& header);

    transaction_list& transactions();

    const transaction_list& transactions() const;

    data_chunk to_data() const;

    size_t satoshi_size() const;

    static hash_digest generate_merkle_root(
        const transaction_list& transactions);

private:

    block_header header_;
    transaction_list transactions_;
};

// A list of indices. Used for creating block_locator objects or
// storing list of unconfirmed input indexes in tx pool.
typedef std::vector<size_t> index_list;

} // end chain
} // end libbitcoin

#endif