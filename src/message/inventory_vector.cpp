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
#include <bitcoin/bitcoin/message/inventory_vector.hpp>
#include <bitcoin/bitcoin/utility/istream.hpp>
#include <bitcoin/bitcoin/utility/serializer.hpp>

namespace libbitcoin {
namespace message {

inventory_vector::inventory_vector()
{
}

inventory_vector::inventory_vector(inventory_type_id type,
    const hash_digest& hash)
    : type_(type), hash_(hash)
{
}

inventory_vector::inventory_vector(std::istream& stream)
{
    uint32_t raw_type = read_4_bytes(stream);
    type_ = inventory_type_from_number(raw_type);
    hash_ = read_hash(stream);

    if (stream.fail())
        throw std::ios_base::failure("inventory_vector");
}

//inventory_vector::inventory_vector(const data_chunk& value)
//: inventory_vector(value.begin(), value.end())
//{
//}

inventory_type_id inventory_vector::type() const
{
    return type_;
}

void inventory_vector::type(const inventory_type_id value)
{
    type_ = value;
}

hash_digest& inventory_vector::hash()
{
    return hash_;
}

const hash_digest& inventory_vector::hash() const
{
    return hash_;
}

void inventory_vector::hash(const hash_digest& value)
{
    hash_ = value;
}

data_chunk inventory_vector::to_data() const
{
    data_chunk result(satoshi_size());
    auto serial = make_serializer(result.begin());
    uint32_t raw_type = inventory_type_to_number(type_);
    serial.write_4_bytes(raw_type);
    serial.write_hash(hash_);
    return result;
}

size_t inventory_vector::satoshi_size() const
{
    return inventory_vector::satoshi_fixed_size();
}

size_t inventory_vector::satoshi_fixed_size()
{
    return 36;
}

} // end message
} // end libbitcoin