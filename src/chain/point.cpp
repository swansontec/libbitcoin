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
#include <bitcoin/bitcoin/chain/point.hpp>

#include <sstream>
#include <boost/iostreams/stream.hpp>
#include <bitcoin/bitcoin/constants.hpp>
#include <bitcoin/bitcoin/formats/base16.hpp>
#include <bitcoin/bitcoin/utility/container_sink.hpp>
#include <bitcoin/bitcoin/utility/container_source.hpp>
#include <bitcoin/bitcoin/utility/istream_reader.hpp>
#include <bitcoin/bitcoin/utility/ostream_writer.hpp>

namespace libbitcoin {
namespace chain {

point point::factory_from_data(const data_chunk& data)
{
    point instance;
    instance.from_data(data);
    return instance;
}

point point::factory_from_data(std::istream& stream)
{
    point instance;
    instance.from_data(stream);
    return instance;
}

point point::factory_from_data(reader& source)
{
    point instance;
    instance.from_data(source);
    return instance;
}

bool point::is_valid() const
{
    return (index != 0) || (hash != null_hash);
}

void point::reset()
{
    hash.fill(0);
    index = 0;
}

bool point::from_data(const data_chunk& data)
{
    data_source istream(data);
    return from_data(istream);
}

bool point::from_data(std::istream& stream)
{
    istream_reader source(stream);
    return from_data(source);
}

bool point::from_data(reader& source)
{
    auto result = true;
    reset();
    hash = source.read_hash();
    index = source.read_4_bytes_little_endian();
    result = source;
    if (!result)
        reset();

    return result;
}

data_chunk point::to_data() const
{
    data_chunk data;
    data_sink ostream(data);
    to_data(ostream);
    ostream.flush();
    BITCOIN_ASSERT(data.size() == serialized_size());
    return data;
}

void point::to_data(std::ostream& stream) const
{
    ostream_writer sink(stream);
    to_data(sink);
}

void point::to_data(writer& sink) const
{
    sink.write_hash(hash);
    sink.write_4_bytes_little_endian(index);
}

uint64_t point::serialized_size() const
{
    return point::satoshi_fixed_size();
}

uint64_t point::satoshi_fixed_size()
{
    return hash_size + 4;
}

std::string point::to_string() const
{
    std::ostringstream value;
    value << "\thash = " << encode_hash(hash) << "\n" << "\tindex = " << index;
    return value.str();
}

bool point::is_null() const
{
    return (index == max_input_sequence) && (hash == null_hash);
}

bool operator==(const point& left, const point& right)
{
    return left.hash == right.hash && left.index == right.index;
}

bool operator!=(const point& left, const point& right)
{
    return !(left == right);
}

} // namspace chain
} // namspace libbitcoin
