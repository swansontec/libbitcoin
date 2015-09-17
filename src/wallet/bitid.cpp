/**
 * Copyright (c) 2015 libbitcoin developers (see AUTHORS)
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
#include <bitcoin/bitcoin/wallet/bitid.hpp>

#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>
#include <bitcoin/bitcoin/utility/endian.hpp>
#include <bitcoin/bitcoin/wallet/uri.hpp>

namespace libbitcoin {
namespace wallet {

bool bitid_callback(std::string& result, const std::string& bitid_uri,
    bool strict)
{
    uri out;
    if (!out.decode(bitid_uri))
        return false;
    if ("bitid" != out.scheme() || out.has_fragment())
        return false;

    auto map = out.decode_query();
    out.remove_query();

    out.set_scheme("https");
    auto u = map.find("u");
    if (map.end() != u && u->second == "1")
        out.set_scheme("http");
    if (!out.has_authority())
        out.set_authority("");

    result = out.encode();
    return true;
}

hd_private_key bitid_derived_key(const hd_private_key& root,
    const std::string& callback_uri, uint32_t index)
{
    auto hash = sha256_hash(build_chunk({
        to_little_endian(index), to_chunk(callback_uri)
    }));

    auto a = from_little_endian<uint32_t>(hash.begin() + 0, hash.begin() + 4);
    auto b = from_little_endian<uint32_t>(hash.begin() + 4, hash.begin() + 8);
    auto c = from_little_endian<uint32_t>(hash.begin() + 8, hash.begin() + 12);
    auto d = from_little_endian<uint32_t>(hash.begin() + 12, hash.begin() + 16);

    return root.
        generate_private_key(13 | first_hardened_key).
        generate_private_key(a | first_hardened_key).
        generate_private_key(b | first_hardened_key).
        generate_private_key(c | first_hardened_key).
        generate_private_key(d | first_hardened_key);
}

} // namespace wallet
} // namespace libbitcoin
