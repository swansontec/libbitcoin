/**
 * Copyright (c) 2011-2015 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * libbitcoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_WIF_KEYS_HPP
#define LIBBITCOIN_WIF_KEYS_HPP

#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/ec_keys.hpp>

namespace libbitcoin {
namespace wallet {

/**
 * Convert a secret parameter to the wallet import format.
 * The compressed flag can be used to show this represents a compressed key.
 * Returns an empty string on error.
 */
BC_API std::string secret_to_wif(const ec_secret& secret,
    bool compressed=true);

/**
 * Convert wallet import format key to secret parameter.
 * Returns a nulled secret on error.
 */
BC_API ec_secret wif_to_secret(const std::string& wif);

/**
 * Checks to see if a wif refers to a compressed key.
 * This does no other checks on the validity of the wif.
 * Returns false otherwise.
 */
BC_API bool is_wif_compressed(const std::string& wif);

} // namespace wallet
} // namespace libbitcoin

#endif

