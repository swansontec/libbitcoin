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
#ifndef LIBBITCOIN_WALLET_BITID_HPP
#define LIBBITCOIN_WALLET_BITID_HPP

#include <cstdint>
#include <string>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/wallet/hd_keys.hpp>

namespace libbitcoin {
namespace wallet {

/**
 * Extracts the callback URI from a bitid URI.
 */
BC_API bool bitid_callback(std::string& result, const std::string& bitid_uri,
    bool strict=true);

/**
 * Derive a key for signing bitid messages.
 * Uses the standard key derivation path given in the BIP proposal.
 * @param index allows the user to have multiple keys per domain.
 */
BC_API hd_private_key bitid_derived_key(const hd_private_key& root,
    const std::string& callback_uri, uint32_t index=0);

} // namespace wallet
} // namespace libbitcoin

#endif
