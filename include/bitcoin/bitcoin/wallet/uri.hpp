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
#ifndef LIBBITCOIN_WALLET_URI_HPP
#define LIBBITCOIN_WALLET_URI_HPP

#include <cstdint>
#include <string>
#include <sstream>
#include <boost/optional.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/wallet/payment_address.hpp>
#include <bitcoin/bitcoin/wallet/stealth_address.hpp>

namespace libbitcoin {
namespace wallet {

/**
 * A parsed URI according to RFC 3986.
 */
class BC_API uri
{
public:
    /**
     * Decodes a URI from a string.
     * @param strict Set to false to tolerate unescaped special characters.
     */
    bool decode(const std::string& in, bool strict=true);
    std::string encode() const;

    /**
     * Returns the lowercased URI scheme, such as `bitcoin`
     */
    std::string scheme() const;
    void set_scheme(const std::string& scheme);

    /**
     * Returns the unescaped URI hierarchical part (hostname + path).
     */
    std::string hierarchy() const;

    /**
     * Returns the complete unescaped query string, if any.
     */
    std::string query() const;
    bool has_query() const;
    void set_query(const std::string& query);

    /**
     * Returns the complete unescaped fragment string, if any.
     */
    std::string fragment() const;
    bool has_fragment() const;
    void set_fragment(const std::string& fragment);

    typedef std::map<std::string, std::string> query_map;

    /**
     * Interprets the query string as a sequence of key-value pairs.
     * All query strings are valid, so this function cannot fail.
     * The results are unescaped. Both keys and values can be zero-length,
     * and if the same key is appears multiple times, the final one wins.
     */
    query_map decode_query() const;
    void encode_query(const query_map& map);

private:
    // All parts are stored escaped:
    std::string scheme_;
    std::string hierarchy_;
    std::string query_;
    std::string fragment_;

    bool has_query_ = false;
    bool has_fragment_ = false;
};

/**
 * The URI parser calls these methods each time it extracts a URI component.
 */
class BC_API uri_visitor
{
public:
    virtual bool got_address(std::string& address) = 0;
    virtual bool got_param(std::string& key, std::string& value) = 0;
};

/**
 * A decoded bitcoin URI corresponding to BIP 21 and BIP 72.
 * All string members are UTF-8.
 */
class BC_API uri_parse_result
  : public uri_visitor
{
public:
    typedef boost::optional<payment_address> optional_address;
    typedef boost::optional<stealth_address> optional_stealth;
    typedef boost::optional<uint64_t> optional_amount;
    typedef boost::optional<std::string> optional_string;

    optional_address address;
    optional_stealth stealth;
    optional_amount amount;
    optional_string label;
    optional_string message;
    optional_string r;

    bool got_address(std::string& address);
    bool got_param(std::string& key, std::string& value);
};

/**
 * Parses a URI string into its individual components.
 * @param strict Only accept properly-escaped parameters. Some bitcoin
 * software does not properly escape URI parameters, and setting strict to
 * false allows these malformed URI's to parse anyhow.
 * @return false if the URI is malformed.
 */
BC_API bool uri_parse(const std::string& in,
    uri_visitor& result, bool strict=true);

/**
 * Assembles a bitcoin URI string.
 */
class uri_writer
{
public:
    BC_API uri_writer();

    // Formatted:
    BC_API void write_address(const payment_address& address);
    BC_API void write_address(const stealth_address& stealth);
    BC_API void write_amount(uint64_t satoshis);
    BC_API void write_label(const std::string& label);
    BC_API void write_message(const std::string& message);
    BC_API void write_r(const std::string& r);

    // Raw:
    BC_API void write_address(const std::string& address);
    BC_API void write_param(const std::string& key, const std::string& value);

    BC_API std::string string() const;

private:
    std::ostringstream stream_;
    bool first_param_;
};

} // namespace wallet
} // namespace libbitcoin

#endif
