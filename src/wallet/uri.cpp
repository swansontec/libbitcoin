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
#include <bitcoin/bitcoin/wallet/uri.hpp>

#include <cstdint>
#include <iomanip>
#include <boost/algorithm/string.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/formats/base10.hpp>
#include <bitcoin/bitcoin/formats/base16.hpp>
#include <bitcoin/bitcoin/formats/base58.hpp>
#include <bitcoin/bitcoin/wallet/stealth_address.hpp>

namespace libbitcoin {
namespace wallet {

// These character classification functions correspond to RFC 3986.
// They avoid C standard library character classification functions,
// since those give different answers based on the current locale.
static bool is_alpha(const char c)
{
    return
        ('A' <= c && c <= 'Z') ||
        ('a' <= c && c <= 'z');
}
static bool is_scheme(const char c)
{
    return
        is_alpha(c) || ('0' <= c && c <= '9') ||
        '+' == c || '-' == c || '.' == c;
}
static bool is_pchar(const char c)
{
    return
        is_alpha(c) || ('0' <= c && c <= '9') ||
        '-' == c || '.' == c || '_' == c || '~' == c || // unreserved
        '!' == c || '$' == c || '&' == c || '\'' == c ||
        '(' == c || ')' == c || '*' == c || '+' == c ||
        ',' == c || ';' == c || '=' == c || // sub-delims
        ':' == c || '@' == c;
}
static bool is_query(const char c)
{
    return is_pchar(c) || '/' == c || '?' == c;
}
static bool is_qchar(const char c)
{
    return is_query(c) && '&' != c && '=' != c;
}

/**
 * Verifies that all RFC 3986 escape sequences in a string are valid,
 * and that all characters belong to the given class.
 */
static bool validate(const std::string& in, bool (*is_valid)(const char))
{
    auto i = in.begin();
    while (in.end() != i)
    {
        if ('%' == *i)
        {
            if (!(2 < in.end() - i && is_base16(i[1]) && is_base16(i[2])))
                return false;
            i += 3;
        }
        else
        {
            if (!is_valid(*i))
                return false;
            i += 1;
        }
    }
    return true;
}

/**
 * Decodes all RFC 3986 escape sequences in a string.
 */
static std::string unescape(const std::string& in)
{
    // Do the conversion:
    std::string out;
    out.reserve(in.size());

    auto i = in.begin();
    while (in.end() != i)
    {
        if ('%' == *i &&
            2 < in.end() - i && is_base16(i[1]) && is_base16(i[2]))
        {
            const char temp[] = {i[1], i[2], 0};
            out.push_back(base16_literal(temp)[0]);
            i += 3;
        }
        else
        {
            out.push_back(*i);
            i += 1;
        }
    }
    return out;
}

bool uri::decode(const std::string& in, bool strict)
{
    auto i = in.begin();

    // Store the scheme:
    auto start = i;
    while (in.end() != i && ':' != *i)
        ++i;
    scheme_ = std::string(start, i);
    if (scheme_.empty() || !is_alpha(scheme_[0]))
        return false;
    for (auto& c: scheme_)
    {
        if (!is_scheme(c))
            return false;
        if ('A' <= c && c <= 'Z')
            c = c - 'A' + 'a';
    }

    // Consume ':':
    if (in.end() == i)
        return false;
    ++i;

    // Store the hierarchy part:
    start = i;
    while (in.end() != i && '#' != *i && '?' != *i)
        ++i;
    hierarchy_ = std::string(start, i);
    if (strict && !validate(hierarchy_, is_pchar))
        return false;

    // Consume '?':
    if (in.end() != i && '#' != *i)
    {
        has_query_ = true;
        ++i;
    }

    // Store the query part:
    start = i;
    while (in.end() != i && '#' != *i)
        ++i;
    query_ = std::string(start, i);
    if (strict && !validate(query_, is_query))
        return false;

    // Consume '#':
    if (in.end() != i)
    {
        has_fragment_ = true;
        ++i;
    }

    // Store the fragment part:
    fragment_ = std::string(i, in.end());
    if (strict && !validate(fragment_, is_query))
        return false;

    return true;
}

std::string uri::encode() const
{
    std::ostringstream out;
    out << scheme_ << ':' << hierarchy_;
    if (has_query_)
        out << '?' << query_;
    if (has_fragment_)
        out << '?' << fragment_;
    return out.str();
}

std::string uri::scheme() const
{
    return scheme_;
}

std::string uri::hierarchy() const
{
    return unescape(hierarchy_);
}

std::string uri::query() const
{
    return unescape(query_);
}

bool uri::has_query() const
{
    return has_query_;
}

void uri::set_query(const std::string& query)
{
    has_query_ = true;
    query_ = query;
}

std::string uri::fragment() const
{
    return unescape(fragment_);
}

bool uri::has_fragment() const
{
    return has_fragment_;
}

void uri::set_fragment(const std::string& fragment)
{
    has_fragment_ = true;
    fragment_ = fragment;
}

uri::query_map uri::decode_query() const
{
    query_map out;

    auto i = query_.begin();
    while (query_.end() != i)
    {
        // Read the key:
        auto begin = i;
        while (query_.end() != i && '&' != *i && '=' != *i)
            ++i;
        auto key = unescape(std::string(begin, i));

        // Consume '=':
        if (query_.end() != i && '&' != *i)
            ++i;

        // Read the value:
        begin = i;
        while (query_.end() != i && '&' != *i)
            ++i;
        out[key] = unescape(std::string(begin, i));

        // Consume '&':
        if (query_.end() != i)
            ++i;
    }

    return out;
}

void uri::encode_query(const query_map& map)
{
    bool first = true;
    std::ostringstream query;

    for (const auto& i: map)
    {
        if (!first)
            query << '&';
        first = false;

        query << i.first;
        if (!i.second.empty())
            query << '+' << i.second;
    }

    set_query(query.str());
}

bool uri_parse(const std::string& in, uri_visitor& result,
    bool strict)
{
    uri parsed;
    if (!parsed.decode(in, strict))
        return false;

    // Check the scheme:
    if (parsed.scheme() != "bitcoin")
        return false;

    // Check the address:
    auto h = parsed.hierarchy();
    if (!is_base58(h))
        return false;
    if (!h.empty() && !result.got_address(h))
        return false;

    // Check the parameters:
    auto q = parsed.decode_query();
    for (const auto& i: q)
    {
        auto key = i.first;
        auto value = i.second;
        if (!key.empty() && !result.got_param(key, value))
            return false;
    }
    return true;
}

bool uri_parse_result::got_address(std::string& address)
{
    payment_address payaddr;
    if (payaddr.from_string(address))
    {
        this->address.reset(payaddr);
        this->stealth.reset();
        return true;
    }

    stealth_address stealthaddr;
    if (stealthaddr.from_string(address))
    {
        this->stealth.reset(stealthaddr);
        this->address.reset();
        return true;
    }

    return false;
}

bool uri_parse_result::got_param(std::string& key, std::string& value)
{
    if (key == "amount")
    {
        uint64_t amount;
        if (!decode_base10(amount, value, btc_decimal_places))
            return false;
        this->amount.reset(amount);
    }
    else if (key == "label")
        label.reset(value);
    else if (key == "message")
        message.reset(value);
    else if (key == "r")
        r.reset(value);
    else if (!key.compare(0, 4, "req-"))
        return false;
    return true;
}

/**
 * Percent-encodes a string.
 * @param is_valid a function returning true for acceptable characters.
 */
static std::string escape(const std::string& in, bool (*is_valid)(char))
{
    std::ostringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (auto c: in)
    {
        if (is_valid(c))
            stream << c;
        else
            stream << '%' << std::setw(2) << +c;
    }
    return stream.str();
}

uri_writer::uri_writer()
  : first_param_{true}
{
    stream_ << "bitcoin:";
}

void uri_writer::write_address(const payment_address& address)
{
    write_address(address.to_string());
}

void uri_writer::write_address(const stealth_address& address)
{
    write_address(address.to_string());
}

void uri_writer::write_amount(uint64_t satoshis)
{
    write_param("amount", encode_base10(satoshis, btc_decimal_places));
}

void uri_writer::write_label(const std::string& label)
{
    write_param("label", label);
}

void uri_writer::write_message(const std::string& message)
{
    write_param("message", message);
}

void uri_writer::write_r(const std::string& r)
{
    write_param("r", r);
}

void uri_writer::write_address(const std::string& address)
{
    stream_ << address;
}

void uri_writer::write_param(const std::string& key,
    const std::string& value)
{
    if (first_param_)
        stream_ << '?';
    else
        stream_ << '&';
    first_param_ = false;
    stream_ << escape(key, is_qchar) << '=' << escape(value, is_qchar);
}

std::string uri_writer::string() const
{
    return stream_.str();
}

} // namespace wallet
} // namespace libbitcoin
