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
#include <boost/test/unit_test.hpp>
#include <bitcoin/bitcoin.hpp>

using namespace bc;

BOOST_AUTO_TEST_SUITE(bitid_tests)

BOOST_AUTO_TEST_CASE(bitid_callback_test)
{
    const std::string path = "bitid.bitcoin.blue/callback";

    std::string result;
    BOOST_REQUIRE(wallet::bitid_callback(result, "bitid:" + path + "?x=1"));
    BOOST_REQUIRE_EQUAL(result, "https://bitid.bitcoin.blue/callback");

    BOOST_REQUIRE(wallet::bitid_callback(result, "bitid://" + path + "?x=1"));
    BOOST_REQUIRE_EQUAL(result, "https://bitid.bitcoin.blue/callback");

    BOOST_REQUIRE(wallet::bitid_callback(result, "bitid://" + path + "?x=1&u=1"));
    BOOST_REQUIRE_EQUAL(result, "http://bitid.bitcoin.blue/callback");
}

BOOST_AUTO_TEST_CASE(bitid_key_test_vector)
{
    wallet::word_list mnemonic = {
        "inhale", "praise", "target", "steak", "garlic", "cricket",
        "paper", "better", "evil", "almost", "sadness", "crawl",
        "city", "banner", "amused", "fringe", "fox", "insect",
        "roast", "aunt", "prefer", "hollow", "basic", "ladder"
    };
    auto entropy = wallet::decode_mnemonic(mnemonic);
    wallet::hd_private_key root_key(entropy);
    BOOST_REQUIRE(root_key.valid());

    auto bitid_key = wallet::bitid_derived_key(root_key,
        "http://bitid.bitcoin.blue/callback", 0);

    BOOST_REQUIRE_EQUAL(bitid_key.address().to_string(),
        "1J34vj4wowwPYafbeibZGht3zy3qERoUM1");
}

BOOST_AUTO_TEST_SUITE_END()
