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
#include <bitcoin/bitcoin/wallet/encrypted_keys.hpp>

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <stdexcept>
#include <boost/locale.hpp>
#include <bitcoin/bitcoin/define.hpp>
#include <bitcoin/bitcoin/math/checksum.hpp>
#include <bitcoin/bitcoin/math/crypto.hpp>
#include <bitcoin/bitcoin/math/hash.hpp>
#include <bitcoin/bitcoin/math/ec_keys.hpp>
#include <bitcoin/bitcoin/unicode/unicode.hpp>
#include <bitcoin/bitcoin/utility/assert.hpp>
#include <bitcoin/bitcoin/utility/data.hpp>
#include <bitcoin/bitcoin/utility/endian.hpp>
#include "parse_encrypted_keys/parse_ek_key.hpp"
#include "parse_encrypted_keys/parse_ek_prefix.hpp"
#include "parse_encrypted_keys/parse_ek_private.hpp"
#include "parse_encrypted_keys/parse_ek_public.hpp"
#include "parse_encrypted_keys/parse_ek_token.hpp"

namespace libbitcoin {
namespace wallet {
    
// Alias commonly-used constants for brevity.
static constexpr auto half = half_hash_size;
static constexpr auto quarter = quarter_hash_size;

// Ensure that hash sizes are aligned with AES block size.
static_assert(2 * quarter == bc::aes256_block_size, "oops!");

// address_
// ----------------------------------------------------------------------------

static hash_digest address_hash(uint8_t version, const ec_point& point)
{
    const payment_address address(version, point);
    return bitcoin_hash(to_chunk(address.to_string()));
}

static ek_salt address_salt(uint8_t version, const ec_point& point)
{
    return slice<0, ek_salt_size>(address_hash(version, point));
}

static bool address_validate(const ec_point& point, const ek_salt& salt,
    uint8_t version, bool compressed)
{
    const auto hash = address_hash(version, point);
    return std::equal(hash.begin(), hash.begin() + salt.size(), salt.begin());
}

static bool address_validate(const ec_secret& secret, const ek_salt& salt,
    uint8_t version, bool compressed)
{
    const auto point = secret_to_public_key(secret, compressed);
    return address_validate(point, salt, version, compressed);
}

// point_
// ----------------------------------------------------------------------------

static hash_digest point_hash(const ec_point& compressed_point)
{
    static constexpr size_t compressed_size = 1 + hash_size;
    BITCOIN_ASSERT(compressed_point.size() == compressed_size);
    const auto point_array = to_array<compressed_size>(compressed_point);
    return slice<1, compressed_size>(point_array);
}

static one_byte point_sign(uint8_t byte, const hash_digest& hash)
{
    static constexpr uint8_t low_bit_mask = 0x01;
    const uint8_t last_byte = hash[hash_size - 1];
    const uint8_t last_byte_odd_field = last_byte & low_bit_mask;
    const uint8_t sign_byte = byte ^ last_byte_odd_field;
    return to_array(sign_byte);
}

static one_byte point_sign(const one_byte& single, const hash_digest& hash)
{
    return point_sign(single.front(), hash);
}

static ec_point point_factory(const one_byte& sign, const hash_digest& hash)
{
    return build_chunk({ sign, hash });
}

// scrypt_
// ----------------------------------------------------------------------------

static hash_digest scrypt_token(data_slice data, data_slice salt)
{
    // Arbitrary scrypt parameters from BIP-38.
    return scrypt<hash_size>(data, salt, 16384u, 8u, 8u);
}

static long_hash scrypt_pair(data_slice data, data_slice salt)
{
    // Arbitrary scrypt parameters from BIP-38.
    return scrypt<long_hash_size>(data, salt, 1024u, 1u, 1u);
}

static long_hash scrypt_private(data_slice data, data_slice salt)
{
    // Arbitrary scrypt parameters from BIP-38.
    return scrypt<long_hash_size>(data, salt, 16384u, 8u, 8u);
}

// set_flags
// ----------------------------------------------------------------------------

static one_byte set_flags(bool compressed, bool lot_sequence, bool multiplied)
{
    uint8_t byte = ek_flag::none;

    if (compressed)
        byte |= ek_flag::ec_compressed;

    if (lot_sequence)
        byte |= ek_flag::lot_sequence;

    if (!multiplied)
        byte |= ek_flag::ec_non_multiplied;

    return to_array(byte);
}

static one_byte set_flags(bool compressed, bool lot_sequence)
{
    return set_flags(compressed, lot_sequence, false);
}

static one_byte set_flags(bool compressed)
{
    return set_flags(compressed, false);
}

// create_key_pair
// ----------------------------------------------------------------------------

static void create_private_key(ek_private& out_private, const one_byte& flags,
    const ek_salt& salt, const ek_entropy& entropy,
    const hash_digest& derived1, const hash_digest& derived2,
    const ek_seed& seed, uint8_t version)
{
    const auto prefix = parse_ek_private::prefix_factory(version, true);

    auto encrypt1 = xor_data<half>(seed, derived1);
    aes256_encrypt(derived2, encrypt1);
    const auto combined = splice(slice<quarter, half>(encrypt1),
        slice<half, half + quarter>(seed));

    auto encrypt2 = xor_data<half>(combined, derived1, 0, half);
    aes256_encrypt(derived2, encrypt2);
    const auto quarter1 = slice<0, quarter>(encrypt1);

    build_checked_array(out_private,
    {
        prefix,
        flags,
        salt,
        entropy,
        quarter1,
        encrypt2
    });
}

static void create_public_key(ek_public& out_public, const one_byte& flags,
    const ek_salt& salt, const ek_entropy& entropy,
    const hash_digest& derived1, const hash_digest& derived2,
    const ec_secret& secret, uint8_t version)
{
    const auto prefix = parse_ek_public::prefix_factory(version);
    const auto point = secret_to_public_key(secret, true);
    const auto hash = point_hash(point);

    auto encrypted1 = xor_data<half>(hash, derived1);
    aes256_encrypt(derived2, encrypted1);

    auto encrypted2 = xor_data<half>(hash, derived1, half);
    aes256_encrypt(derived2, encrypted2);

    const auto sign = point_sign(point.front(), derived2);

    build_checked_array(out_public,
    {
        prefix,
        flags,
        salt,
        entropy,
        sign,
        encrypted1,
        encrypted2
    });
}

// There is no scenario requiring a public key, we support it for completeness.
bool create_key_pair(ek_private& out_private, ek_public& out_public,
    ec_point& out_point, const ek_token& token, const ek_seed& seed,
    uint8_t version, bool compressed)
{
    const parse_ek_token parse(token);
    if (!parse.valid())
        return false;

    const auto point = point_factory(parse.sign(), parse.data());
    out_point = point;
    const auto factor = bitcoin_hash(seed);
    ec_multiply(out_point, factor);

    if (!compressed)
        out_point = decompress_public_key(out_point);

    const auto salt = address_salt(version, out_point);
    const auto salt_entropy = splice(salt, parse.entropy());
    const auto derived = split(scrypt_pair(point, salt_entropy));
    const auto flags = set_flags(compressed, parse.lot_sequence(), true);

    create_private_key(out_private, flags, salt, parse.entropy(), derived.left,
        derived.right, seed, version);
    create_public_key(out_public, flags, salt, parse.entropy(), derived.left,
        derived.right, factor, version);

    return true;
}

bool create_key_pair(ek_private& out_private, ec_point& out_point,
    const ek_token& token, const ek_seed& seed, uint8_t version,
    bool compressed)
{
    ek_public out_public;
    return create_key_pair(out_private, out_public, out_point, token, seed,
        version, compressed);
}

#ifdef WITH_ICU

// create_token
// ----------------------------------------------------------------------------

// This call requires an ICU build, the other excluded calls are dependencies.
static data_chunk normal(const std::string& passphrase)
{
    return to_chunk(to_normal_nfc_form(passphrase));
}

static void create_token(ek_token& out_token, const std::string& passphrase,
    data_slice owner_salt, const ek_entropy& owner_entropy,
    const byte_array<parse_ek_token::prefix_size>& prefix)
{
    BITCOIN_ASSERT(owner_salt.size() == ek_salt_size ||
        owner_salt.size() == ek_entropy_size);

    const auto lot_sequence = owner_salt.size() == ek_salt_size;
    auto factor = scrypt_token(normal(passphrase), owner_salt);

    if (lot_sequence)
        factor = bitcoin_hash(splice(factor, owner_entropy));

    const auto point = secret_to_public_key(factor, true);

    build_checked_array(out_token,
    {
        prefix,
        owner_entropy,
        point
    });
}

// The salt here is owner-supplied random bits, not the address hash.
void create_token(ek_token& out_token, const std::string& passphrase,
    const ek_entropy& entropy)
{
    // BIP38: If lot and sequence numbers are not being included, then
    // owner_salt is 8 random bytes instead of 4, lot_sequence is omitted and
    // owner_entropy becomes an alias for owner_salt.
    const auto prefix = parse_ek_token::prefix_factory(false);
    create_token(out_token, passphrase, entropy, entropy, prefix);
}

// The salt here is owner-supplied random bits, not the address hash.
bool create_token(ek_token& out_token, const std::string& passphrase,
    const ek_salt& salt, uint32_t lot, uint32_t sequence)
{
    if (lot > ek_max_lot || sequence > ek_max_sequence)
        return false;

    static constexpr size_t max_sequence_bits = 12;
    const uint32_t lot_sequence = (lot << max_sequence_bits) || sequence;
    const auto entropy = splice(salt, to_big_endian(lot_sequence));
    const auto prefix = parse_ek_token::prefix_factory(true);
    create_token(out_token, passphrase, salt, entropy, prefix);
    return true;
}

// encrypt
// ----------------------------------------------------------------------------

void encrypt(ek_private& out_private, const ec_secret& secret,
    const std::string& passphrase, uint8_t version, bool compressed)
{
    const auto prefix = parse_ek_private::prefix_factory(version, false);
    const auto point = secret_to_public_key(secret, compressed);
    const auto salt = address_salt(version, point);
    const auto derived = split(scrypt_private(normal(passphrase), salt));

    auto encrypted1 = xor_data<half>(secret, derived.left);
    aes256_encrypt(derived.right, encrypted1);

    auto encrypted2 = xor_data<half>(secret, derived.left, half);
    aes256_encrypt(derived.right, encrypted2);

    build_checked_array(out_private,
    {
        prefix,
        set_flags(compressed),
        salt,
        encrypted1,
        encrypted2
    });
}

// decrypt private_key
// ----------------------------------------------------------------------------

static bool decrypt_multiplied(ec_secret& out_secret,
    const parse_ek_private& parse, const std::string& passphrase)
{
    auto secret = scrypt_token(normal(passphrase), parse.owner_salt());

    if (parse.lot_sequence())
        secret = bitcoin_hash(splice(secret, parse.entropy()));

    const auto point = secret_to_public_key(secret, true);
    const auto salt_entropy = splice(parse.salt(), parse.entropy());
    const auto derived = split(scrypt_pair(point, salt_entropy));

    auto encrypt1 = parse.data1();
    auto encrypt2 = parse.data2();

    aes256_decrypt(derived.right, encrypt2);
    const auto decrypt2 = xor_data<half>(encrypt2, derived.left, 0, half);
    auto part = split(decrypt2);
    auto extended = splice(encrypt1, part.left);

    aes256_decrypt(derived.right, extended);
    const auto decrypt1 = xor_data<half>(extended, derived.left);
    const auto factor = bitcoin_hash(splice(decrypt1, part.right));
    ec_multiply(secret, factor);

    const auto compressed = parse.compressed();
    const auto address_version = parse.address_version();
    if (!address_validate(secret, parse.salt(), address_version, compressed))
        return false;

    out_secret = secret;
    return true;
}

static bool decrypt_secret(ec_secret& out_secret,
    const parse_ek_private& parse, const std::string& passphrase)
{
    const auto derived = split(scrypt_private(normal(passphrase), parse.salt()));
    auto encrypt1 = splice(parse.entropy(), parse.data1());
    auto encrypt2 = parse.data2();

    aes256_decrypt(derived.right, encrypt1);
    aes256_decrypt(derived.right, encrypt2);

    const auto encrypted = splice(encrypt1, encrypt2);
    const auto secret = xor_data<hash_size>(encrypted, derived.left);

    const auto compressed = parse.compressed();
    const auto address_version = parse.address_version();
    if (!address_validate(secret, parse.salt(), address_version, compressed))
        return false;

    out_secret = secret;
    return true;
}

bool decrypt(ec_secret& out_secret, uint8_t& out_version, bool& compressed,
    const ek_private& key, const std::string& passphrase)
{
    const parse_ek_private parse(key);
    if (!parse.valid())
        return false;

    const auto success = parse.multiplied() ?
        decrypt_multiplied(out_secret, parse, passphrase) :
        decrypt_secret(out_secret, parse, passphrase);

    if (success)
    {
        compressed = parse.compressed();
        out_version = parse.address_version();
    }

    return success;
}

// decrypt public_key
// ----------------------------------------------------------------------------

bool decrypt(ec_point& out_point, uint8_t& out_version, const ek_public& key,
    const std::string& passphrase)
{
    const parse_ek_public parse(key);
    if (!parse.valid())
        return false;

    const auto version = parse.address_version();
    const auto compressed = parse.compressed();
    const auto lot_sequence = parse.lot_sequence();
    auto factor = scrypt_token(normal(passphrase), parse.owner_salt());

    if (lot_sequence)
        factor = bitcoin_hash(splice(factor, parse.entropy()));

    const auto point = secret_to_public_key(factor, true);
    const auto salt_entropy = splice(parse.salt(), parse.entropy());
    auto derived = split(scrypt_pair(point, salt_entropy));
    auto encrypt = split(parse.data());

    aes256_decrypt(derived.right, encrypt.left);
    const auto decrypt1 = xor_data<half>(encrypt.left, derived.left);

    aes256_decrypt(derived.right, encrypt.right);
    const auto decrypt2 = xor_data<half>(encrypt.right, derived.left, 0, half);

    const auto sign_byte = point_sign(parse.sign(), derived.right);
    auto generated = build_chunk({ sign_byte, decrypt1, decrypt2 });

    ec_multiply(generated, factor);
    if (!compressed)
        generated = decompress_public_key(generated);

    if (!address_validate(generated, parse.salt(), version, compressed))
        return false;

    out_point = generated;
    out_version = version;
    return true;
}

#endif // WITH_ICU

} // namespace wallet
} // namespace libbitcoin
