#include <string>
#include <iostream>
#include <vector>
#include <array>

#include "solar/crypto.h"
#include "solar/wordlist.h"

#include "solar/lib/libtorsion/include/torsion/ecc.h"
#include "solar/lib/libtorsion/include/torsion/hash.h"
#include "solar/lib/libtorsion/include/torsion/rand.h"
#include "solar/lib/libtorsion/include/torsion/drbg.h"
#include "solar/lib/libtorsion/include/torsion/encoding.h"

#include "solar/lib/bcl/src/Ripemd160.hpp"
#include "solar/lib/bcl/src/Base58Check.hpp"
#include "solar/lib/bcl/src/Sha256.hpp"

void generate_random_bytes(unsigned char *bytes, size_t size) {
	torsion_getentropy(bytes, size);
}

std::string bytes_to_entropy(unsigned char *bytes, size_t size) {
	std::string entropy;

	for (int i = 0; i < size; i++) {
		entropy.append(decimal_to_binary(bytes[i]));
	}

	return entropy;
}

std::string decimal_to_binary(int decimal) {
	std::string binary;

	for (int i = 7; i >= 0; i--) {
		int k = decimal >> i;

		if (k & 1) {
			binary.append("1");
		} else {
			binary.append("0");
		}
	}

	return binary;
}

std::string generate_checksum(unsigned char *bytes, size_t size, int bits) {
	sha256_t sha256;
	unsigned char hash[32];

	sha256_init(&sha256);
	sha256_update(&sha256, bytes, size);
	sha256_final(&sha256, hash);

	// Take 1 bit for each 32 bits of the hash
	// hash[0] is 8 bits so we can substr from this value
	// 128 bit hash = 4(128/32) bits checksum
	// 256 bit hash = 8(256/32) bits checksum
	return decimal_to_binary(hash[0]).substr(0, bits / 32);
}

std::vector<int> fingerprint_to_decimals(std::string fingerprint, size_t size) {
 	std::vector<int> decimals;
	int wordSize = 11; // in bits

	// fingerprint = entropy(128 bit) + checksum(4 bit) = 132 bit = 132 / 11 = 12 words
	// fingerprint = entropy(256 bit) + checksum(8 bit) = 264 bit = 264 / 11 = 24 words
	for (int i = 0; i < (size / wordSize); i++) {
		int decimal = binary_to_decimal(fingerprint.substr(i * wordSize, wordSize));

		decimals.push_back(decimal);
	}

	return decimals;
}

// https://www.geeksforgeeks.org/program-binary-decimal-conversion/
int binary_to_decimal(std::string binary) {
	int decimal = 0;

	for (int i = 0; i < binary.size(); i++) {
		decimal <<= 1;

		if (binary[i] == '1') {
			decimal += 1;
		}
	}

	return decimal;
}

std::string decimals_to_words(std::vector<int> decimals, size_t size) {
	std::string words;

	for (int i = 0; i < size; i++) {
    	words.append(BIP39_WORDLIST_ENGLISH[decimals[i]]);

		if (i != size - 1) {
			words.append(" ");
		}
   	}

   	return words;
}

std::string generate_mnemonic(int bits) {
	if (bits != 128 && bits != 256) {
		return std::string("<Invalid amount of bits>");
	}

	size_t bytes_size = 16;
	unsigned char bytes[bytes_size];

	generate_random_bytes(bytes, bytes_size);

	std::string entropy = bytes_to_entropy(bytes, bits / 8);
	std::string checksum = generate_checksum(bytes, bits / 8, bits);

	std::string fingerprint;

	fingerprint.append(entropy);
	fingerprint.append(checksum);

	std::vector<int> decimals = fingerprint_to_decimals(fingerprint, fingerprint.size());
	std::string mnemonic = decimals_to_words(decimals, decimals.size());

//	std::cout << entropy << std::endl;
//	std::cout << checksum << std::endl;
//	std::cout << mnemonic << std::endl;
//	std::cout << mnemonic_to_wallet_address(mnemonic) << std::endl;
//	std::cout << mnemonic_to_public_key(mnemonic) << std::endl;

	return mnemonic;
}

std::string mnemonic_to_wallet_address(std::string mnemonic) {
	sha256_t sha256;
	unsigned char hash[32];

	sha256_init(&sha256);
	sha256_update(&sha256, mnemonic.c_str(), mnemonic.size());
	sha256_final(&sha256, hash);

	wei_curve_t *ec = wei_curve_create(WEI_CURVE_SECP256K1);
	unsigned char publicKeyBytes[33];

	ecdsa_pubkey_create(ec, publicKeyBytes, NULL, hash, 1);

	unsigned char publicKeyHash[20];

	bcl::Ripemd160::getHash(publicKeyBytes, 33, publicKeyHash);

	char address[36];

	bcl::Base58Check::pubkeyHashToBase58Check(publicKeyHash, 63, &address[0]);
	wei_curve_destroy(ec);

	return std::string(address);
}

std::string mnemonic_to_public_key(std::string mnemonic) {
	sha256_t sha256;
	unsigned char hash[32];

	sha256_init(&sha256);
	sha256_update(&sha256, mnemonic.c_str(), mnemonic.size());
	sha256_final(&sha256, hash);

	wei_curve_t *ec = wei_curve_create(WEI_CURVE_SECP256K1);
	unsigned char publicKeyBytes[33];

	ecdsa_pubkey_create(ec, publicKeyBytes, NULL, hash, 1);

  	char publicKey[32];
  	size_t publicKeySize = 32;

   	base16_encode(publicKey, &publicKeySize, publicKeyBytes, 33);

	wei_curve_destroy(ec);

	return std::string(publicKey);
}

void mnemonic_to_private_key(std::string mnemonic, unsigned char *out) {
	sha256_t sha256;

	sha256_init(&sha256);
	sha256_update(&sha256, mnemonic.c_str(), mnemonic.size());
	sha256_final(&sha256, out);
}

std::string sign_message(std::string message, std::string mnemonic) {
	std::string publicKey = mnemonic_to_public_key(mnemonic);

	sha256_t sha256;
	unsigned char hash[32];

	sha256_init(&sha256);
	sha256_update(&sha256, message.c_str(), message.size());
	sha256_final(&sha256, hash);

	unsigned char signatureBytes[64];
	unsigned char entropy[32];

	torsion_getentropy(entropy, 32);

	wei_curve_t *ec = wei_curve_create(WEI_CURVE_SECP256K1);

	unsigned char privateKeyBytes[32];

	mnemonic_to_private_key(mnemonic, privateKeyBytes);

	bip340_sign(ec, signatureBytes, hash, 32, privateKeyBytes, entropy);

  	char signature[128];
  	size_t signatureSize = 128;

	base16_encode(signature, &signatureSize, signatureBytes, 64);

	wei_curve_destroy(ec);

	return std::string(signature);
}
