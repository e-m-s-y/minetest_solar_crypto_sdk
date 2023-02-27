#pragma once

#include <vector>

void generate_random_bytes(unsigned char *bytes, size_t size);
std::string bytes_to_entropy(unsigned char *bytes, size_t size);
std::string decimal_to_binary(int decimal);
std::string generate_checksum(unsigned char *bytes, size_t size, int bits);
std::vector<int> fingerprint_to_decimals(std::string fingerprint, size_t size);
int binary_to_decimal(std::string binary);
std::string decimals_to_words(std::vector<int> decimals, size_t size);
std::string generate_mnemonic(int bits);
std::string mnemonic_to_wallet_address(std::string mnemonic);
std::string mnemonic_to_public_key(std::string mnemonic);
std::string mnemonic_to_private_key(std::string mnemonic);
std::string sign_message(std::string message, std::string mnemonic);
