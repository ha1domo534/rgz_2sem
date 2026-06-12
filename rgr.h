#ifndef RGR_H
#define RGR_H

#include <cstddef>
#include <cstdint>

#define ALGORITHM_XOR        1
#define ALGORITHM_PLAYFAIR   2

int read_data(const char* path, uint8_t** data, size_t* len);
int write_data(const char* path, const uint8_t* data, size_t len);
char* generate_key(int algorithm, size_t* key_len);

int xor_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);
int playfair_encrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);
int playfair_decrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);

#endif