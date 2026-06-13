#ifndef RGR_H
#define RGR_H

#include <cstddef>
#include <cstdint>

#define ALGORITHM_XOR        1
#define ALGORITHM_PLAYFAIR   2
#define ALGORITHM_CAESAR     3
#define ALGORITHM_VIGENERE   4
#define ALGORITHM_SCYTALE    5
#define ALGORITHM_GRONSFELD  6

// вспомогательные функции
int read_data(const char* path, uint8_t** data, size_t* len);
int write_data(const char* path, const uint8_t* data, size_t len);
void secure_zero(void* ptr, size_t len);
char* generate_key(int algorithm, size_t* key_len);

// алгоритмы шифрования
int xor_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, 
               size_t key_len, uint8_t* output);

int playfair_encrypt(const uint8_t* input, size_t input_len, const uint8_t* key, 
                     size_t key_len, uint8_t** output, size_t* output_len);
int playfair_decrypt(const uint8_t* input, size_t input_len, const uint8_t* key, 
                     size_t key_len, uint8_t** output, size_t* output_len);

int caesar_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, 
                  size_t key_len, uint8_t* output, int mode);

int vigenere_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, 
                    size_t key_len, uint8_t* output, int mode);

int scytale_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, 
                   size_t key_len, uint8_t** output, size_t* output_len, int mode);

int gronsfeld_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, 
                     size_t key_len, uint8_t* output, int mode);

#endif
