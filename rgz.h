#ifndef RGZ_H
#define RGZ_H

#include <cstddef>
#include <cstdint>

#define ALGORITHM_XOR        1
#define ALGORITHM_PLAYFAIR   2

struct Arguments {
    int algorithm;
    int mode;
    const char* key;
    const char* input;
    const char* output;
    int gen_key;
    int help;
};

void print_help(const char* prog_name);
int parse_arguments(int argc, char* argv[], struct Arguments* args);
int read_data(const char* path, uint8_t** data, size_t* len);
int write_data(const char* path, const uint8_t* data, size_t len);
char* generate_key(int algorithm, size_t* key_len);
int process_data(const struct Arguments* args);

int xor_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);
int playfair_encrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);
int playfair_decrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output);

#endif