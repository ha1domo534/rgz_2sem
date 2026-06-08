#include "rgz.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <vector>
#include <string>

int read_data(const char* path, uint8_t** data, size_t* len) {
    if (!path) {
        std::vector<uint8_t> buffer;
        int ch;
        while ((ch = getchar()) != EOF) {
            buffer.push_back((uint8_t)ch);
        }
        *len = buffer.size();
        *data = (uint8_t*)malloc(*len);
        if (!*data) return -1;
        memcpy(*data, buffer.data(), *len);
        return 0;
    } else {
        FILE* f = fopen(path, "rb");
        if (!f) return -1;
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        *data = (uint8_t*)malloc(size);
        if (!*data) { fclose(f); return -1; }
        size_t read = fread(*data, 1, size, f);
        fclose(f);
        if (read != (size_t)size) { free(*data); return -1; }
        *len = size;
        return 0;
    }
}

int write_data(const char* path, const uint8_t* data, size_t len) {
    if (!path) {
        fwrite(data, 1, len, stdout);
        return 0;
    } else {
        size_t path_len = strlen(path);
        if (path_len > 0 && (path[path_len-1] == '/' || path[path_len-1] == '\\')) {
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%soutput.bin", path);
            FILE* f = fopen(full_path, "wb");
            if (!f) return -1;
            fwrite(data, 1, len, f);
            fclose(f);
            printf("Created file: %s\n", full_path);
            return 0;
        } else {
            FILE* f = fopen(path, "wb");
            if (!f) return -1;
            fwrite(data, 1, len, f);
            fclose(f);
            return 0;
        }
    }
}

char* generate_key(int algorithm, size_t* key_len) {
    srand((unsigned int)time(NULL));
    if (algorithm == ALGORITHM_XOR) {
        size_t len = 16;
        char* key = (char*)malloc(len);
        for (size_t i = 0; i < len; ++i) {
            key[i] = (char)(rand() % 256);
        }
        *key_len = len;
        return key;
    } else if (algorithm == ALGORITHM_PLAYFAIR) {
        size_t len = 9;
        char* key = (char*)malloc(len);
        for (size_t i = 0; i < len-1; ++i) {
            key[i] = 'A' + (rand() % 26);
        }
        key[len-1] = '\0';
        *key_len = len-1;
        return key;
    }
    return NULL;
}

int xor_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output) {
    for (size_t i = 0; i < input_len; ++i) {
        output[i] = input[i] ^ key[i % key_len];
    }
    return 0;
}

static void build_playfair_table(const char* keyword, char table[5][5]) {
    char used[26] = {0};
    int idx = 0;
    for (const char* p = keyword; *p; ++p) {
        char c = toupper(*p);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z' && !used[c - 'A']) {
            used[c - 'A'] = 1;
            table[idx / 5][idx % 5] = c;
            ++idx;
        }
    }
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (c == 'J') continue;
        if (!used[c - 'A']) {
            table[idx / 5][idx % 5] = c;
            ++idx;
        }
    }
}

static void find_position(char c, char table[5][5], int* row, int* col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            if (table[i][j] == c) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

static std::string prepare_playfair(const std::string& text) {
    std::string result;
    for (char c : text) {
        if (isalpha((unsigned char)c)) {
            char up = toupper(c);
            if (up == 'J') up = 'I';
            result.push_back(up);
        }
    }
    std::string processed;
    for (size_t i = 0; i < result.size(); ++i) {
        processed.push_back(result[i]);
        if (i + 1 < result.size() && result[i] == result[i+1]) {
            processed.push_back('X');
        }
    }
    if (processed.size() % 2 != 0) {
        processed.push_back('X');
    }
    return processed;
}

static std::string playfair_cipher(const std::string& text, const char* keyword, int encrypt) {
    char table[5][5];
    build_playfair_table(keyword, table);
    std::string prepared = prepare_playfair(text);
    std::string result;
    for (size_t i = 0; i < prepared.size(); i += 2) {
        char a = prepared[i];
        char b = prepared[i+1];
        int r1, c1, r2, c2;
        find_position(a, table, &r1, &c1);
        find_position(b, table, &r2, &c2);
        if (r1 == r2) {
            int shift = encrypt ? 1 : 4;
            result.push_back(table[r1][(c1 + shift) % 5]);
            result.push_back(table[r2][(c2 + shift) % 5]);
        } else if (c1 == c2) {
            int shift = encrypt ? 1 : 4;
            result.push_back(table[(r1 + shift) % 5][c1]);
            result.push_back(table[(r2 + shift) % 5][c2]);
        } else {
            result.push_back(table[r1][c2]);
            result.push_back(table[r2][c1]);
        }
    }
    return result;
}

int playfair_encrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output) {
    char* text = (char*)malloc(input_len + 1);
    memcpy(text, input, input_len);
    text[input_len] = '\0';
    std::string enc = playfair_cipher(text, (const char*)key, 1);
    free(text);
    if (enc.size() + 1 > input_len) {
        return -1;
    }
    memcpy(output, enc.c_str(), enc.size() + 1);
    return 0;
}

int playfair_decrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output) {
    char* text = (char*)malloc(input_len + 1);
    memcpy(text, input, input_len);
    text[input_len] = '\0';
    std::string dec = playfair_cipher(text, (const char*)key, 0);
    free(text);
    if (dec.size() + 1 > input_len) {
        return -1;
    }
    memcpy(output, dec.c_str(), dec.size() + 1);
    return 0;
}

void print_help(const char* prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -a, --algorithm ALGO   xor, playfair\n");
    printf("  -m, --mode MODE        encrypt, decrypt, gen-key\n");
    printf("  -k, --key KEY          key string or file\n");
    printf("  -i, --input FILE       input file (default stdin)\n");
    printf("  -o, --output FILE      output file (default stdout)\n");
    printf("  --gen-key              generate random key\n");
    printf("  -h, --help             show this help\n");
}

int parse_arguments(int argc, char* argv[], struct Arguments* args) {
    args->algorithm = 0;
    args->mode = -1;
    args->key = NULL;
    args->input = NULL;
    args->output = NULL;
    args->gen_key = 0;
    args->help = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            args->help = 1;
            return 0;
        } else if (strcmp(argv[i], "--algorithm") == 0 || strcmp(argv[i], "-a") == 0) {
            if (i+1 < argc) {
                ++i;
                if (strcmp(argv[i], "xor") == 0) args->algorithm = ALGORITHM_XOR;
                else if (strcmp(argv[i], "playfair") == 0) args->algorithm = ALGORITHM_PLAYFAIR;
                else return -1;
            } else return -1;
        } else if (strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i+1 < argc) {
                ++i;
                if (strcmp(argv[i], "encrypt") == 0) args->mode = 0;
                else if (strcmp(argv[i], "decrypt") == 0) args->mode = 1;
                else if (strcmp(argv[i], "gen-key") == 0) args->mode = 2;
                else return -1;
            } else return -1;
        } else if (strcmp(argv[i], "--key") == 0 || strcmp(argv[i], "-k") == 0) {
            if (i+1 < argc) { ++i; args->key = argv[i]; }
            else return -1;
        } else if (strcmp(argv[i], "--input") == 0 || strcmp(argv[i], "-i") == 0) {
            if (i+1 < argc) { ++i; args->input = argv[i]; }
            else return -1;
        } else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0) {
            if (i+1 < argc) { ++i; args->output = argv[i]; }
            else return -1;
        } else if (strcmp(argv[i], "--gen-key") == 0) {
            args->gen_key = 1;
            args->mode = 2;
        } else {
            return -1;
        }
    }
    if (args->help) return 0;
    if (args->mode == -1) return -1;
    if (args->mode != 2 && !args->key) return -1;
    if (args->algorithm == 0 && args->mode != 2) return -1;
    return 0;
}

int process_data(const struct Arguments* args) {
    if (args->mode == 2) {
        size_t key_len;
        char* key = generate_key(args->algorithm, &key_len);
        if (!key) return 1;
        if (args->output) {
            write_data(args->output, (uint8_t*)key, key_len);
        } else {
            fwrite(key, 1, key_len, stdout);
        }
        free(key);
        return 0;
    }
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    if (read_data(args->input, &input_data, &input_len) != 0) return 1;
    uint8_t* key_data = NULL;
    size_t key_len = 0;
    FILE* test = fopen(args->key, "rb");
    if (test) {
        fclose(test);
        if (read_data(args->key, &key_data, &key_len) != 0) {
            free(input_data);
            return 1;
        }
    } else {
        key_len = strlen(args->key);
        key_data = (uint8_t*)malloc(key_len);
        memcpy(key_data, args->key, key_len);
    }
    uint8_t* output_data = NULL;
    size_t output_len = 0;
    int ret = 0;
    if (args->algorithm == ALGORITHM_XOR) {
        output_len = input_len;
        output_data = (uint8_t*)malloc(output_len);
        if (!output_data) { ret = 1; goto cleanup; }
        xor_cipher(input_data, input_len, key_data, key_len, output_data);
    } else if (args->algorithm == ALGORITHM_PLAYFAIR) {
        output_len = input_len;
        output_data = (uint8_t*)malloc(output_len);
        if (!output_data) { ret = 1; goto cleanup; }
        if (args->mode == 0) {
            ret = playfair_encrypt(input_data, input_len, key_data, key_len, output_data);
        } else {
            ret = playfair_decrypt(input_data, input_len, key_data, key_len, output_data);
        }
    } else {
        ret = 1;
    }
    if (ret == 0) {
        if (write_data(args->output, output_data, output_len) != 0) ret = 1;
    }
cleanup:
    free(input_data);
    free(key_data);
    if (output_data) free(output_data);
    return ret;
}