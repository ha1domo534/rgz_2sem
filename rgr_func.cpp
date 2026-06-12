#include "rgr.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <vector>
#include <string>
#include <cmath>

int read_data(const char* path, uint8_t** data, size_t* len) {
    if (!path) {
        std::vector<uint8_t> buffer;
        int ch;
        while ((ch = getchar()) != EOF) buffer.push_back((uint8_t)ch);
        *len = buffer.size();
        *data = (uint8_t*)malloc(*len);
        if (!*data) return -1;
        memcpy(*data, buffer.data(), *len);
        return 0;
    }
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

int write_data(const char* path, const uint8_t* data, size_t len) {
    if (!path) {
        fwrite(data, 1, len, stdout);
        return 0;
    }
    size_t path_len = strlen(path);
    if (path_len > 0 && (path[path_len-1] == '/' || path[path_len-1] == '\\')) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%soutput.bin", path);
        FILE* f = fopen(full_path, "wb");
        if (!f) return -1;
        fwrite(data, 1, len, f);
        fclose(f);
        printf("Создан файл: %s\n", full_path);
        return 0;
    }
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);
    return 0;
}

char* generate_key(int algorithm, size_t* key_len) {
    srand((unsigned int)time(NULL));
    if (algorithm == ALGORITHM_XOR) {
        size_t len = 16;
        char* key = (char*)malloc(len);
        for (size_t i = 0; i < len; ++i) key[i] = (char)(rand() % 256);
        *key_len = len;
        return key;
    }
    if (algorithm == ALGORITHM_PLAYFAIR) {
        size_t len = 9;
        char* key = (char*)malloc(len);
        for (size_t i = 0; i < len-1; ++i) key[i] = 'A' + (rand() % 26);
        key[len-1] = '\0';
        *key_len = len-1;
        return key;
    }
    if (algorithm == ALGORITHM_CAESAR) {
        int shift = rand() % 26;
        char* key = (char*)malloc(4);
        sprintf(key, "%d", shift);
        *key_len = strlen(key);
        return key;
    }
    if (algorithm == ALGORITHM_VIGENERE) {
        size_t len = 8;
        char* key = (char*)malloc(len+1);
        for (size_t i = 0; i < len; ++i) key[i] = 'A' + (rand() % 26);
        key[len] = '\0';
        *key_len = len;
        return key;
    }
    if (algorithm == ALGORITHM_SCYTALE) {
        int cols = 2 + rand() % 10;
        char* key = (char*)malloc(4);
        sprintf(key, "%d", cols);
        *key_len = strlen(key);
        return key;
    }
    if (algorithm == ALGORITHM_GRONSFELD) {
        size_t len = 6;
        char* key = (char*)malloc(len+1);
        for (size_t i = 0; i < len; ++i) key[i] = '0' + (rand() % 10);
        key[len] = '\0';
        *key_len = len;
        return key;
    }
    return NULL;
}

int xor_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output) {
    for (size_t i = 0; i < input_len; ++i) output[i] = input[i] ^ key[i % key_len];
    return 0;
}

//PLAYFAIR 
static void build_playfair_table(const char* keyword, char table[5][5]) {
    char used[26] = {0};
    int idx = 0;
    for (const char* p = keyword; *p; ++p) {
        char c = toupper(*p);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z' && !used[c - 'A']) {
            used[c - 'A'] = 1;
            table[idx/5][idx%5] = c;
            ++idx;
        }
    }
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (c == 'J') continue;
        if (!used[c - 'A']) {
            table[idx/5][idx%5] = c;
            ++idx;
        }
    }
}

static void find_position(char c, char table[5][5], int* row, int* col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 5; ++j)
            if (table[i][j] == c) { *row = i; *col = j; return; }
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
        if (i+1 < result.size() && result[i] == result[i+1])
            processed.push_back('X');
    }
    if (processed.size() % 2 != 0)
        processed.push_back('X');
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
            result.push_back(table[r1][(c1+shift)%5]);
            result.push_back(table[r2][(c2+shift)%5]);
        } else if (c1 == c2) {
            int shift = encrypt ? 1 : 4;
            result.push_back(table[(r1+shift)%5][c1]);
            result.push_back(table[(r2+shift)%5][c2]);
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
    strcpy((char*)output, enc.c_str());
    return 0;
}

int playfair_decrypt(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output) {
    char* text = (char*)malloc(input_len + 1);
    memcpy(text, input, input_len);
    text[input_len] = '\0';
    std::string dec = playfair_cipher(text, (const char*)key, 0);
    free(text);
    std::string result;
    for (size_t i = 0; i < dec.size(); ++i) {
        if (dec[i] == 'X') {
            if (i > 0 && i < dec.size()-1 && dec[i-1] == dec[i+1]) continue;
            if (i == dec.size()-1) continue;
        }
        result.push_back(dec[i]);
    }
    strcpy((char*)output, result.c_str());
    return 0;
}

//CAESAR 
int caesar_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output, int mode) {
    int shift = atoi((const char*)key) % 26;
    if (mode == 2) shift = (26 - shift) % 26;
    for (size_t i = 0; i < input_len; ++i) {
        unsigned char c = input[i];
        if (c >= 'a' && c <= 'z') output[i] = 'a' + (c - 'a' + shift) % 26;
        else if (c >= 'A' && c <= 'Z') output[i] = 'A' + (c - 'A' + shift) % 26;
        else output[i] = c;
    }
    return 0;
}

//VIGENERE 
int vigenere_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output, int mode) {
    for (size_t i = 0; i < input_len; ++i) {
        unsigned char c = input[i];
        int k = key[i % key_len];
        if (k >= 'a' && k <= 'z') k -= 'a';
        else if (k >= 'A' && k <= 'Z') k -= 'A';
        else k = 0;
        if (mode == 2) k = (26 - k) % 26;
        if (c >= 'a' && c <= 'z') output[i] = 'a' + (c - 'a' + k) % 26;
        else if (c >= 'A' && c <= 'Z') output[i] = 'A' + (c - 'A' + k) % 26;
        else output[i] = c;
    }
    return 0;
}

//SCYTALE 
int scytale_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output, int mode) {
    int cols = atoi((const char*)key);
    if (cols < 2) cols = 2;
    int rows = (input_len + cols - 1) / cols;
    if (mode == 1) {
        int idx = 0;
        for (int c = 0; c < cols; ++c)
            for (int r = 0; r < rows; ++r) {
                int pos = r * cols + c;
                if (pos < (int)input_len) output[idx++] = input[pos];
                else output[idx++] = ' ';
            }
        output[idx] = '\0';
    } else {
        int idx = 0;
        for (int r = 0; r < rows; ++r)
            for (int c = 0; c < cols; ++c) {
                int pos = c * rows + r;
                if (pos < (int)input_len) output[idx++] = input[pos];
            }
        output[idx] = '\0';
    }
    return 0;
}

//GRONSFELD 
int gronsfeld_cipher(const uint8_t* input, size_t input_len, const uint8_t* key, size_t key_len, uint8_t* output, int mode) {
    for (size_t i = 0; i < input_len; ++i) {
        unsigned char c = input[i];
        int shift = (key[i % key_len] - '0') % 10;
        if (mode == 2) shift = -shift;  
        int final_shift = (shift % 26 + 26) % 26;  
        if (c >= 'a' && c <= 'z') output[i] = 'a' + (c - 'a' + final_shift) % 26;
        else if (c >= 'A' && c <= 'Z') output[i] = 'A' + (c - 'A' + final_shift) % 26;
        else output[i] = c;
    }
    return 0;
}
