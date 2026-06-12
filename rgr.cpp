#include "rgr.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

void show_menu() {
    printf("\n========================================\n");
    printf("   ПРОГРАММА ШИФРОВАНИЯ\n");
    printf("========================================\n");
    printf("1. Шифрование/дешифрование текста\n");
    printf("2. Шифрование/дешифрование файла\n");
    printf("3. Генерация ключа\n");
    printf("4. Выход\n");
    printf("========================================\n");
    printf("Ваш выбор: ");
}

void show_algorithms() {
    printf("\nВыберите алгоритм:\n");
    printf("1. XOR\n");
    printf("2. Playfair\n");
    printf("3. Цезарь\n");
    printf("4. Виженер\n");
    printf("5. Скитала\n");
    printf("6. Гронфельд\n");
    printf("Ваш выбор: ");
}

int is_hex_string(const char* s) {
    int has_hex = 0;
    for (const char* p = s; *p; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))
            has_hex = 1;
        else if (*p != ' ' && *p != '\t' && *p != '\n')
            return 0;
    }
    return has_hex;
}

int hex_string_to_bytes(const char* hex, uint8_t** out, size_t* out_len) {
    size_t count = 0;
    for (const char* p = hex; *p; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            if (*(p+1) && ((*(p+1) >= '0' && *(p+1) <= '9') || (*(p+1) >= 'a' && *(p+1) <= 'f') || (*(p+1) >= 'A' && *(p+1) <= 'F'))) {
                count++;
                p++;
            }
        }
    }
    if (count == 0) return -1;
    *out = (uint8_t*)malloc(count);
    if (!*out) return -1;
    size_t idx = 0;
    for (const char* p = hex; *p && idx < count; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            if (*(p+1) && ((*(p+1) >= '0' && *(p+1) <= '9') || (*(p+1) >= 'a' && *(p+1) <= 'f') || (*(p+1) >= 'A' && *(p+1) <= 'F'))) {
                char byte_str[3] = {*p, *(p+1), '\0'};
                (*out)[idx++] = (uint8_t)strtol(byte_str, NULL, 16);
                p++;
            }
        }
    }
    *out_len = count;
    return 0;
}

void process_text() {
    int alg, mode;
    char key[256], text[4096];
    show_algorithms();
    scanf("%d", &alg); getchar();
    printf("Выберите режим:\n1. Шифрование\n2. Дешифрование\nВаш выбор: ");
    scanf("%d", &mode); getchar();
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin); key[strcspn(key, "\n")] = '\0';
    printf("Введите текст: ");
    fgets(text, sizeof(text), stdin); text[strcspn(text, "\n")] = '\0';

    size_t key_len = strlen(key);
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    int is_hex = 0;

    if (alg == ALGORITHM_XOR && mode == 2 && is_hex_string(text)) {
        if (hex_string_to_bytes(text, &input_data, &input_len) == 0) is_hex = 1;
    }
    if (!is_hex) {
        input_len = strlen(text);
        input_data = (uint8_t*)malloc(input_len + 1);
        memcpy(input_data, text, input_len);
        input_data[input_len] = '\0';
    }
    if (!input_data) { printf("Ошибка памяти\n"); return; }

    size_t output_len = (alg == ALGORITHM_XOR) ? input_len : (input_len * 4 + 1024);
    uint8_t* output_data = (uint8_t*)malloc(output_len);
    if (!output_data) { free(input_data); printf("Ошибка памяти\n"); return; }
    memset(output_data, 0, output_len);

    int ret = -1;
    switch (alg) {
        case ALGORITHM_XOR:
            xor_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data);
            ret = 0;
            break;
        case ALGORITHM_PLAYFAIR:
            if (mode == 1)
                ret = playfair_encrypt(input_data, input_len, (uint8_t*)key, key_len, output_data);
            else
                ret = playfair_decrypt(input_data, input_len, (uint8_t*)key, key_len, output_data);
            break;
        case ALGORITHM_CAESAR:
            ret = caesar_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        case ALGORITHM_VIGENERE:
            ret = vigenere_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        case ALGORITHM_SCYTALE: {
            uint8_t skey[1] = {(uint8_t)atoi(key)};
            ret = scytale_cipher(input_data, input_len, skey, 1, output_data, mode);
            break;
        }
        case ALGORITHM_GRONSFELD:
            ret = gronsfeld_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        default:
            printf("Неверный алгоритм\n");
            ret = -1;
    }

    if (ret == 0) {
        printf("\nРЕЗУЛЬТАТ:\n");
        if (alg == ALGORITHM_XOR && mode == 1) {
            for (size_t i = 0; i < input_len; ++i) printf("%02x ", output_data[i]);
            printf("\n");
        } else {
            printf("%s\n", (char*)output_data);
        }
    } else {
        printf("Ошибка операции\n");
    }
    free(input_data);
    free(output_data);
}

void process_file() {
    int alg, mode;
    char key[256], in_path[1024], out_path[1024];
    show_algorithms();
    scanf("%d", &alg); getchar();
    printf("Выберите режим:\n1. Шифрование\n2. Дешифрование\nВаш выбор: ");
    scanf("%d", &mode); getchar();
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin); key[strcspn(key, "\n")] = '\0';
    printf("Введите путь к входному файлу: ");
    fgets(in_path, sizeof(in_path), stdin); in_path[strcspn(in_path, "\n")] = '\0';
    printf("Введите путь к выходному файлу (или папке, заканчивающейся на /): ");
    fgets(out_path, sizeof(out_path), stdin); out_path[strcspn(out_path, "\n")] = '\0';

    uint8_t* input_data = NULL;
    size_t input_len = 0;
    if (read_data(in_path, &input_data, &input_len) != 0) {
        printf("Ошибка чтения входного файла\n");
        return;
    }

    size_t key_len = strlen(key);
    uint8_t* key_data = (uint8_t*)key;
    uint8_t skey[1];
    if (alg == ALGORITHM_SCYTALE) {
        skey[0] = (uint8_t)atoi(key);
        key_data = skey;
        key_len = 1;
    }

    size_t output_len = (alg == ALGORITHM_XOR) ? input_len : (input_len * 4 + 1024);
    uint8_t* output_data = (uint8_t*)malloc(output_len);
    if (!output_data) { free(input_data); printf("Ошибка памяти\n"); return; }
    memset(output_data, 0, output_len);

    int ret = -1;
    switch (alg) {
        case ALGORITHM_XOR:
            xor_cipher(input_data, input_len, key_data, key_len, output_data);
            ret = 0;
            break;
        case ALGORITHM_PLAYFAIR:
            if (mode == 1)
                ret = playfair_encrypt(input_data, input_len, key_data, key_len, output_data);
            else
                ret = playfair_decrypt(input_data, input_len, key_data, key_len, output_data);
            break;
        case ALGORITHM_CAESAR:
            ret = caesar_cipher(input_data, input_len, key_data, key_len, output_data, mode);
            break;
        case ALGORITHM_VIGENERE:
            ret = vigenere_cipher(input_data, input_len, key_data, key_len, output_data, mode);
            break;
        case ALGORITHM_SCYTALE:
            ret = scytale_cipher(input_data, input_len, key_data, key_len, output_data, mode);
            break;
        case ALGORITHM_GRONSFELD:
            ret = gronsfeld_cipher(input_data, input_len, key_data, key_len, output_data, mode);
            break;
        default:
            printf("Неверный алгоритм\n");
            ret = -1;
    }

    if (ret == 0) {
        if (write_data(out_path, output_data, input_len) != 0)
            printf("Ошибка записи выходного файла\n");
        else
            printf("Операция успешно выполнена\n");
    } else {
        printf("Ошибка операции\n");
    }
    free(input_data);
    free(output_data);
}

void process_gen_key() {
    int alg;
    show_algorithms();
    scanf("%d", &alg); getchar();
    size_t key_len;
    char* key = generate_key(alg, &key_len);
    if (!key) { printf("Ошибка генерации\n"); return; }
    printf("\nСгенерированный ключ: ");
    if (alg == ALGORITHM_XOR) {
        for (size_t i = 0; i < key_len; ++i) printf("%02x ", (unsigned char)key[i]);
        printf("\n");
    } else if (alg == ALGORITHM_SCYTALE) {
        printf("%d\n", key[0]);
    } else {
        printf("%s\n", key);
    }
    free(key);
}

int main() {
    char password[100];
    printf("Введите пароль: ");
    scanf("%99s", password);
    if (strcmp(password, "0123") != 0) {
        printf("Неверный пароль. Программа завершает работу.\n");
        return 1;
    }
    int choice;
    while (1) {
        show_menu();
        scanf("%d", &choice); getchar();
        switch (choice) {
            case 1: process_text(); break;
            case 2: process_file(); break;
            case 3: process_gen_key(); break;
            case 4: printf("До свидания!\n"); return 0;
            default: printf("Неверный выбор\n");
        }
    }
}