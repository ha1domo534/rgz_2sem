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
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            has_hex = 1;
        } else if (*p != ' ' && *p != '\t' && *p != '\n') {
            return 0;
        }
    }
    return has_hex;
}

int hex_string_to_bytes(const char* hex, uint8_t** out, size_t* out_len) {
    size_t count = 0;
    for (const char* p = hex; *p; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            if (*(p+1) && ((*(p+1) >= '0' && *(p+1) <= '9') || 
                           (*(p+1) >= 'a' && *(p+1) <= 'f') || 
                           (*(p+1) >= 'A' && *(p+1) <= 'F'))) {
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
            if (*(p+1) && ((*(p+1) >= '0' && *(p+1) <= '9') || 
                           (*(p+1) >= 'a' && *(p+1) <= 'f') || 
                           (*(p+1) >= 'A' && *(p+1) <= 'F'))) {
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
    scanf("%d", &alg);
    getchar();
    
    printf("Выберите режим:\n1. Шифрование\n2. Дешифрование\nВаш выбор: ");
    scanf("%d", &mode);
    getchar();
    
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    
    printf("Введите текст: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';
    
    size_t key_len = strlen(key);
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    int is_hex = 0;
    
    if (alg == ALGORITHM_XOR && mode == 2 && is_hex_string(text)) {
        if (hex_string_to_bytes(text, &input_data, &input_len) == 0) {
            is_hex = 1;
        }
    }
    
    if (!is_hex) {
        input_len = strlen(text);
        input_data = (uint8_t*)malloc(input_len + 1);
        if (!input_data) {
            printf("Ошибка памяти\n");
            return;
        }
        memcpy(input_data, text, input_len);
        input_data[input_len] = '\0';
    }
    
    if (!input_data) {
        printf("Ошибка памяти\n");
        return;
    }
    
    int ret = -1;
    uint8_t* output_data = NULL;
    size_t output_len = 0;
    
    switch (alg) {
        case ALGORITHM_XOR: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = xor_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data);
            break;
        }
        
        case ALGORITHM_PLAYFAIR: {
            if (mode == 1) {
                ret = playfair_encrypt(input_data, input_len, (uint8_t*)key, key_len, 
                                       &output_data, &output_len);
            } else {
                ret = playfair_decrypt(input_data, input_len, (uint8_t*)key, key_len, 
                                       &output_data, &output_len);
            }
            break;
        }
        
        case ALGORITHM_CAESAR: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = caesar_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        case ALGORITHM_VIGENERE: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = vigenere_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        case ALGORITHM_SCYTALE: {
            ret = scytale_cipher(input_data, input_len, (uint8_t*)key, key_len, 
                                 &output_data, &output_len, mode);
            break;
        }
        
        case ALGORITHM_GRONSFELD: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = gronsfeld_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        default:
            printf("Неверный алгоритм\n");
            ret = -1;
    }
    
    if (ret == 0 && output_data) {
        printf("\nРЕЗУЛЬТАТ:\n");
        if (alg == ALGORITHM_XOR && mode == 1) {
            for (size_t i = 0; i < output_len; ++i) {
                printf("%02x ", output_data[i]);
            }
            printf("\n");
        } else {
            fwrite(output_data, 1, output_len, stdout);
            printf("\n");
        }
    } else if (ret != 0) {
        printf("Ошибка операции\n");
    }
    
    secure_zero(input_data, input_len);
    free(input_data);
    if (output_data) {
        secure_zero(output_data, output_len);
        free(output_data);
    }
}

void process_file() {
    int alg, mode;
    char key[256], in_path[1024], out_path[1024];
    
    show_algorithms();
    scanf("%d", &alg);
    getchar();
    
    printf("Выберите режим:\n1. Шифрование\n2. Дешифрование\nВаш выбор: ");
    scanf("%d", &mode);
    getchar();
    
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    
    printf("Введите путь к входному файлу: ");
    fgets(in_path, sizeof(in_path), stdin);
    in_path[strcspn(in_path, "\n")] = '\0';
    
    printf("Введите путь к выходному файлу (или папке, заканчивающейся на /): ");
    fgets(out_path, sizeof(out_path), stdin);
    out_path[strcspn(out_path, "\n")] = '\0';
    
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    
    if (read_data(in_path, &input_data, &input_len) != 0) {
        printf("Ошибка чтения входного файла\n");
        return;
    }
    
    size_t key_len = strlen(key);
    int ret = -1;
    uint8_t* output_data = NULL;
    size_t output_len = 0;
    
    switch (alg) {
        case ALGORITHM_XOR: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = xor_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data);
            break;
        }
        
        case ALGORITHM_PLAYFAIR: {
            if (mode == 1) {
                ret = playfair_encrypt(input_data, input_len, (uint8_t*)key, key_len, 
                                       &output_data, &output_len);
            } else {
                ret = playfair_decrypt(input_data, input_len, (uint8_t*)key, key_len, 
                                       &output_data, &output_len);
            }
            break;
        }
        
        case ALGORITHM_CAESAR: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = caesar_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        case ALGORITHM_VIGENERE: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = vigenere_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        case ALGORITHM_SCYTALE: {
            ret = scytale_cipher(input_data, input_len, (uint8_t*)key, key_len, 
                                 &output_data, &output_len, mode);
            break;
        }
        
        case ALGORITHM_GRONSFELD: {
            output_len = input_len;
            output_data = (uint8_t*)malloc(output_len);
            if (!output_data) {
                printf("Ошибка памяти\n");
                free(input_data);
                return;
            }
            ret = gronsfeld_cipher(input_data, input_len, (uint8_t*)key, key_len, output_data, mode);
            break;
        }
        
        default:
            printf("Неверный алгоритм\n");
            ret = -1;
    }
    
    if (ret == 0 && output_data) {
        if (write_data(out_path, output_data, output_len) != 0) {
            printf("Ошибка записи выходного файла\n");
        } else {
            printf("Операция успешно выполнена\n");
        }
    } else {
        printf("Ошибка операции\n");
    }
    
    secure_zero(input_data, input_len);
    free(input_data);
    if (output_data) {
        secure_zero(output_data, output_len);
        free(output_data);
    }
}

void process_gen_key() {
    int alg;
    show_algorithms();
    scanf("%d", &alg);
    getchar();
    
    size_t key_len;
    char* key = generate_key(alg, &key_len);
    
    if (!key) {
        printf("Ошибка генерации ключа\n");
        return;
    }
    
    printf("\nСгенерированный ключ: ");
    if (alg == ALGORITHM_XOR) {
        for (size_t i = 0; i < key_len; ++i) {
            printf("%02x ", (unsigned char)key[i]);
        }
        printf("\n");
    } else if (alg == ALGORITHM_SCYTALE) {
        printf("%d\n", key[0]);
    } else {
        printf("%s\n", key);
    }
    
    secure_zero(key, key_len);
    free(key);
}

int main() {
    int choice;
    while (1) {
        show_menu();
        scanf("%d", &choice);
        getchar();
        
        switch (choice) {
            case 1: process_text(); break;
            case 2: process_file(); break;
            case 3: process_gen_key(); break;
            case 4: 
                printf("До свидания!\n");
                return 0;
            default:
                printf("Неверный выбор\n");
        }
    }
}
