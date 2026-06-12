#include "rgr.h"
#include <cstdio>
#include <cstring>
#include <string>

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

void process_text() {
    int alg, mode;
    char key[256];
    char text[4096];
    char result[4096];
    
    printf("\nВыберите алгоритм:\n");
    printf("1. XOR\n");
    printf("2. Playfair\n");
    printf("Ваш выбор: ");
    scanf("%d", &alg);
    getchar();
    
    printf("Выберите режим:\n");
    printf("1. Шифрование\n");
    printf("2. Дешифрование\n");
    printf("Ваш выбор: ");
    scanf("%d", &mode);
    getchar();
    
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    
    printf("Введите текст: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';
    
    size_t input_len = strlen(text);
    size_t key_len = strlen(key);
    
    uint8_t* output_data = (uint8_t*)malloc(input_len + 1);
    if (!output_data) {
        printf("Ошибка выделения памяти\n");
        return;
    }
    
    int ret = -1;
    
    if (alg == 1) {
        xor_cipher((uint8_t*)text, input_len, (uint8_t*)key, key_len, output_data);
        ret = 0;
    } else if (alg == 2) {
        if (mode == 1) {
            ret = playfair_encrypt((uint8_t*)text, input_len, (uint8_t*)key, key_len, output_data);
        } else {
            ret = playfair_decrypt((uint8_t*)text, input_len, (uint8_t*)key, key_len, output_data);
        }
    } else {
        printf("Неверный выбор алгоритма\n");
        free(output_data);
        return;
    }
    
    if (ret == 0) {
        printf("\nРЕЗУЛЬТАТ:\n");
        if (alg == 1 && mode == 1) {
            for (size_t i = 0; i < input_len; ++i) {
                printf("%02x ", output_data[i]);
            }
            printf("\n");
        } else {
            printf("%s\n", (char*)output_data);
        }
    } else {
        printf("Ошибка при выполнении операции\n");
    }
    
    free(output_data);
}

void process_file() {
    int alg, mode;
    char key[256];
    char input_path[1024];
    char output_path[1024];
    
    printf("\nВыберите алгоритм:\n");
    printf("1. XOR\n");
    printf("2. Playfair\n");
    printf("Ваш выбор: ");
    scanf("%d", &alg);
    getchar();
    
    printf("Выберите режим:\n");
    printf("1. Шифрование\n");
    printf("2. Дешифрование\n");
    printf("Ваш выбор: ");
    scanf("%d", &mode);
    getchar();
    
    printf("Введите ключ: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    
    printf("Введите путь к входному файлу: ");
    fgets(input_path, sizeof(input_path), stdin);
    input_path[strcspn(input_path, "\n")] = '\0';
    
    printf("Введите путь к выходному файлу (или папке, заканчивающейся на /): ");
    fgets(output_path, sizeof(output_path), stdin);
    output_path[strcspn(output_path, "\n")] = '\0';
    
    uint8_t* input_data = NULL;
    size_t input_len = 0;
    
    if (read_data(input_path, &input_data, &input_len) != 0) {
        printf("Ошибка чтения входного файла\n");
        return;
    }
    
    size_t key_len = strlen(key);
    uint8_t* key_data = (uint8_t*)key;
    
    uint8_t* output_data = (uint8_t*)malloc(input_len + 1);
    if (!output_data) {
        printf("Ошибка выделения памяти\n");
        free(input_data);
        return;
    }
    
    int ret = -1;
    
    if (alg == 1) {
        xor_cipher(input_data, input_len, key_data, key_len, output_data);
        ret = 0;
    } else if (alg == 2) {
        if (mode == 1) {
            ret = playfair_encrypt(input_data, input_len, key_data, key_len, output_data);
        } else {
            ret = playfair_decrypt(input_data, input_len, key_data, key_len, output_data);
        }
    } else {
        printf("Неверный выбор алгоритма\n");
        free(input_data);
        free(output_data);
        return;
    }
    
    if (ret == 0) {
        if (write_data(output_path, output_data, input_len) != 0) {
            printf("Ошибка записи выходного файла\n");
        } else {
            printf("Операция успешно выполнена\n");
        }
    } else {
        printf("Ошибка при выполнении операции\n");
    }
    
    free(input_data);
    free(output_data);
}

void process_gen_key() {
    int alg;
    
    printf("\nВыберите алгоритм:\n");
    printf("1. XOR\n");
    printf("2. Playfair\n");
    printf("Ваш выбор: ");
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
    } else {
        printf("%s\n", key);
    }
    
    free(key);
}

int main() {
    char password[100];
    int choice;
    
    printf("Введите пароль: ");
    scanf("%99s", password);
    
    if (strcmp(password, "0123") != 0) {
        printf("Неверный пароль. Программа завершает работу.\n");
        return 1;
    }
    
    while (1) {
        show_menu();
        scanf("%d", &choice);
        getchar();
        
        switch (choice) {
            case 1:
                process_text();
                break;
            case 2:
                process_file();
                break;
            case 3:
                process_gen_key();
                break;
            case 4:
                printf("До свидания!\n");
                return 0;
            default:
                printf("Неверный выбор. Попробуйте снова.\n");
        }
    }
    
    return 0;
}