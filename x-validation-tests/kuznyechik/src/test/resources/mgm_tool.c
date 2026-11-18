/*
 * Эталонный MGM (Кузнечик, RFC 9058) на EVP API OpenSSL с провайдером gostprov.
 * Нужен кросс-валидации: утилита openssl enc не поддерживает AEAD-режимы.
 *
 * Использование (все аргументы - hex, пустая строка допустима как "-"):
 *   mgm_tool enc <key> <icn> <aad> <plaintext>       -> hex(шифртекст || тег)
 *   mgm_tool dec <key> <icn> <aad> <ciphertext||tag> -> hex(открытый текст)
 * Код выхода: 0 - успех, 2 - отказ по тегу, 1 - любая другая ошибка.
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG_LEN 16
#define EXIT_FAIL 1
#define EXIT_BAD_TAG 2

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Разбирает hex; "-" означает пустую строку. Возвращает длину или -1. */
static int parse_hex(const char *hex, unsigned char **out) {
    size_t len = strlen(hex);
    if (strcmp(hex, "-") == 0) len = 0;
    if (len % 2 != 0) return -1;
    *out = malloc(len / 2 + 1);
    if (*out == NULL) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        (*out)[i] = (unsigned char) (hi * 16 + lo);
    }
    return (int) (len / 2);
}

static void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: mgm_tool enc|dec key icn aad input\n");
        return EXIT_FAIL;
    }
    int encrypt = strcmp(argv[1], "enc") == 0;
    if (!encrypt && strcmp(argv[1], "dec") != 0) return EXIT_FAIL;

    unsigned char *key, *icn, *aad, *input;
    int key_len = parse_hex(argv[2], &key);
    int icn_len = parse_hex(argv[3], &icn);
    int aad_len = parse_hex(argv[4], &aad);
    int in_len = parse_hex(argv[5], &input);
    if (key_len != 32 || icn_len != 16 || aad_len < 0 || in_len < 0) return EXIT_FAIL;

    int data_len = encrypt ? in_len : in_len - TAG_LEN;
    if (data_len < 0) return EXIT_FAIL;

    if (OSSL_PROVIDER_load(NULL, "gostprov") == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAIL;
    }
    /*
     * gostprov публикует шифры без свойств, поэтому запрос "provider=gostprov" их не находит.
     * Чтобы результат не зависел от порядка провайдеров, проверяем источник найденного шифра.
     */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-mgm", NULL);
    if (cipher == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAIL;
    }
    const OSSL_PROVIDER *source = EVP_CIPHER_get0_provider(cipher);
    if (source == NULL || strcmp(OSSL_PROVIDER_get0_name(source), "gostprov") != 0) {
        fprintf(stderr, "kuznyechik-mgm is not provided by gostprov\n");
        return EXIT_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *output = malloc(data_len + TAG_LEN + 1);
    unsigned char tag[TAG_LEN];
    int out_len = 0, tmp = 0, status = EXIT_FAIL;
    if (ctx == NULL || output == NULL) return EXIT_FAIL;

    int ok = encrypt ? EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)
                     : EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, icn_len, NULL);
    ok = ok && (encrypt ? EVP_EncryptInit_ex(ctx, NULL, NULL, key, icn)
                        : EVP_DecryptInit_ex(ctx, NULL, NULL, key, icn));
    if (!ok) goto done;

    /*
     * При расшифровании AAD передаётся всегда, даже нулевой длины. Расшифрование gost-engine
     * (gost_mgm128_decrypt) инициализирует Z_1 = E_K(1 || ICN) только внутри обработки AAD, а
     * шифрование (gost_mgm128_encrypt) делает это само. Если AAD не передавать, расшифрование
     * считает неверный тег и отвергает корректный пакет. Вызов нулевой длины обходит дефект и
     * на результат шифрования не влияет, поэтому для шифрования его пропускаем, как делает
     * штатный test_mgm.c.
     */
    if (aad_len > 0 || !encrypt) {
        ok = encrypt ? EVP_EncryptUpdate(ctx, NULL, &tmp, aad, aad_len)
                     : EVP_DecryptUpdate(ctx, NULL, &tmp, aad, aad_len);
        if (!ok) goto done;
    }
    if (data_len > 0) {
        ok = encrypt ? EVP_EncryptUpdate(ctx, output, &out_len, input, data_len)
                     : EVP_DecryptUpdate(ctx, output, &out_len, input, data_len);
        if (!ok) goto done;
        /* Недодача данных иначе проявилась бы лишь расхождением байтов с неясной причиной */
        if (out_len != data_len) goto done;
    }

    if (encrypt) {
        if (EVP_EncryptFinal_ex(ctx, output + out_len, &tmp) <= 0) goto done;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) <= 0) goto done;
        memcpy(output + data_len, tag, TAG_LEN);
        print_hex(output, data_len + TAG_LEN);
        status = 0;
    } else {
        memcpy(tag, input + data_len, TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) <= 0) goto done;
        if (EVP_DecryptFinal_ex(ctx, output + out_len, &tmp) <= 0) {
            status = EXIT_BAD_TAG;
            goto done;
        }
        print_hex(output, data_len);
        status = 0;
    }
done:
    /* При отказе по тегу очередь ошибок - штатный исход, при остальных нужна для диагностики */
    if (status == EXIT_FAIL) ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return status;
}
