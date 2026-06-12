Данный документ содержит инструкцию по сборке openssl для CI или любом
чистом окружении.

# Требования

1.  В ОС должны присутствовать следующие пакеты:

    - util-linux (getconf)

    - perl 5+

    - make

    - gcc

    - cmake

    - git

    - wget

# Параметры сборки

Для воспроизводимости фиксируем конрктеные коммиты.

**GOST\_ENGINE\_COMMIT** = `3dd0f0e4299489a537398cfa4d9daad260ac87a8`

**LIBPROV\_COMMIT** = `d5d381f71c90fe0c91f861784b715b189554f1f2`

Обновлять эти хеши — когда требуется свежая версия gost-engine.

# Порядок сборки

## Подготовка исходников

    cd /tmp

    # OpenSSL 3.6.0
    wget -q https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
    tar xzf openssl-3.6.0.tar.gz

    # gost-engine — фиксированный коммит
    git clone https://github.com/gost-engine/engine.git gost-engine-src
    git -C gost-engine-src checkout ${GOST_ENGINE_COMMIT}

## Патч TLS 1.3

    cd /tmp/openssl-3.6.0

    patch -p2 < /tmp/gost-engine-src/patches/openssl-tls1.3.patch
    # exit code 0 — успешно

    # Проверка — патч не должен задвоиться
    test $(grep -c "SSL_MAGMA_MGM" ssl/tls13_enc.c) = 1
    test $(grep -c "SSL_KUZNYECHIK_MGM" ssl/tls13_enc.c) = 1

## Патч верификации сертификатов Streebog

    cd /tmp/openssl-3.6.0

    # Фикс 1: явные secbits для Streebog-256/512 в x509_sig_info_init
    patch -p1 << 'PATCH1'
    --- a/crypto/x509/x509_set.c
    +++ b/crypto/x509/x509_set.c
    @@ -278,6 +278,14 @@
             siginf->secbits = 105;
             break;
    +    case NID_id_GostR3411_2012_256:
    +        siginf->secbits = 128;
    +        break;
    +    case NID_id_GostR3411_2012_512:
    +        siginf->secbits = 256;
    +        break;
         default:
    PATCH1

    # Фикс 2: fallback EVP_MD_fetch в a_verify.c
    patch -p1 << 'PATCH2'
    --- a/crypto/asn1/a_verify.c
    +++ b/crypto/asn1/a_verify.c
    @@ -178,7 +178,11 @@
                 if (mdnid != NID_undef) {
    -                type = EVP_get_digestbynid(mdnid);
    +                if ((type = EVP_get_digestbynid(mdnid)) == NULL) {
    +                    const char *md_name = OBJ_nid2sn(mdnid);
    +                    if (md_name != NULL)
    +                        type = EVP_MD_fetch(NULL, md_name, NULL);
    +                }
                     if (type == NULL) {
    PATCH2

    # Проверки
    grep -q "NID_id_GostR3411_2012_256.*secbits = 128" crypto/x509/x509_set.c
    echo "OK: x509_set.c"
    grep -q "EVP_MD_fetch" crypto/asn1/a_verify.c
    echo "OK: a_verify.c"

## Сборка OpenSSL

    cd /tmp/openssl-3.6.0

    ./Configure                           \
      --prefix=/opt/openssl-3.6.0-gost    \
      --libdir=lib                        \
      --openssldir=/opt/openssl-3.6.0-gost/ssl \
      shared                              \
      -Wl,-rpath=/opt/openssl-3.6.0-gost/lib

    make -j$(getconf _NPROCESSORS_ONLN)
    make install_sw

## Инициализация submodule gost-engine

    cd /tmp/gost-engine-src

    # libprov — фиксированный коммит
    git submodule update --init
    git -C libprov checkout ${LIBPROV_COMMIT}

## Сборка gost-engine как провайдера

    cd /tmp/gost-engine-src
    mkdir -p build && cd build

    cmake ..                                                        \
      -DOPENSSL_ROOT_DIR=/opt/openssl-3.6.0-gost                    \
      -DCMAKE_BUILD_TYPE=Release                                    \
      -DOPENSSL_ENGINES_DIR=/opt/openssl-3.6.0-gost/lib/engines-3

    make -j$(getconf _NPROCESSORS_ONLN)

    mkdir -p /opt/openssl-3.6.0-gost/lib/ossl-modules
    cp bin/gostprov.so /opt/openssl-3.6.0-gost/lib/ossl-modules/
    cp bin/libgostprov.so /opt/openssl-3.6.0-gost/lib/

## 8. Проверка

    /opt/openssl-3.6.0-gost/bin/openssl version
    # → OpenSSL 3.6.0 1 Oct 2025

    /opt/openssl-3.6.0-gost/bin/openssl ciphers -s -tls1_3 \
      -ciphersuites TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L \
      -provider gostprov -provider default
    # → TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L

    # Проверка верификации цепочки сертификатов с сервером, работающим на localhost:8443
    # echo | /opt/openssl-3.6.0-gost/bin/openssl s_client \
    #   -connect localhost:8443 -tls1_3 \
    #   -ciphersuites TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L \
    #   -curves GC256B \
    #   -provider gostprov -provider default -verify_return_error
    # → Verify return code: 0 (ok)

# Примечания

- Патч `openssl-tls1.3.patch` меняет `tls13_enc.c` — для поддержки
  MGM-режимов (MAGMA/KUZNYECHIK) в TLS 1.3 HKDF.

- Два дополнительных патча исправляют верификацию сертификатов с
  ГОСТ-подписями (Streebog-256/512):

  - `x509_set.c` — явные secbits для Streebog-256 (128) и Streebog-512
    (256)

  - `a_verify.c` — fallback на `EVP_MD_fetch` если `EVP_get_digestbynid`
    не находит дайджест

- RPATH вшит прямо в бинарник openssl — `LD_LIBRARY_PATH` не требуется.

- gost-provider грузится флагом `-provider gostprov`.

- Коммиты gost-engine и libprov зафиксированы для воспроизводимой
  сборки. Обновлять — только осознанно.
