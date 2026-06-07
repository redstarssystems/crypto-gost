# Цели

Кросс-валидация ключей проверяет, что crypto-gost производит те же
математические результаты и те же DER-структуры, что и две широко
признанные эталонные реализации: BouncyCastle (Java) и OpenSSL с
gostprov/engine gost.

Проверяется:

1.  **DER roundtrip** — сериализация ключа в DER и обратное чтение через
    crypto-gost (целостность `GostDerCodec`).

2.  **Параметры crypto-gost → BC** — конвертация кривых параметров из
    crypto-gost в BouncyCastle и обратно, сравнение d и Q.

3.  **Параметры BC → crypto-gost + Q = d·G** — BC генерирует ключи,
    crypto-gost принимает, плюс верификация через скалярное умножение
    (`ECPoint.multiply`).

4.  **ASN.1 DER структура** — OID алгоритма подписи (256/512 бит) и OID
    кривой в DER-представлении ключа, проверенные через BC ASN.1 парсер.

5.  **ECDH симметричность** —
    `KeyAgreement.computeSharedSecret(A.priv, B.pub)` ==
    `KeyAgreement.computeSharedSecret(B.priv, A.pub)` для crypto-gost и
    BC независимо.

6.  **ECDH межреализационная совместимость** — shared secret совпадает
    между crypto-gost, BC и OpenSSL gostprov для всех поддерживаемых
    кривых.

# Кривые

<table style="width:100%;">
<colgroup>
<col style="width: 34%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 16%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Кривая</th>
<th style="text-align: left;">Разрядность</th>
<th style="text-align: left;">BC</th>
<th style="text-align: left;">OpenSSL</th>
<th style="text-align: left;">ECDH (OpenSSL)</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>TC26-A-256</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-B-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-C-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
</tbody>
</table>

TC26-A-256 не поддерживается OpenSSL gostprov — нет paramset:D для
256-бит кривых.

# Что и как проверяется

Для каждой кривой генерируется случайная ключевая пара — свежая на
каждый тест.

## BC-тесты (4 проверки × 7 кривых = 28 проверок)

1.  **DER roundtrip** — ключ → DER-кодирование (`GostDerCodec`) →
    DER-декодирование → сравнение Q (x, y) и d.

2.  **crypto-gost → BC** — ключи crypto-gost → BouncyCastle
    `ECDomainParameters`, сравнение d и Q.

3.  **BC → crypto-gost** — ключи BC → crypto-gost + верификация
    `G * d == Q` через `ECPoint.multiply(d)`.

4.  **ASN.1 DER структура** — парсинг DER через `SubjectPublicKeyInfo` /
    `PrivateKeyInfo` BC, сравнение OID алгоритма и OID кривой.

## OpenSSL-тесты (2 проверки × 6 кривых = 12 проверок)

Для каждой openssl-совместимой кривой (CryptoPro-A/B/C, TC26-A/B/C-512):

1.  **OpenSSL genpkey → crypto-gost** — gostprov генерирует ключ через
    `openssl genpkey`, DER читается через
    `GostDerCodec.decodePrivateKey`, затем проверяется Q = d·G.

2.  **crypto-gost → OpenSSL pkey** — crypto-gost генерирует ключ, DER
    читается через `openssl pkey`.

## ECDH BC-тесты (3 сценария × 7 кривых = 21 проверка)

Все семь кривых, precondition не требуется.

1.  **crypto-gost обе стороны** — `computeSharedSecret(A.priv, B.pub)`
    == `computeSharedSecret(B.priv, A.pub)`. Проверяет симметричность и
    математическую корректность реализации.

2.  **BC обе стороны** — `ECDHBasicAgreement(A.priv, B.pub)` ==
    `ECDHBasicAgreement(B.priv, A.pub)`. Независимая проверка
    симметричности на стороне BC.

3.  **crypto-gost × BC** — crypto-gost вычисляет shared secret с
    BC-публичным ключом, BC вычисляет shared secret с
    crypto-gost-публичным ключом, результаты сравниваются. Проверяет
    совместимость представления ключей и идентичность алгоритма d·Q.

## ECDH OpenSSL-тесты (3 сценария × 6 кривых = 18 проверок)

Для каждой openssl-совместимой кривой (CryptoPro-A/B/C, TC26-A/B/C-512).
Precondition: OpenSSL + gostprov доступны, `pkeyutl -derive` работает.

1.  **crypto-gost обе стороны vs OpenSSL** — crypto-gost вычисляет
    shared secret, OpenSSL `pkeyutl -derive` вычисляет тот же secret с
    теми же DER-ключами. Проверяет wire-формат ключей и алгоритм.

2.  **OpenSSL обе стороны vs crypto-gost** — OpenSSL генерирует оба
    ключа, `pkeyutl -derive` вычисляет shared secret, crypto-gost читает
    DER-ключи и вычисляет тот же результат.

3.  **Смешанный (crypto-gost A × OpenSSL B)** — crypto-gost генерирует
    ключ A, OpenSSL генерирует ключ B. crypto-gost вычисляет
    `A.priv × B.pub`, OpenSSL вычисляет `A.priv × B.pub`. Дополнительно
    проверяется симметричность: `B.priv × A.pub` (crypto-gost) ==
    `A.priv × B.pub`.

# Структура модуля

    x-validation-tests/keys/
      src/test/java/.../crossval/keys/
        TestData.java                         — кривые, флаги совместимости
        BcKeyHelper.java                      — обёртка над BC: domain, конвертация, ASN.1
        BcKeyCrossValidationTest.java         — JUnit 5: crypto-gost vs BC (ключи)
        BcEcdhCrossValidationTest.java        — JUnit 5: crypto-gost vs BC (ECDH)
        OpenSslKeysCrossValidationTest.java   — JUnit 5: crypto-gost vs OpenSSL (ключи)
        OpenSslEcdhCrossValidationTest.java   — JUnit 5: crypto-gost vs OpenSSL (ECDH)

## Технические решения

**Graceful skip.** `@BeforeAll` в OpenSSL-тестах проверяет доступность
бинарника и gostprov. При недоступности тесты пропускаются через
`Assumptions.assumeTrue`.

**`assumeGostDerive`.** Отдельная probe-проверка
`OpenSslChecker.assumeGostDerive()`: запускает `pkeyutl -derive` с
временными ключами. Некоторые конфигурации OpenSSL поддерживают genpkey,
но не pkeyutl -derive для ГОСТ.

**Путь к бинарнику.** `OpenSslChecker.resolveOpenSslBinary()` читает
системное свойство `openssl.binary`, затем переменную окружения
`OPENSSL_BIN`, иначе — `openssl` из `$PATH`.

**Фильтрация кривых.** `TestData.CurveSpec` содержит три флага:
`opensslGenSupported`, `opensslReadSupported`, `ecdhSupported` — каждый
тест перебирает только совместимые кривые.

**OID-совместимость 512-бит кривых.** OpenSSL использует OID
`1.2.643.7.1.2.1.2.x` для TC26-A/B/C-512. После исправления в
`GostCurves` эти OID совпадают, и crypto-gost читает OpenSSL-ключи без
ошибок.

**Конвертация LE → BE для BC.** `ECDHBasicAgreement.calculateAgreement`
возвращает X-координату как `BigInteger` (big-endian). Утилита
`toLeBytes` конвертирует в little-endian фиксированной длины `hlen` —
формат совпадает с `KeyAgreement.computeSharedSecret`.

# Покрытие

<table style="width:100%;">
<colgroup>
<col style="width: 42%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Что проверяется</th>
<th style="text-align: left;">BC ключи</th>
<th style="text-align: left;">BC ECDH</th>
<th style="text-align: left;">OpenSSL ключи</th>
<th style="text-align: left;">OpenSSL ECDH</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>DER roundtrip: encode → decode, Q и d
совпадают</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>crypto-gost → BC: d и Q передаются без
потерь</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>BC → crypto-gost: Q = d·G</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ASN.1: OID алгоритма и кривой в DER
верны</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDH симметричность crypto-gost: A·B ==
B·A</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDH симметричность BC: A·B ==
B·A</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDH crypto-gost × BC: shared secret
совпадает</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (7)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>OpenSSL genpkey → crypto-gost: читает
ключ, Q = d·G</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (6)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>crypto-gost → OpenSSL pkey: OpenSSL
читает DER</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (6)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>crypto-gost ключи → pkeyutl -derive
совпадает</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (6)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>OpenSSL ключи → KeyAgreement
совпадает</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (6)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Смешанный + симметричность (A·B ==
B·A)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (6)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Итого проверок</p></td>
<td style="text-align: left;"><p>28</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>12</p></td>
<td style="text-align: left;"><p>18</p></td>
</tr>
</tbody>
</table>

Итого: **79 проверок** (28 + 21 + 12 + 18).

# Запуск

    # Все тесты модуля (79 проверок)
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true

    # Только ECDH-тесты
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true \
        -Dtest="BcEcdhCrossValidationTest,OpenSslEcdhCrossValidationTest"

    # С кастомным OpenSSL
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true \
        -Dopenssl.binary=/path/to/openssl

    # Без OpenSSL (только BC, 49 проверок — всегда зелёные)
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true \
        -Dtest="BcKeyCrossValidationTest,BcEcdhCrossValidationTest"
