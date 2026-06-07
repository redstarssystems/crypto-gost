# Цели

Тестовых векторов из стандарта недостаточно: они подтверждают
корректность реализации алгоритма электронной подписи на фиксированных
данных, но не гарантируют совместимость с другими реализациями. Подпись
может проходить на тестовых векторах и при этом не верифицироваться в BC
или OpenSSL по разным причинам, которые нужно выявлять.

Кросс-валидация применяется после каждого изменения в `crypto-gost-core`
и закрывает две цели:

1.  **Корректность** — подпись, созданная `crypto-gost`, верифицируется
    независимой реализацией, и наоборот.

2.  **Tamper-защита** — испорченная подпись отклоняется обеими
    сторонами, то есть верификация реально проверяет подпись, а не
    возвращает `true` безусловно.

# Алгоритм и кривые

Алгоритм: ГОСТ Р 34.10-2012 (ECGOST3410-2012), хэш — Streebog.

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Кривая</th>
<th style="text-align: left;">Разрядность</th>
<th style="text-align: left;">BC</th>
<th style="text-align: left;">OpenSSL</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>TC26-A-256</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-B-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-C-512</p></td>
<td style="text-align: left;"><p>512 бит</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
</tbody>
</table>

CryptoPro-кривые совместимы по OID: `1.2.643.2.2.35.1/2/3` ↔ OpenSSL
paramset A/B/C. TC26-512-кривые совместимы через `gost2012_512` paramset
A/B/C.

# Что и как проверяется

Подписи одного сообщения двумя библиотеками различаются: `crypto-gost`
использует детерминированный `k` по RFC 6979, BC использует случайный
`k`. Поэтому прямое сравнение значений невозможно — проверка строится на
верификации:

1.  `crypto-gost` подписывает — BC или OpenSSL верифицирует.

2.  BC подписывает — `crypto-gost` верифицирует.

3.  OpenSSL подписывает — `crypto-gost` верифицирует.

4.  Подпись намеренно портится (XOR первого байта s-компоненты) —
    верификатор должен её отклонить.

Для каждой кривой генерируются две независимые пары ключей.  

Первая пара генерируется через KeyGenerator.generateKeyPair(). На ней BC
выполняет все три проверки: crypto-gost подписывает → BC верифицирует,
BC подписывает → crypto-gost верифицирует, tamper в обе стороны. На ней
же OpenSSL верифицирует подписи crypto-gost и отклоняет испорченные.

Вторая — через openssl genpkey. На ней OpenSSL подписывает, crypto-gost
верифицирует. Отдельная пара нужна по техническим причинам: engine gost
кодирует закрытый ключ в little-endian, GostDerCodec — в big-endian.
Передать один ключ между двумя системами невозможно, поэтому OpenSSL
генерирует свой ключ, экспортирует открытую часть через openssl pkey
-pubout, crypto-gost читает её через GostDerCodec.decodePublicKey и
использует для верификации.

Сообщения случайные (100 штук по 1024 байта для BC, 10 для OpenSSL).

# Структура модуля

    x-validation-tests/sign/
      src/test/java/.../crossval/sign/
        TestData.java                     — кривые, параметры теста
        BcSignHelper.java                 — обёртка над BC: подписать, верифицировать, закодировать
        BcSignCrossValidationTest.java      — JUnit 5: crypto-gost vs BC
        OpenSslSignCrossValidationTest.java — JUnit 5: crypto-gost vs OpenSSL

# Покрытие

<table>
<colgroup>
<col style="width: 60%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Что проверяется</th>
<th style="text-align: left;">BC (7 кривых)</th>
<th style="text-align: left;">OpenSSL (6 кривых)</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>crypto-gost подписывает → верификатор
проверяет</p></td>
<td style="text-align: left;"><p>100 проверок</p></td>
<td style="text-align: left;"><p>10 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>верификатор подписывает → crypto-gost
проверяет</p></td>
<td style="text-align: left;"><p>100 проверок</p></td>
<td style="text-align: left;"><p>10 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>испорченная подпись
отклоняется</p></td>
<td style="text-align: left;"><p>200 проверок (оба направления)</p></td>
<td style="text-align: left;"><p>10 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Итого проверок на кривую</p></td>
<td style="text-align: left;"><p>400</p></td>
<td style="text-align: left;"><p>30</p></td>
</tr>
</tbody>
</table>

Итого: BC — `7 × 400 = 2800 проверок`, OpenSSL —
`6 × 30 = 180 проверок`.

# Запуск

    # Совместимость с BouncyCastle и OpenSSL (JUnit 5, 7+6 кривых, 2800+180 проверок)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true

    # Только OpenSSL-проверки (фильтр JUnit, 6 кривых)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true \
        -Dtest=OpenSsl*CrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Из корня проекта (JUnit, для CI)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true

OpenSSL-тесты требуют наличия `engine gost`. Проверить:
`openssl engine gost` и `openssl dgst -streebog256 /dev/null`.
TC26-512-кривые engine gost поддерживает через `gost2012_512`.
