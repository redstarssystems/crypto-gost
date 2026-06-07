# Цели

Кросс-валидация хэшей (Streebog-256/512) и кодов аутентификации
(HMAC-Streebog-256/512, CMAC-Kuznyechik) подтверждает совместимость
реализации `crypto-gost-core` с независимыми библиотеками OpenSSL и
BouncyCastle.

Покрываемые алгоритмы:

- Streebog-256 (хэш, ГОСТ Р 34.11-2012)

- Streebog-512 (хэш, ГОСТ Р 34.11-2012)

- HMAC-Streebog-256 (RFC 7836)

- HMAC-Streebog-512 (RFC 7836)

- CMAC-Kuznyechik (ГОСТ Р 34.13-2015)

# Что и как проверяется

Для каждой комбинации (алгоритм, размер) выполняется одно сравнение:

1.  Генерируется детерминированное сообщение `msg(size)` —
    последовательность байт `0x00, 0x01, ..., 0xFF, 0x00, ...` длиной
    `size`.

2.  Для HMAC и CMAC используется детерминированный ключ `testKey()` — те
    же первые 32 байта последовательности `{0x00..0x1F}`. Для Streebog
    (чистый хэш) ключ не нужен.

3.  Результат `crypto-gost` сравнивается с результатом BC или OpenSSL на
    тех же входных данных: `assertArrayEquals(gost, reference)`.

4.  При несовпадении выводится hex-контекст вокруг первого расходящегося
    байта через `diffContext()`.

Детерминированные данные выбраны намеренно: при расхождении результаты
воспроизводимы без фиксации seed’а.

Итого: `5 алгоритмов × 17 размеров = 85 проверок` на каждый эталон (BC,
OpenSSL).

# Тестовые размеры

Набор размеров ориентирован на граничные условия алгоритмов:

    { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096, 4097 }

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 66%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Группа</th>
<th style="text-align: left;">Цель</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>0, 1</code></p></td>
<td style="text-align: left;"><p>Граничные случаи.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>15, 16, 17</code></p></td>
<td style="text-align: left;"><p>Неполный блок, ровно блок, блок+1
(16-байтный блок Kuznyechik для CMAC).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>63, 64, 65</code></p></td>
<td style="text-align: left;"><p>Граница 64-байтного блока
Streebog.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>127, 128, 129</code></p></td>
<td style="text-align: left;"><p>Двойной блок ±1.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>255, 256, 257</code></p></td>
<td style="text-align: left;"><p>Граница степени двойки.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>1000, 4096, 4097</code></p></td>
<td style="text-align: left;"><p>Умеренный размер, граница 256
блоков.</p></td>
</tr>
</tbody>
</table>

# Структура модуля

    x-validation-tests/digest-mac/
      src/test/java/.../crossval/digestmac/
        TestData.java                    — SIZES, Algo enum, msg(), testKey()
        BcMacHelper.java                 — BC-примитивы (Streebog, HMAC, CMAC)
        OpenSslMacHelper.java            — subprocess-вызов openssl dgst / openssl mac
        BcMacCrossValidationTest.java      — JUnit 5: crypto-gost vs BC
        OpenSslMacCrossValidationTest.java — JUnit 5: crypto-gost vs OpenSSL

Каждый тест выполняет **одно** сравнение на комбинацию (алгоритм,
размер).

# Запуск

    # Кросс-валидация с BouncyCastle и OpenSSL (JUnit 5)
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true

    # Только OpenSSL-проверки (фильтр JUnit)
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true \
        -Dtest=OpenSsl*CrossValidationTest

    # Запуск из корня проекта (JUnit, для CI)
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true

OpenSSL-тесты требуют провайдера GOST (gost-engine или встроенный). Без
них OpenSSL-тесты пропускаются через `Assumptions.assumeTrue`.
Проверить: `openssl dgst -streebog256 /dev/null`
