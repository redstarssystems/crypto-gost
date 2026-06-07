# Цели

Тестовых векторов из стандарта недостаточно: они не выявляют дефекты
реализации режимов шифрования на граничных размерах данных и не
подтверждают совместимость с другими реализациями. Кросс-валидация
применяется после каждого рефакторинга `crypto-gost-core` и закрывает
три цели:

1.  **Корректность** — рефакторинг не нарушил криптографическую
    семантику ни в одном режиме.

2.  **Обратная совместимость** — шифртекст текущей версии
    расшифровывается предыдущей, и наоборот.

3.  **Совместимость с независимыми реализациями** — шифртекст совпадает
    с результатом BouncyCastle 1.84 и OpenSSL 3.x.

# Тестовые размеры

Единый массив `SIZES` используется во всех тестах:

    { 0, 1, 15, 16, 17, 50, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257,
      1000, 4080..4097, 10000, 65534..65537, 262144, 1048576, 1048577 }

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
<td style="text-align: left;"><p>Граничные случаи. CBC на
<code>size=0</code> шифрует в 16 байт PKCS7-паддинга — поведение
согласовано с OpenSSL.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>15, 16, 17</code></p></td>
<td style="text-align: left;"><p>Неполный блок, ровно блок, блок+1.
Хвостовая обработка и корректность паддинга CBC.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>63–65</code>,
<code>127–129</code>, <code>255–257</code></p></td>
<td style="text-align: left;"><p>Границы степеней двойки — выявляют
однобайтовые переполнения в счётчике.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>4080–4097</code></p></td>
<td style="text-align: left;"><p>Переход 255→256 блоков. Регрессионная
защита от дефектов счётчика CTR (класс <a
href="https://www.cve.org/CVERecord?id=CVE-2025-14813">CVE-2025-14813</a>).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>65534–65537</code></p></td>
<td style="text-align: left;"><p>Пред-граница, граница и переполнение
16-битного беззнакового счётчика (<code>65535 → 65536</code>). Выявляет
усечение до <code>short</code>/<code>char</code>.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>262144</code></p></td>
<td style="text-align: left;"><p>Давление на <code>long</code>-счётчик,
согласованность <code>processBlocks</code> и
<code>calculateByte</code>.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>1048576, 1048577</code></p></td>
<td style="text-align: left;"><p>1 МБ ± 1 байт. Стресс и проверка
хвостовой обработки на реалистичных объёмах.</p></td>
</tr>
</tbody>
</table>

CBC тестируется в двух вариантах: с PKCS7-паддингом (все размеры) и без
паддинга (только кратные 16). Для CBC/NoPad в OpenSSL передаётся
`-nopad`, в crypto-gost — `Cipher.Padding.NONE`.

# Структура модуля

    x-validation-tests/kuznyechik/
      src/main/java/.../crossval/kuznyechik/
        CrossVersionTool.java  - subprocess-хелпер для предыдущей версии JAR
      src/test/java/.../crossval/kuznyechik/
        BcHelper.java                   - BC-криптопримитивы (CTR, CBC, CFB, OFB)
        CompatHelper.java               - общие методы: subprocess, OpenSSL
        TestData.java                   - SIZES[], утилиты
        BcCrossValidationTest.java      - JUnit 5: текущая vs BC
        CrossVersionTest.java           - JUnit 5: текущая vs предыдущая версия
        OpenSslCrossValidationTest.java - JUnit 5: текущая vs OpenSSL

BC-тестирование — только JUnit (`BcCrossValidationTest`): BouncyCastle
доступен на classpath напрямую. OpenSSL и кросс-версионный тесты — тоже
через JUnit 5 с `@BeforeAll` graceful skip.

## Технические решения

**Данные через файлы.** `CrossVersionTool` принимает пути к файлам, не
hex-аргументы — аргументы командной строки ограничены ОС (128–256 КБ),
что делало бы тесты на 262 КБ и 1 МБ невозможными.

**Subprocess для изоляции версий.** Предыдущая версия библиотеки
запускается в отдельной JVM с `OLD_JAR` на classpath — единственный
способ избежать конфликтов загрузчика классов.

**Graceful skip.** Тесты пропускаются (`Assumptions.assumeTrue`) с
понятным сообщением если предыдущий JAR не найден или OpenSSL собран без
поддержки Кузнечика. Основная CI-сборка не ломается.

**CTR IV.** CTR по ГОСТ Р 34.13-2015 использует 8-байтный IV. Тесты
генерируют 16 байт, `CrossVersionTool` обрезает до 8 сам; в
`Cipher.encrypt` передаётся `Arrays.copyOf(iv, 8)`.

**MGM.** MGM — AEAD-режим вне `Cipher.Mode`. Тестируется только
кросс-версионно (`MgmCipher.sealWithIcn/open`, пустой AAD, три
направления на все размеры). BC и OpenSSL MGM не поддерживают.

# Покрытие

<table>
<colgroup>
<col style="width: 38%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Что проверяется</th>
<th style="text-align: left;">CTR</th>
<th style="text-align: left;">CBC</th>
<th style="text-align: left;">CFB</th>
<th style="text-align: left;">OFB</th>
<th style="text-align: left;">MGM</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>KAT-векторы (существующие
тесты)</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Совместимость с предыдущей
версией</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Совместимость с OpenSSL</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Совместимость с BouncyCastle
1.84</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Граничные и стрессовые размеры</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CBC без паддинга (NoPad)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Каждая ячейка ✓ означает три проверки: совпадение шифртекстов,
расшифровка в обе стороны.

# Запуск

    # Все тесты (BC + OpenSSL + кросс-версия, JUnit 5)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true

    # Только OpenSSL-проверки (фильтр JUnit)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=OpenSslCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только кросс-версионная проверка между crypto-gost (фильтр JUnit)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=CrossVersionTest -Dsurefire.failIfNoSpecifiedTests=false
