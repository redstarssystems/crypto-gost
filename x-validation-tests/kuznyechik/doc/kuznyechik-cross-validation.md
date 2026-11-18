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
        CrossVersionTool.java           - файловый CLI + режим serve (worker предыдущей версии)
      src/test/java/.../crossval/kuznyechik/
        BcHelper.java                   - BC-криптопримитивы (CTR, CBC, CFB, OFB)
        CompatHelper.java               - OpenSSL через subprocess
        OldVersionWorker.java           - долгоживущий worker предыдущей версии, бинарный протокол
        TestData.java                   - SIZES[], утилиты
        BcCrossValidationTest.java      - JUnit 5: текущая vs BC
        CrossVersionTest.java           - JUnit 5: текущая vs предыдущая версия
        OpenSslCrossValidationTest.java - JUnit 5: текущая vs OpenSSL
        OpenSslMgmCrossValidationTest.java - JUnit 5: MGM (JCA и MgmCipher) vs OpenSSL
        MgmToolRunner.java              - сборка gcc и запуск C-хелпера mgm_tool
      src/test/resources/
        mgm_tool.c                      - C-хелпер: Кузнечик-MGM на EVP API OpenSSL (gostprov)

BC-тестирование — только JUnit (`BcCrossValidationTest`): BouncyCastle
доступен на classpath напрямую. OpenSSL и кросс-версионный тесты — тоже
через JUnit 5 с `@BeforeAll` graceful skip.

## Технические решения

**Worker вместо JVM на кейс.** Предыдущая версия библиотеки запускается
в отдельной JVM с `OLD_JAR` на classpath — единственный способ избежать
конфликтов загрузчика классов. Раньше JVM поднималась на каждый вызов
(дважды на кейс): 430 стартов, ≈59 с на класс. Теперь `OldVersionWorker`
держит один процесс `CrossVersionTool serve` на весь тестовый класс.

**Бинарный протокол через pipe.** Запросы и ответы идут потоком
`DataInputStream`/`DataOutputStream` через stdin/stdout: версия
протокола, режим, операция, ключ, IV/ICN и payload с префиксами длины.
Данные не пишутся на диск и не передаются через аргументы командной
строки (ограничение ОС 128–256 КБ исключило бы тесты на 262 КБ и 1 МиБ).
Файловый режим `CrossVersionTool` сохранён для ручного CLI-запуска.

**Fail-closed на фрейминге.** Ошибка операции (например, провал
аутентификации MGM) возвращается статусом и не роняет worker. Ошибка
фрейминга или ввода-вывода фатальна: worker завершается, продолжать на
рассинхронизированном потоке нельзя. Размер любого кадра ограничен
сверху.

**Диагностика и таймаут.** stderr worker читается daemon-потоком в
кольцевой буфер последних строк, поэтому заполненный pipe не блокирует
процесс. Запрос ограничен таймаутом; по истечении worker принудительно
уничтожается, а в сообщении остаётся хвост stderr.

**Затирание ключей.** Worker обнуляет ключ через
`SymmetricKey.destroy()` и локальные массивы через `Arrays.fill` после
каждой операции.

**Graceful skip.** OpenSSL-тесты пропускаются
(`Assumptions.assumeTrue`), если OpenSSL недоступен или собран без
поддержки Кузнечика. Кросс-версионный тест падает (`fail`) с понятным
сообщением, если JAR предыдущей версии не найден: без него проверка
обратной совместимости невозможна.

**CTR IV.** CTR по ГОСТ Р 34.13-2015 использует 8-байтный IV. Тесты
генерируют 16 байт, `CrossVersionTool` обрезает до 8 сам; в
`Cipher.encrypt` передаётся `Arrays.copyOf(iv, 8)`.

**MGM.** MGM — AEAD-режим вне `Cipher.Mode`. С предыдущей версией
сверяется `MgmCipher.sealWithIcn/open` (пустой AAD на все размеры, а для
размера 0 непустой AAD: MGM отвергает пустой открытый текст без AAD, RFC
9058 §6; три направления на все размеры). BouncyCastle MGM не
поддерживает. С OpenSSL MGM сверяет `OpenSslMgmCrossValidationTest`:
утилита `openssl enc` AEAD не умеет, поэтому эталоном служит небольшая
C-программа `mgm_tool.c` на EVP API (`kuznyechik-mgm` из провайдера
gostprov). `MgmToolRunner` собирает её `gcc` один раз за прогон. Тест
пропускается только при отсутствии предпосылок (`gcc`, заголовки и
`libcrypto` OpenSSL, `gostprov.so`, возможность запускать файлы из
каталога временных файлов: он может быть смонтирован с `noexec`); если
они есть, а сборка или запуск упали, тест падает. Матрица: AAD {0, 1,
15, 16, 17, 41, 100} байт × открытый текст {0, 1, 16, 17, 67} байт
(кроме пары пустых). Для каждой пары JCA `Kuznyechik/MGM/NoPadding` и
`MgmCipher.sealWithIcn` совпадают с OpenSSL байт в байт, OpenSSL
расшифровывает наши пакеты, мы — его пакеты. Отдельно: `updateAAD` и
`update` порциями 1, 7 и 16 байт (хелпер принимает AAD целиком, так что
порции сверяются с одним вызовом OpenSSL); искажение тега, шифртекста и
AAD отвергается обеими сторонами; при пустых P и A тег OpenSSL не
зависит от ICN и равен `E_K(0)`, чем подтверждается довод RFC 9058 §6, а
библиотека такое сообщение отвергает.

# Ограничения

**Пространство API предыдущего релиза.** `CrossVersionTool`
компилируется против текущего core, а исполняется против `OLD_JAR`.
Поэтому режим `serve` может вызывать только методы, существующие в
предыдущем релизе
(`Cipher.encrypt/decrypt(data, key, iv, mode[, padding])`,
`MgmCipher.sealWithIcn/open`, `SymmetricKey(byte[])`,
`SymmetricKey.destroy()`). Новый overload даст `NoSuchMethodError`
только в рантайме.

**Общая статика.** Worker живёт весь тестовый класс, поэтому статическое
состояние предыдущей версии общее для всех кейсов. Для проверки
совместимости шифртекстов это приемлемо; более того, проверяется и
«прогретое» состояние, а не только холодный старт.

**Расшифрование MGM в gost-engine без AAD.** Проверено на gost-engine
v3.0.3-85: `gost_mgm128_decrypt` не вычисляет Z₁ = E\_K(1 ‖ ICN), если
AAD не передавался (шифрование делает это само), и для пакета без AAD
считает неверный тег. Шифртекст и тег при шифровании совпадают с нашими,
расходится только расшифрование самого движка. Хелпер `mgm_tool` при
расшифровании всегда вызывает обновление AAD нулевой длины: это обходит
дефект и результата не меняет. Тест этот дефект не закрепляет.

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
<td style="text-align: left;"><p>✓</p></td>
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

    # Только MGM против OpenSSL (нужны gcc, заголовки OpenSSL и gostprov.so)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=OpenSslMgmCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только кросс-версионная проверка между crypto-gost (фильтр JUnit)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=CrossVersionTest -Dsurefire.failIfNoSpecifiedTests=false
