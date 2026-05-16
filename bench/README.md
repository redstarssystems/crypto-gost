Результаты сравнения **crypto-gost-core** и **BouncyCastle 1.83** в
части операций электронной подписи:

- [Результаты сравнения для 256
  бит](results/signature/ecgost256-throughput.png)

- [Результаты сравнения для 512
  бит](results/signature/ecgost512-throughput.png)

Результаты сравнения **crypto-gost-core** и **BouncyCastle 1.83** в
части операций шифрования "Кузнечик":

- [Результаты сравнения режима
  CTR](results/kuznyechik/kuznyechik-ctr-throughput.png)

- [Результаты сравнения режима
  CFB](results/kuznyechik/kuznyechik-cfb-throughput.png)

# Методики бенчмарков

**Все тесты производились на ОС AltLinux p11 x86\_64 с установленным
OpenSSL+ГОСТ.**

## Бенчмарк электронной подписи ГОСТ Р 34.10-2012

Расположение: папка `bench/signature`.

### Что измеряется

Пропускная способность (ops/s) операций подписания и верификации по ГОСТ
Р 34.10-2012 на двух группах кривых:

- **256-бит** — кривая CryptoPro-A (RFC 4357)

- **512-бит** — кривая TC26-A-512 (RFC 7836)

### Что сравнивается

**crypto-gost** (низкоуровневый API: `ECDSASigner` + `Streebog256/512`)
против **BouncyCastle** (`ECGOST3410_2012Signer`). Обе библиотеки
используют одну и ту же ключевую пару.

**crypto-gost** использует детерминированный нонс k (RFC 6979 +
HMAC-Стрибог), BouncyCastle — случайный `SecureRandom`. Это влияет на
скорость подписания, но не верификации.

### Что не входит в измерение

Объекты подписи (`ECDSASigner`, `ECGOST3410_2012Signer`) создаются в
`@Setup` и переиспользуются через `init()`.  

Измеряется только hash-then-sign / hash-then-verify без накладных
расходов на аллокации объектов.

### Параметры JMH

- 5 итераций прогрева × 2 с.

- 5 итераций замера × 2 с.

- 3 форка JVM.

Итого ~60 с на один режим (256/512) × операцию (sign/verify). Три форка
устраняют JIT-зависимости между запусками.

### Как воспроизвести

    make build              # сборка uber-jar
    make bench-256 plot     # 256-бит бенчмарк + график
    make bench-512 plot-512 # 512-бит бенчмарк + график
    make bench-all          # оба бенчмарка

### Как читать графики

Гистограммы показывают среднее значение ops/s, планки погрешностей —
99.9% доверительный интервал JMH.  
Если планки двух столбцов перекрываются — разница статистически
незначима.

## Кузнечик

**Расположение**: Каталог *bench/kuznyechik*

**Запуск:** `make bench`

**Что измеряется:** Пропускная способность симметричного шифрования
Кузнечик (ГОСТ Р 34.12-2015) в режимах CTR и CFB при разных размерах
буфера: 1 КБ, 10 КБ, 100 КБ, 1 МБ. Результат — МБ/с обработанных данных.

**Что сравнивается:** crypto-gost (низкоуровневый API: Ctr/Cfb +
processBytes) против **BouncyCastle** (SICBlockCipher/CFBBlockCipher +
processBytes). Обе библиотеки используют один и тот же ключ и IV,
созданные через KeyGenerator.generateSymmetricKey().

**Что не входит в измерение:** Создание объектов шифра и ключевое
расписание вынесены в @Setup — они выполняются один раз до замера.
Бенчмарк измеряет только время обработки данных, без накладных расходов
на аллокации.

**Как обеспечивается честность:**

- IV инкрементируется на каждой итерации — JIT не может кешировать
  одинаковый результат.

- Входные данные читаются из бинарного файла со случайным содержимым
  (генерируется dd if=/dev/urandom).

- Оба соперника переинициализируют шифр перед каждым вызовом одинаково.

**Параметры JMH:**

5 итераций прогрева × 2 с + 5 итераций замера × 2 с + 3 форка JVM. Итого
~60 секунд на один режим. Три форка устраняют JIT-зависимости между
запусками, 5 итераций дают надёжный доверительный интервал (99.9% CI
выводится автоматически JMH).

**Как воспроизвести:** make data \# генерация тестовых файлов make build
\# сборка uber-jar make bench \# запуск обоих бенчмарков make plot \#
построение графиков (требует gnuplot)

**Как читать графики:** Гистограммы показывают среднее значение MB/s,
планки погрешностей — 99.9% доверительный интервал JMH. Если планки двух
столбцов перекрываются — разница статистически незначима.

# Методики кросс-валидации

Каталог *bench/signature*.

## Кросс-валидация электронной подписи ГОСТ Р 34.10-2012 с BouncyCastle

### Цель

Подтвердить **совместимость** реализации **crypto-gost** с BouncyCastle
1.83: подписи, выработанные одной библиотекой, должны успешно
верифицироваться другой.

### Структура

Каждый тест **двунаправленный**:

- `crypto-gost → bc` — crypto-gost подписывает, BC верифицирует.

- `bc → crypto-gost` — BC подписывает, crypto-gost верифицирует.

Покрытие: все 7 стандартных кривых ГОСТ Р 34.10-2012:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Кривая</p></td>
<td style="text-align: left;"><p>Размер</p></td>
<td style="text-align: left;"><p>Стандарт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-256</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-B-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-C-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
</tbody>
</table>

По 100 случайных сообщений на кривую (итого 1400 проверок).

### Как воспроизвести

    make cross-validate-256  # все 256-бит кривые
    make cross-validate-512  # все 512-бит кривые
    make cross-validate-all  # все 7 кривых

### Ожидаемый результат

    All 1400 cross-validation checks PASSED. ✓

## Кросс-валидация электронной подписи ГОСТ Р 34.10-2012 с OpenSSL (ГОСТ)

### Цель

Подтвердить **совместимость** реализации **crypto-gost** с **OpenSSL
3.3.х (ГОСТ)**: подписи, выработанные библиотекой, должны успешно
верифицироваться независимой реализацией OpenSSL..

### Структура

**Направление:** crypto-gost подписывает → OpenSSL верифицирует.

Покрытие: 3 стандартных кривых ГОСТ Р 34.10-2012:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Кривая</p></td>
<td style="text-align: left;"><p>Размер</p></td>
<td style="text-align: left;"><p>Стандарт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
</tbody>
</table>

**Ограничение:** TC26-A-256 и 512-бит кривые не поддерживаются engine
gost на данной системе.

**Алгоритм одного теста:**

1.  Генерируется случайный закрытый ключ (openssl rand -hex 32) и
    случайное сообщение (1 КБ из /dev/urandom).

2.  SignatureTool (crypto-gost) вычисляет публичный ключ Q=d·G и
    экспортирует его в DER SubjectPublicKeyInfo.

3.  SignatureTool подписывает сообщение — формат r||s (big-endian).

4.  Подпись конвертируется в формат OpenSSL engine gost: s||r.

5.  OpenSSL dgst -streebog256 -engine gost -verify верифицирует.

6.  Tamper-тест: XOR первого байта подписи — OpenSSL должен отклонить.

**Формат подписи (важно для совместимости):** crypto-gost : r\_BE ||
s\_BE OpenSSL gost: s\_BE || r\_BE

Скрипт выполняет перестановку автоматически.

### Как воспроизвести

    make cross-validate-openssl  # 3 кривых 256 бит, требует OpenSSL engine gost

### Ожидаемый результат

      Сводка:
        Всего проверок:  60
        Пройдено:        60
        Ошибок:          0
        Статус:          УСПЕХ

## Кузнечик

**Расположение**: Каталог *bench/kuznyechik*

**Запуск:**

- `make cross-validate` \# **crypto-gost ↔ BouncyCastle.**

- `make cross-validate-openssl` \# **crypto-gost ↔ OpenSSL** (требует
  OpenSSL 3.x с ГОСТ).

**Цель:** Подтвердить совместимость реализации Кузнечика в
**crypto-gost** с независимыми реализациями (BouncyCastle 1.83 и OpenSSL
3.x), а также дополнительно подтвердить корректность алгоритма через три
независимых источника.

**Структура:** Две независимые кросс-валидации:

1.  **crypto-gost** ↔ **BouncyCastle 1.83**
    (KuznyechikCrossValidation.java)

    Каждый тест двунаправленный:

    - gost→bc: crypto-gost шифрует → BC расшифровывает → сравниваем с
      исходником.

    - bc→gost: BC шифрует → crypto-gost расшифровывает → сравниваем с
      исходником.

      **Режимы**: CTR, CBC/PKCS7, CBC/NoPad, CFB, OFB, MGM (только
      roundtrip, BC не поддерживает MGM).

      **Размеры данных:** 0, 1, 16, 255, 10000 байт — покрывают пустые
      данные, 1 байт, ровно один блок, некратный блоку, большой буфер.

      **Дополнительно:** тест со случайными данными и случайными IV
      через SecureRandom для CTR и CFB — исключает зависимость от
      предсказуемых паттернов.

2.  **crypto-gost** ↔ **OpenSSL 3.x** (cross-validate-openssl.sh)

    Использует KuznyechikTool — CLI-обёртку над crypto-gost API — как
    мост между Java и OpenSSL.

    Каждый тест двунаправленный:

    - openssl → crypto-gost: OpenSSL шифрует файл → KuznyechikTool
      расшифровывает → сравнение.

    - crypto-gost → openssl: KuznyechikTool шифрует файл → OpenSSL
      расшифровывает → сравнение.

      Ключ и IV генерируются случайно через openssl rand на каждый тест.

      **Режимы:** CTR, CBC/PKCS7, CBC/NoPad, CFB, OFB.

      **Совместимость CTR IV:** ГОСТ Р 34.13-2015 определяет CTR IV как
      8 байт, счётчик = IV || 0x00\*8. OpenSSL kuznyechik-ctr принимает
      16-байтный IV и интерпретирует его как начальное значение
      счётчика. Совместимость обеспечена: crypto-gost использует IV8 ||
      0x00\*8, OpenSSL получает тот же 16-байтный вектор — результаты
      шифрования совпадают.

## Методика кросс-валидации: хэш-функции и кода аутентификации (имитовставки)

Кросс-валидация подтверждает корректность реализации путём сравнения
результатов **crypto-gost** с двумя независимыми реализациями:
**BouncyCastle 1.83** и **OpenSSL 3.3.x** с ГОСТ-провайдером.

### Покрытие

<table>
<colgroup>
<col style="width: 60%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Алгоритм</th>
<th style="text-align: left;">BouncyCastle 1.83</th>
<th style="text-align: left;">OpenSSL 3.x</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Streebog-256 (ГОСТ Р
34.11-2012)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Streebog-512 (ГОСТ Р
34.11-2012)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HMAC-Streebog-256 (RFC 7836)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HMAC-Streebog-512 (RFC 7836)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CMAC-Кузнечик (ГОСТ Р
34.13-2015)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Итого</strong></p></td>
<td style="text-align: left;"><p><strong>90 проверок</strong></p></td>
<td style="text-align: left;"><p><strong>25 проверок</strong></p></td>
</tr>
</tbody>
</table>

### Кросс-валидация с BouncyCastle

Для каждого алгоритма и каждого размера сообщения
`{0, 1, 8, 16, 32, 64, 256, 1024, 65535}` байт проверяются два
направления:

- `crypto-gost → BC` — crypto-gost вычисляет тег/хэш, BouncyCastle
  проверяет совпадение.

- `BC → crypto-gost` — BouncyCastle вычисляет тег/хэш, crypto-gost
  проверяет совпадение.

Используется высокоуровневый API: `api/Digest` и `api/CmacApi`.

### Кросс-валидация с OpenSSL

Для каждого алгоритма и каждого размера сообщения
`{0, 1, 16, 255, 1024}` байт с уникальным случайным ключом (32 байта,
`openssl rand -hex 32`) проверяется направление:

- `crypto-gost → openssl` — crypto-gost вычисляет результат через
  `MacTool`, OpenSSL вычисляет тот же результат независимо, значения
  сравниваются побайтово.

  Команды OpenSSL:

<!-- -->

    # Streebog-256 / Streebog-512
    openssl dgst -streebog256 -r <file>
    openssl dgst -streebog512 -r <file>
    # HMAC-Streebog-256 / HMAC-Streebog-512
    openssl mac -digest streebog256 -macopt hexkey:<KEY> HMAC < <file>
    openssl mac -digest streebog512 -macopt hexkey:<KEY> HMAC < <file>
    # CMAC-Kuznyechik
    openssl mac -cipher kuznyechik-cbc -macopt hexkey:<KEY> CMAC < <file>

### Требования

- Java 21+

- BouncyCastle 1.83 (`bcprov-jdk18on`)

- OpenSSL 3.x с GOST-провайдером (поддержка `streebog256`,
  `kuznyechik-cbc`)

### Как воспроизвести

    # Сборка
    cd bench/mac
    make build

    # Кросс-валидация с BouncyCastle (лог: results/cross-validate-bc.log)
    make cross-validate

    # Кросс-валидация с OpenSSL (лог: results/cross-validate-openssl.log)
    make cross-validate-openssl

### Ожидаемый результат

Все 115 проверок прошли успешно на следующем окружении:
