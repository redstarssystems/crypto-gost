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

**crypto-gost** по умолчанию использует гибридный нонс k (HMAC-Стрибог
по схеме RFC 6979, затравка — число e уравнения подписи, плюс свежие
случайные байты), BouncyCastle — случайный `SecureRandom`. Результаты в
этом каталоге получены до включения гибридного режима по умолчанию и в
этом файле не пересчитывались. Это влияет на скорость подписания, но не
верификации.

### Что не входит в измерение

Объекты подписи (`ECDSASigner`, `ECGOST3410_2012Signer`) создаются в
`@Setup` и переиспользуются через `init()`.  

Измеряется только hash-then-sign / hash-then-verify без накладных
расходов на аллокации объектов.

### Параметры JMH

- 5 итераций прогрева × 2 с.

- 5 итераций замера × 2 с.

- 3 форка JVM.

Итого ≈60 с на один режим (256/512) × операцию (sign/verify). Три форка
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
≈60 секунд на один режим. Три форка устраняют JIT-зависимости между
запусками, 5 итераций дают надёжный доверительный интервал (99.9% CI
выводится автоматически JMH).

**Как воспроизвести:** make data \# генерация тестовых файлов make build
\# сборка uber-jar make bench \# запуск обоих бенчмарков make plot \#
построение графиков (требует gnuplot)

**Как читать графики:** Гистограммы показывают среднее значение MB/s,
планки погрешностей — 99.9% доверительный интервал JMH. Если планки двух
столбцов перекрываются — разница статистически незначима.

## Выделения памяти и время в ядре (scrypt, MGM, потоки, Кузнечик)

Расположение: папка `bench/core` (класс `CoreBench`) и классы
`FieldBench` и `TableBench` в `bench/signature` (пакет
`org.rssys.gost.signature`, потому что внутренние классы подписи видны
только ему).

### Что измеряется

Время и, главное, выделения памяти на операцию: `scrypt` (N = 2¹², r =
8), `MgmCipher.seal` и `open` на 64 байтах, `Mgm` с тегом 12 байт,
запись и чтение потоков `Cipher` по 4 КиБ (CTR, CFB, OFB),
`AuthenticatedCipher.seal` и `open` на 4 КиБ (в том числе с внешним AAD
в 16 байт), запись и чтение `AuthenticatedStream` (чанк 4 КиБ; чтение
мелких чанков и с внешним AAD), `init` Кузнечика, `SymmetricKey.getKey`;
в `bench/signature` стоимость операций над элементом поля и построения
wNAF-таблицы.

### Как воспроизвести

Метрика выделений не зависит от загрузки машины, поэтому запускать с
профилировщиком сборщика мусора и смотреть `gc.alloc.rate.norm` (байт на
операцию):

    cd bench/core && mvn package && java -jar target/benchmarks.jar -p mode=CTR -prof gc
    cd bench/signature && mvn package && java -jar target/benchmarks.jar 'TableBench|FieldBench' -prof gc

Для сравнения до и после изменения собирайте uber-jar из обоих состояний
кода и запускайте их попеременно на одной машине.

## Стоимость проверки большого CRL

Расположение: папка `bench/crl`. Это не JMH: разбор CRL разовый, а
главный результат - пик памяти и граница `OutOfMemoryError`.

### Что измеряется

Стоимость `CrlVerifier.verify` на CRL с 0,8; 2 и 4 млн записей (≈49 байт
на запись, как у CRL ФНС): время, выделенная память, минимальная куча,
при которой проверка проходит. Лимиты `maxCrlSize` и `maxRevokedEntries`
подняты явно. Три серии:

- **Серия A, повторная проверка без кэша разбора**: на каждом
  рукопожатии заново выполняется `CrlVerifier.verify` (так проверяют CMS
  и `ChainValidator`; в менеджере доверия так было до кэша проверенных
  CRL). 1, 4 и 16 одновременных проверок.

- **Серия B, холодный путь** (первое соединение и каждый `nextUpdate`):
  загрузка с локального HTTP-сервера (отдельная JVM) через
  `CrlCache.get` и проверка своего сертификата. 1 и 16 потоков, каждый
  раунд начинается с пустого кэша. До кэша проверенных CRL каждый поток
  грузил и проверял свою копию.

- **Серия C, кэш проверенных CRL** (как в менеджере доверия): потоки
  вызывают `CrlCache.get` и проверяют свой сертификат. Первый раунд
  холодный (один поток проверяет подпись и разбирает записи, остальные
  ждут), остальные горячие. Бюджет кэша поднят, чтобы измерять
  удержание, а не вытеснение. 1, 4 и 16 потоков.

Каждая ячейка сетки выполняется в новой JVM с `-Xms` равным `-Xmx` (256
МБ, 512 МБ, 1 ГБ, 2 ГБ) и сборщиком G1. База - JDK 21, контрольные
ячейки (4 млн записей) - JDK 25. Ячейки идут от 2 ГБ вниз и
останавливаются после первого сбоя.

Исходы ячейки: `OK`, `OOM` (`OutOfMemoryError`), `DEGRADED` (время
больше чем в 10 раз против той же ячейки на 2 ГБ: JVM почти всё время
собирает мусор), `TIMEOUT` (600 с). Результат - интервал минимальной
кучи, например «от 512 МБ (на 256 МБ: OOM)»; если не прошло даже на 2
ГБ - «больше 2048 МБ», без досчёта выше.

Как измеряется: живой пик - максимум занятой кучи после сборки по
журналу `-Xlog:gc`; верхняя оценка - наблюдатель раз в 10 мс (видит и
ещё не собранный мусор); выделенная память за вызов -
`ThreadMXBean.getThreadAllocatedBytes`; время - медиана раундов (первый
раунд холодный).

Результат означает «куча только под проверку CRL». Данных самого сервиса
в куче в замере нет, поэтому вывод «сервису на 512 МБ хватает» из него
делать нельзя.

### Контроль на настоящем CRL

Синтетика с тем же числом записей, что в предъявленном CRL, должна
совпасть с ним по байтам на запись (±10%) и по времени разбора (±30%).
Оба CRL разбираются одинаково:
`verifySignatureAndParse(caKey, allowDelta=false)` - подпись и строгий
разбор записей без проверки срока (срок настоящего CRL истекает).
Настоящий CRL и сертификат издателя передаются параметрами, в
репозитории их нет:

    make control FNS_CRL=/путь/fns.crl FNS_CRT=/путь/fns-issuer.crt

Без параметров цель печатает «КОНТРОЛЬ НЕ ВЫПОЛНЕН». Файл CRL чужого УЦ
в историю не попадает (`*.crl` и `data/` игнорируются).

### Базовый замер (2026-11-07, до строгого разбора дат)

Условия: коммит `dbe1d41c` плюс модуль `bench/crl` в рабочем дереве
(правки не закоммичены), JDK 21.0.13 (база) и 25.0.5 (контроль), 16
ядер, 32 ГБ памяти (доступно ≈10 ГБ), G1, `-Xms` равен `-Xmx`.

Контроль: CRL ФНС (829 548 записей, 40 780 414 байт, SHA-256
`d7b1d602a78fb230b9760826fc810eefd8a8baf264d1c5285e11a8c0c2316190`,
`thisUpdate` 2026-11-06, `nextUpdate` 2026-11-14) и синтетика с тем же
числом записей: 49,2 и 49,0 байт на запись (-0,3%). Время «подпись +
хэш + разбор» (`verifySignatureAndParse`) в двух прогонах: 1308,7 и
1303,7 мс (-0,4%); 1473,8 и 1264,7 мс (-14,2%). Разброс между прогонами
≈12%; оба прогона внутри порогов ±10% по байтам и ±30% по времени,
контроль пройден. Вывод контроля сохраняется в `data/control.txt`.

Таблицы ниже сняты на синтетическом CRL с 800 000 записей (39,2 МБ; 37,4
МиБ), по размеру близком к CRL ФНС (829 548 записей, 40,8 МБ), но не на
самом CRL ФНС. Размеры в таблицах даны в МиБ.

<table>
<caption>Минимальная куча только под проверку CRL, записи указаны для
синтетических CRL (интервал: наименьшая прошедшая ступень и следующая за
ней, где уже <code>OutOfMemoryError</code>)</caption>
<colgroup>
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 42%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Серия</th>
<th style="text-align: left;">JDK</th>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">Проверок</th>
<th style="text-align: left;">Минимальная куча</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>A (горячий путь)</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 512 МБ (на 256 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>от 1024 МБ (на 512 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 1024 МБ (на 512 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 2048 МБ (на 1024 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>25</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 2048 МБ (на 1024 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>A</p></td>
<td style="text-align: left;"><p>25</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B (холодный путь)</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 512 МБ (на 256 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 1024 МБ (на 512 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>от 2048 МБ (на 1024 МБ: OOM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>B</p></td>
<td style="text-align: left;"><p>21</p></td>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>больше 2048 МБ</p></td>
</tr>
</tbody>
</table>

"Больше 2048 МБ" - даже на 2 ГБ завершилась только часть потоков
(например, 9 из 16 при 0,8 млн и 16 проверках, 1 из 16 при 2 и 4 млн),
остальные получили `OutOfMemoryError`; у таких ячеек раунд шёл 20-90 с
из-за непрерывной сборки мусора. Исход «деградация» не потребовался: все
сбои оказались `OutOfMemoryError`. Расхождений между JDK 21 и JDK 25 по
границам нет; на JDK 25 вызов медленнее примерно на 12% (4 млн записей,
одна проверка: 7645 и 6829 мс).

<table style="width:100%;">
<caption>Один вызов <code>verify</code>, один поток, прогретый (JDK 21,
куча 2 ГБ)</caption>
<colgroup>
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 14%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">Размер CRL, МиБ</th>
<th style="text-align: left;">Всего, мс</th>
<th style="text-align: left;">Хэш, мс</th>
<th style="text-align: left;">Подпись, мс</th>
<th style="text-align: left;">Разбор, мс</th>
<th style="text-align: left;">Выделено за вызов, МиБ</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>37,4</p></td>
<td style="text-align: left;"><p>1168</p></td>
<td style="text-align: left;"><p>486</p></td>
<td style="text-align: left;"><p>1,4</p></td>
<td style="text-align: left;"><p>681</p></td>
<td style="text-align: left;"><p>1803</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>93,5</p></td>
<td style="text-align: left;"><p>3259</p></td>
<td style="text-align: left;"><p>1205</p></td>
<td style="text-align: left;"><p>1,6</p></td>
<td style="text-align: left;"><p>2053</p></td>
<td style="text-align: left;"><p>4480</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>186,9</p></td>
<td style="text-align: left;"><p>6715</p></td>
<td style="text-align: left;"><p>2400</p></td>
<td style="text-align: left;"><p>1,6</p></td>
<td style="text-align: left;"><p>4314</p></td>
<td style="text-align: left;"><p>8921</p></td>
</tr>
</tbody>
</table>

<table>
<caption>Удерживаемая память, пока на разобранный <code>GostCrl</code>
есть ссылка (после <code>System.gc()</code>)</caption>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">Размер CRL, МиБ</th>
<th style="text-align: left;">Удерживает <code>GostCrl</code>, МиБ</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>37,4</p></td>
<td style="text-align: left;"><p>224</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>93,5</p></td>
<td style="text-align: left;"><p>553</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>186,9</p></td>
<td style="text-align: left;"><p>1105</p></td>
</tr>
</tbody>
</table>

Холодный путь (серия B) добавляет загрузку: для 0,8 млн записей на
локальном сервере 0,6-0,7 с и около 60 МБ живой кучи сверх горячего пути
(копии при сборке ответа). `CrlCache.put` занимает 1-2 мс и значения не
меняет.

Выводы замера:

- Подпись - постоянная и ничтожная (1,5 мс). Время делят хэш Стрибога
  (≈36%, ≈78 МиБ/с) и строгий разбор записей (≈64% при разбивке выше;
  см. оценку долей в разборе ниже).

- Один вызов выделяет ≈48 байт на каждый байт CRL (≈2,4 КБ на запись),
  хотя удерживает ≈6 байт на байт CRL. Для CRL размера ФНС это около 1,8
  ГиБ мусора на каждое рукопожатие.

- Живая куча на одну проверку - это разобранный `GostCrl` (≈224 МиБ для
  800 000 записей, вместе с собственной копией DER) плюс один общий
  массив CRL (≈37 МиБ), общий для всех потоков. Модель «число проверок ×
  удерживаемый `GostCrl` + один массив» совпала со всеми измеренными
  интервалами: для 800 000 записей одна проверка ≈261 МиБ (прошла на
  512, упала на 256), четыре ≈933 МиБ (прошли на 1024, упали на 512),
  шестнадцать ≈3,6 ГиБ (не помещаются в 2 ГиБ); для 2 млн записей одна
  проверка ≈646 МиБ, четыре ≈2,3 ГиБ; для 4 млн одна ≈1,3 ГиБ, четыре
  ≈4,5 ГиБ.

- Память растёт линейно по числу проверок. Время рушится только когда
  памяти не хватает: JVM десятки секунд собирает мусор, прежде чем часть
  потоков получит `OutOfMemoryError`.

- Значения лимитов по умолчанию (64 МиБ и 1 000 000 записей) замер не
  опровергает, но и не оправдывает увеличение: рост лимита прямо
  увеличивает требования к куче на каждое рукопожатие.

### Где уходит выделение внутри разбора

Отдельное измерение до исправления (не часть сетки, один запуск, JDK
21): на каждую запись CRL `GostDerParser.parseTime` превращает дату в
строку и разбирает её через заново построенный
`DateTimeFormatter.ofPattern`, а затем
`GostSignatureHelper.formatGeneralizedTime` форматирует дату обратно в
строку. Измерено: `parseTime` 1696 байт и 354 нс на вызов,
`formatGeneralizedTime` 224 байта и 93 нс на вызов; всего ≈1920 байт из
≈2363 байт на запись (≈81% выделения) и ≈447 нс на запись, то есть ≈358
мс из ≈1443 мс одного вызова на 800 000 записей (≈25% вызова, ≈52% этапа
«разбор»). Это оценка по одной дате; профилировщиком не подтверждена.

### Повторный замер (2026-11-07, после строгого разбора дат без форматтера)

Те же условия, те же файлы данных, та же сетка; разбор дат переписан без
строки и форматтера на запись, строку даты отзыва собирает из
проверенных байт. Невыполненные ячейки не добавлялись, интервалы
минимальной кучи совпали с прежними во всех строках таблицы выше.

<table style="width:100%;">
<caption>Один вызов <code>verify</code>, JDK 21, 1 проверка,
<code>-Xmx</code> 2048 МБ (до → после)</caption>
<colgroup>
<col style="width: 14%" />
<col style="width: 28%" />
<col style="width: 28%" />
<col style="width: 28%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">Выделено за вызов, МиБ</th>
<th style="text-align: left;">Время (медиана), мс</th>
<th style="text-align: left;">Удерживаемый <code>GostCrl</code>,
МиБ</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>1802,7 → 400,6 (-78%)</p></td>
<td style="text-align: left;"><p>1442,9 → 1053,0 (-27%)</p></td>
<td style="text-align: left;"><p>223,6 (без изменений)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>4480,3 → 959,4 (-79%)</p></td>
<td style="text-align: left;"><p>3526,0 → 2506,4 (-29%)</p></td>
<td style="text-align: left;"><p>553,2 (без изменений)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>8921,2 → 1810,8 (-80%)</p></td>
<td style="text-align: left;"><p>6828,8 → 5082,0 (-26%)</p></td>
<td style="text-align: left;"><p>1105,0 (без изменений)</p></td>
</tr>
</tbody>
</table>

- Разбивка этапов на 0,8 млн записей: хэш 486,3 → 483,4 мс (без
  изменений), разбор 680,6 → 357,4 мс, всего 1168,3 → 842,3 мс.

- JDK 25, 4 млн записей: выделено 8832,8 → 1834,7 МиБ, время 7644,5 →
  6118,6 мс.

- Контроль на CRL ФНС повторён: 49,2 и 49,0 байт на запись (-0,3%),
  время «подпись + хэш + разбор» 985,0 и 983,1 мс (-0,2%); пороги
  соблюдены.

- Выделение на запись упало с ≈2363 до ≈525 байт. Куда уходят оставшиеся
  ≈525 байт, не разбиралось.

- Границы по куче не сдвинулись: их определяет удерживаемый объект, а не
  мусор. Живой пик по журналу сборки у самой границы кучи нестабилен: 4
  проверки, 0,8 млн записей, 2048 МБ дали 1735 → 2047 МиБ при тех же 4
  успешных из 4; причина не исследована.

- Оставшееся время почти целиком делят хэш (≈57% вызова) и строгий обход
  записей; следующий шаг по времени - кэш результата разбора, а не
  дальнейшая правка дат.

### Кэш проверенных CRL (замер после введения `VerifiedCrl`)

Те же условия и те же файлы данных, JDK 21, `-Xms` равен `-Xmx`. CRL уже
загружен: хэш, подпись и разбор выполняет один поток, остальные ждут
(`loads=1` во всех ячейках, кроме сорвавшихся).

<table>
<caption>Горячее соединение, серия C (<code>-Xmx</code> 2048 МБ, медиана
по четырём горячим раундам)</caption>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">Проверок</th>
<th style="text-align: left;">Первое соединение, мс</th>
<th style="text-align: left;">Горячая проверка, мс</th>
<th style="text-align: left;">Выделение на проверку</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>1 / 4 / 16</p></td>
<td style="text-align: left;"><p>1274 / 1240 / 1167</p></td>
<td style="text-align: left;"><p>0,2 / 0,4 / 0,4</p></td>
<td style="text-align: left;"><p>менее 0,05 МиБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>1 / 4 / 16</p></td>
<td style="text-align: left;"><p>2724 / 2882 / 2671</p></td>
<td style="text-align: left;"><p>0,3 / 0,4 / 0,4</p></td>
<td style="text-align: left;"><p>менее 0,05 МиБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>1 / 4 / 16</p></td>
<td style="text-align: left;"><p>5565 / 5988 / 5669</p></td>
<td style="text-align: left;"><p>0,3 / 0,3 / 0,3</p></td>
<td style="text-align: left;"><p>менее 0,05 МиБ</p></td>
</tr>
</tbody>
</table>

Для сравнения, серия A после перехода на строгие даты (проверка заново
на каждом соединении): 1053 мс на 0,8 млн записей и 1 проверку, 2506 мс
на 2 млн, 5082 мс на 4 млн, с выделением 401, 959 и 1811 МиБ на
проверку.

<table>
<caption>Минимальная куча, серия C (интервал: наименьшая прошедшая
ступень и следующая, где уже <code>OutOfMemoryError</code>)</caption>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Записей</th>
<th style="text-align: left;">1 проверка</th>
<th style="text-align: left;">4 проверки</th>
<th style="text-align: left;">16 проверок</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>0,8 млн</p></td>
<td style="text-align: left;"><p>от 512 МБ</p></td>
<td style="text-align: left;"><p>от 512 МБ</p></td>
<td style="text-align: left;"><p>от 512 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 млн</p></td>
<td style="text-align: left;"><p>от 1024 МБ</p></td>
<td style="text-align: left;"><p>от 1024 МБ</p></td>
<td style="text-align: left;"><p>от 1024 МБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 млн</p></td>
<td style="text-align: left;"><p>от 2048 МБ</p></td>
<td style="text-align: left;"><p>от 2048 МБ</p></td>
<td style="text-align: left;"><p>от 2048 МБ</p></td>
</tr>
</tbody>
</table>

Без кэша (серия A) для тех же CRL требовалось: 0,8 млн — от 512, от 1024
и больше 2048 МБ; 2 млн — от 1024 и больше 2048 МБ; 4 млн — от 2048 и
больше 2048 МБ на 1, 4 и 16 проверок. Теперь граница не зависит от числа
проверок: удерживается одна копия.

- Живая куча на 0,8 / 2 / 4 млн записей: 213-296 / 660-728 / 1292-1377
  МиБ по журналу сборки. Это один разобранный `GostCrl` (224 / 553 /
  1105 МиБ) плюс общий массив DER в ячейке (37 / 94 / 187 МиБ).

- Холодный путь с сетью (серия B, 2048 МБ): 1634 мс на 0,8 млн записей
  при 1 потоке и 1672 мс при 16 (раньше при 16 потоках 8 из 16 получали
  `OutOfMemoryError` за ≈25 с); 4285 и 3836 мс на 2 млн; 8085 и 7778 мс
  на 4 млн. На 16 потоков загрузка выполняется один раз (`fetches=1`).

- Когда куча слишком мала (ступень «OOM»), потоки-ожидающие повторяют
  попытку после сбоя инициатора, поэтому время до отказа растёт с числом
  потоков (800 000 записей, 256 МБ, 16 потоков: ≈26 с, 16 загрузок).
  Состояние гонки не возникает, но отказ приходит позже; при нехватке
  памяти соединения всё равно не состоятся.

- Контроль на CRL ФНС повторён: 49,2 и 49,0 байт на запись (-0,3%),
  время «подпись + хэш + разбор» 933,4 и 1010,4 мс (+8,3%); пороги
  соблюдены.

### Как воспроизвести

    cd bench/crl
    make deps      # собирает и устанавливает core, pkix, tls13, jsse в ~/.m2
    make gen       # CRL на 0,8; 2 и 4 млн записей в bench/crl/data/ (куча 7 ГБ)
    make control FNS_CRL=... FNS_CRT=...
    make grid      # вся сетка; результат в data/results.csv и data/summary.adoc

Во время прогона на машине не должно работать ничего тяжёлого, иначе
подкачка исказит время. В отчёт по замеру входят хэш коммита, признак
незакоммиченных правок, версия JDK, число ядер и свободная память.

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
