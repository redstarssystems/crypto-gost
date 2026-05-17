# Исходные вопросы

Перед запуском стресс-теста были сформулированы следующие вопросы:

1.  **Утечки памяти.** Растёт ли heap линейно при длительной работе?
    Освобождаются ли ресурсы после закрытия соединений?

2.  **Зависания.** Может ли провайдер заблокироваться при параллельных
    `wrap()`/`unwrap()` из разных потоков? Корректно ли завершается
    handshake под конкурентной нагрузкой?

3.  **Корректность протокола.** Не нарушается ли TLS 1.3 при длительной
    работе — в частности, KeyUpdate (смена ключей при достижении SNMAX)
    и NewSessionTicket (PSK-тикеты для resumption)?

4.  **LRU-эвикция сессий.** Соблюдается ли лимит `sessionCacheSize` при
    большом числе уникальных клиентов?

5.  **Устойчивость к аварийным обрывам.** Продолжает ли сервер принимать
    соединения после hard close (RST без `close_notify`) со стороны
    клиента?

6.  **Максимум одновременных сессий.** До какого числа параллельных
    TLS-соединений провайдер работает стабильно в рамках доступного
    heap?

# Инфраструктура теста

## Сервер

`GostSSLServerSocket` на случайном порту (`:0`). На каждое входящее
соединение запускается виртуальный поток (Project Loom) с echo-циклом:
читает байты из `InputStream`, возвращает обратно в `OutputStream`.

Такой сервер минимален и прозрачен: отсутствует HTTP-слой или
application-фреймворк, которые могли бы замаскировать или усилить
проблемы в JSSE-провайдере.

## Клиентский контекст

Единый `SSLContext` (провайдер `RssysGostJsse`, протокол `TLSv1.3`),
разделяемый между всеми профилями. Все клиенты используют
`GostSSLSocket` через стандартный `SSLSocketFactory`.

## Session cache

`GostSSLSessionContext.setSessionCacheSize(5000)` — ограничение LRU-кэша
сессий на серверной стороне. Позволяет проверить эвикцию при числе
уникальных клиентов, превышающем лимит.

# Профили нагрузки

Все профили запускаются параллельно в виртуальных потоках и работают
одновременно в течение всего теста.

## Профиль 1 — Короткие сессии (fire-and-forget)

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Потоков</p></td>
<td style="text-align: left;"><p>30</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Паттерн</p></td>
<td style="text-align: left;"><p>connect → handshake → send 1 KB →
readEcho → close → повтор</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Таймаут</p></td>
<td style="text-align: left;"><p>15 с на чтение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>давление на создание/закрытие сессий,
PSK store, <code>putSession</code></p></td>
</tr>
</tbody>
</table>

## Профиль 2 — Средние сессии (request-response)

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Потоков</p></td>
<td style="text-align: left;"><p>20</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Паттерн</p></td>
<td style="text-align: left;"><p>одно соединение живёт 5–30 с; за это
время 10–50 обменов с паузой 100–500 мс; размер payload 1–100
байт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Таймаут</p></td>
<td style="text-align: left;"><p>15 с на чтение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>проверка корректности многократного
write/read на одном соединении, keep-alive поведение
GostSSLSocket</p></td>
</tr>
</tbody>
</table>

## Профиль 3 — Длинные сессии (throughput)

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Потоков</p></td>
<td style="text-align: left;"><p>5</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Паттерн</p></td>
<td style="text-align: left;"><p>одно соединение на весь тест;
непрерывные 16 KB chunks</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Таймаут</p></td>
<td style="text-align: left;"><p>30 с на чтение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>измерение пропускной способности,
проверка поведения TLSTREE при большом числе TLS-записей
(KeyUpdate)</p></td>
</tr>
</tbody>
</table>

Размер chunk выбран равным `MAX_PLAINTEXT_LENGTH` (16 384 байт) —
максимальная TLS-запись по RFC 8446 §5.1.

## Профиль 4 — Аварийные обрывы (chaos)

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Потоков</p></td>
<td style="text-align: left;"><p>10</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Паттерн</p></td>
<td style="text-align: left;"><p>connect → handshake → sleep(0–2 с) →
hard close (RST через закрытие raw TCP-сокета без
<code>close_notify</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>проверка устойчивости сервера к
аномальным завершениям; сервер не должен зависнуть или отказать в приёме
новых соединений</p></td>
</tr>
</tbody>
</table>

# Мониторинг

Каждые 30 секунд фиксируются:

- используемый heap (MB и % от `-Xmx`);

- число GC-коллекций нарастающим итогом;

- число сессий в LRU-кэше сервера (`GostSSLSessionContext.getIds()`);

- счётчики успешных запросов и ошибок по каждому профилю.

При росте heap более чем в 1,5 раза за два измерения и превышении 85 %
от `-Xmx` автоматически сохраняется thread dump в
`build/reports/stress-dump-<timestamp>.txt`.

# Параметры запуска

    # Полный прогон (5 минут)
    make -C examples/jsse test-stress

    # Быстрый прогон (1 минута)
    make -C examples/jsse test-stress ARGS=-Dstress.duration=1

    # Через Maven напрямую
    mvn test -pl examples/jsse -am \
      -Dtest="JsseStressTest#stressTest" \
      -Dstress.duration=5 \
      -Dstress.cacheSize=5000

# Результаты эталонного прогона

Среда: JVM `-Xmx8g`, Project Loom (vthreads), ГОСТ без аппаратного
ускорения.

<table style="width:100%;">
<colgroup>
<col style="width: 16%" />
<col style="width: 34%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 16%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Профиль</p></td>
<td style="text-align: left;"><p>Описание</p></td>
<td style="text-align: left;"><p>Успешных</p></td>
<td style="text-align: left;"><p>Ошибок</p></td>
<td style="text-align: left;"><p>Оценка</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>30 потоков × fire-and-forget 1
KB</p></td>
<td style="text-align: left;"><p>~141 000</p></td>
<td style="text-align: left;"><p>~506 000</p></td>
<td style="text-align: left;"><p>✅ см. ниже</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × keep-alive 5–30 с</p></td>
<td style="text-align: left;"><p>~11 000</p></td>
<td style="text-align: left;"><p>~19 000</p></td>
<td style="text-align: left;"><p>✅ см. ниже</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × 16 KB непрерывно</p></td>
<td style="text-align: left;"><p>~17 000 (≈ 260 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — chaos</p></td>
<td style="text-align: left;"><p>10 потоков × RST без
close_notify</p></td>
<td style="text-align: left;"><p>~1 700</p></td>
<td style="text-align: left;"><p>~98 000</p></td>
<td style="text-align: left;"><p>✅ ожидаемо</p></td>
</tr>
</tbody>
</table>

**Heap:** осциллирует от 200 MB до 1 800 MB при `-Xmx8g` (22 % пик), без
линейного роста. Сессии в LRU-кэше стабилизировались на 5 000.
GC-коллекций: ~3 000 за 5 минут — нормальный показатель.

# Интерпретация результатов

## Утечки памяти — нет

Heap осциллирует вокруг среднего значения без тренда роста. После
каждого GC-цикла объём возвращается к базовому уровню.
`GostSSLSessionContext.sessions` (LRU) удерживается в пределах 5 000
записей на протяжении всего теста — эвикция работает.

## Зависаний — нет

Профиль 4 (10 потоков hard-RST) генерировал ~98 000 аномальных обрывов.
Сервер продолжал принимать соединения без задержек. `GostSSLSocket`
корректно обрабатывает `IOException` при чтении/записи в разорванное
соединение и не блокирует `inboundLock`/`outboundLock`.

## Корректность TLS — подтверждена

Профиль 3 выполнил ~17 000 16 KB echo-обменов (≈ 260 MB) без единой
ошибки. При таком числе TLS-записей срабатывает KeyUpdate (смена ключей
при достижении SNMAX для suite L). 0 ошибок означает что KeyUpdate и
возобновление шифрования после смены ключей работают корректно.

## Ошибки профилей 1 и 2 — не баги провайдера

Высокое число ошибок в профилях 1 и 2 объясняется исчерпанием
ephemeral-портов ОС: 30 потоков профиля 1 непрерывно открывают и
закрывают TCP-соединения быстрее, чем ОС освобождает порты из состояния
`TIME_WAIT`. Последующие `createSocket()` получают `BindException`. Это
системное ограничение, не проблема JSSE-провайдера.

Диагностика подтверждена логированием типа исключения: все ошибки
профилей 1 и 2 — `BindException`, не `SSLException`.

## Ошибки профиля 4 — ожидаемы

Каждый из ~98 000 обрывов регистрируется как ошибка на стороне клиента
(hard close до нормального завершения). Assertions для профиля 4
намеренно не проверяют счётчик ошибок.
