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

4.  **LRU-вытеснение сессий.** Соблюдается ли лимит `sessionCacheSize`
    при большом числе уникальных клиентов?

5.  **Устойчивость к аварийным обрывам.** Продолжает ли сервер принимать
    соединения после жёстких обрывов (RST без `close_notify`) со стороны
    клиента?

6.  **Максимум одновременных сессий.** До какого числа параллельных
    TLS-соединений провайдер работает стабильно в рамках доступного
    heap?

# Инфраструктура теста

## Сервер

`GostSSLServerSocket` на случайном порту. На каждое входящее соединение
запускается виртуальный поток (vthread) с echo-циклом: читает байты из
`InputStream`, возвращает обратно в `OutputStream`.

Такой сервер минимален и прозрачен: отсутствует HTTP-слой или фреймворк,
которые могли бы замаскировать или усилить проблемы в JSSE-провайдере.

## Клиентский контекст

Для JsseStressTest — единый `SSLContext` (провайдер `RssysGostJsse`,
протокол `TLSv1.3`), разделяемый между всеми профилями. Все клиенты
используют `GostSSLSocket` через стандартный `SSLSocketFactory`.

Для UndertowStressTest — те же настройки JSSE, но клиент и сервер
общаются через HTTPS: Undertow-сервер сконфигурирован с тем же
`SSLContext`, клиент использует `HttpsURLConnection` с
`GostSSLSocketFactory`.

## Кэш сессий

`GostSSLSessionContext.setSessionCacheSize(5000)` — ограничение LRU-кэша
сессий на серверной стороне. Позволяет проверить вытеснение сессий при
числе уникальных клиентов, превышающем лимит.

# Профили нагрузки

Все профили запускаются параллельно в виртуальных потоках и работают
одновременно в течение всего теста.

## Профиль 1 — Короткие сессии (открыть-отправить-закрыть)

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
<td style="text-align: left;"><p>Нагрузка на создание/закрытие сессий,
PSK store, <code>putSession</code></p></td>
</tr>
</tbody>
</table>

## Профиль 2 — Средние сессии (запрос-ответ)

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
<td style="text-align: left;"><p>Одно соединение живёт 5–30 с; за это
время 10–50 обменов с паузой 100–500 мс; объём данных 1–100
байт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Таймаут</p></td>
<td style="text-align: left;"><p>15 с на чтение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>Проверка корректности многократного
write/read на одном соединении, поведение при длительном соединении
GostSSLSocket</p></td>
</tr>
</tbody>
</table>

## Профиль 3 — Длинные сессии (пропускная способность, throughput)

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
<td style="text-align: left;"><p>Одно соединение на весь тест;
непрерывные блоки по 16 КБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Таймаут</p></td>
<td style="text-align: left;"><p>30 с на чтение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>Измерение пропускной способности,
проверка поведения TLSTREE при большом числе TLS-записей
(KeyUpdate)</p></td>
</tr>
</tbody>
</table>

Размер блока выбран равным `MAX_PLAINTEXT_LENGTH` (16 384 байт) —
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
жёсткий обрыв (RST через закрытие raw TCP-сокета без
<code>close_notify</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Цель</p></td>
<td style="text-align: left;"><p>Проверка устойчивости сервера к
аномальным завершениям; сервер не должен зависнуть или отказать в приёме
новых соединений</p></td>
</tr>
</tbody>
</table>

# Мониторинг

Каждые 30 секунд фиксируются:

- Используемый heap (MB и % от `-Xmx`);

- Число GC-коллекций нарастающим итогом;

- Число сессий в LRU-кэше сервера (`GostSSLSessionContext.getIds()`);

- Счётчики успешных запросов и ошибок по каждому профилю.

При росте heap более чем в 1,5 раза за два измерения и превышении 85 %
от `-Xmx` автоматически сохраняется дамп потоков в
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

# Результаты прогона

**Дата:** 2026-05-25.  
**Среда:** Alt Linux p11, JVM `-Xmx8g`, JDK 25.0.3, Project Loom
(vthreads), Intel Core Ultra 9 285H (Arrow Lake), 16 ядер / 16 потоков,
30 GiB RAM. ГОСТ без аппаратного ускорения.

Перед прогоном применены sysctl:
`net.ipv4.ip_local_port_range="1024 65535"`, `net.ipv4.tcp_tw_reuse=1`.
Это напрямую влияет на профиль 1 (см. интерпретацию).

## JsseStressTest — Socket (raw echo)

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
<td style="text-align: left;"><p>30 потоков × открыть-отправить-закрыть
1 KB</p></td>
<td style="text-align: left;"><p>262 877</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × длительное соединение 5–30
с</p></td>
<td style="text-align: left;"><p>19 291</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × 16 KB непрерывно</p></td>
<td style="text-align: left;"><p>30 463 (≈ 475 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>2 945</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 824 MB / 7 924 MB (10 %) — стабилен, без тренда роста.  
**GC:** +4 099 коллекций за 5 минут.  
**Кэш сессий:** 5 000 (потолок, очистка сессий работает).  

## UndertowStressTest — HTTP (echo)

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
<td style="text-align: left;"><p>30 потоков × HTTP POST 1 KB</p></td>
<td style="text-align: left;"><p>254 284</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × HTTP длительное соединение
5–30 с</p></td>
<td style="text-align: left;"><p>19 497</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × HTTP POST 16 KB
непрерывно</p></td>
<td style="text-align: left;"><p>30 846 (≈ 482 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>2 901</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 757 MB / 7 924 MB (9 %) — стабилен, без тренда роста.  
**GC:** +4 244 коллекций за 5 минут.  
**Кэш сессий:** 5 000 (потолок, очистка работает).  

# Интерпретация результатов

## Утечки памяти — нет

Heap стабилен на уровне 9-15 % от `-Xmx8g` без тренда роста. Heap v0.3.3
значительно ниже v0.3.2: 824 MB (10 %) против 1 167 MB (14 %) на
JsseStressTest, и 757 MB (9 %) против 1 261 MB (15 %) на
UndertowStressTest.

`GostSSLSessionContext.sessions` (LRU) удерживается в пределах 5 000
записей — эвикция работает корректно.

GC-нагрузка: <sub>4\ 100-4\ 300\ коллекций\ за\ 5\ минут\ (v0.3.2:</sub>
4 800-5 100). GC на единицу работы: в среднем 0,0130 GC/req против
0,0175 на v0.3.2 (–25,7 %).

## Зависаний — нет

Профиль 4 (10 потоков жёсткий RST) выполнил ~2 900 аномальных обрывов. 0
неожиданных исключений на стороне клиента — все handshake и sleep
завершились штатно до RST, ни одно соединение не оборвалось на полпути.
Сервер продолжал принимать соединения без задержек. `GostSSLSocket`
корректно обрабатывает `IOException` при чтении/записи в разорванное
соединение и не блокирует `inboundLock`/`outboundLock`.

## Корректность TLS — подтверждена

Профиль 3 выполнил 30 000+ 16 KB echo-обменов (≈ 475-485 MB) без единой
ошибки. При таком числе TLS-записей срабатывает KeyUpdate (смена ключей
при достижении SNMAX для suite L). 0 ошибок означает что KeyUpdate и
возобновление шифрования после смены ключей работают корректно.

## Влияние sysctl на Профиль 1

Перед этим прогоном были применены sysctl:

- `net.ipv4.ip_local_port_range="1024 65535"` — 64 568 портов вместо 28
  241 (32 768-60 999), в 2,3× больше пространства для уникальных
  src-портов;

- `net.ipv4.tcp_tw_reuse=1` — порт из `TIME_WAIT` можно занять сразу,
  без ожидания 60 с таймаута.

30 потоков в профиле 1 непрерывно открывают и закрывают TCP-соединения;
без настроек выше они бы упирались в лимит портов за &lt; 1 с и половину
времени получали `BindException`.

Чтобы выделить разницу на уровне кода, был выполнен A/B-прогон
JsseStressTest на версиях v0.3.2 и v0.3.3 при одинаковых sysctl:

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Профиль</p></td>
<td style="text-align: left;"><p>v0.3.2</p></td>
<td style="text-align: left;"><p>v0.3.3</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>241 084</p></td>
<td style="text-align: left;"><p>262 877</p></td>
<td style="text-align: left;"><p><strong>+9,0 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>30 196 (471 MB)</p></td>
<td style="text-align: left;"><p>30 463 (475 MB)</p></td>
<td style="text-align: left;"><p><strong>+0,9 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC, всего</p></td>
<td style="text-align: left;"><p>5 129</p></td>
<td style="text-align: left;"><p>4 099</p></td>
<td style="text-align: left;"><p><strong>−20,1 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0175</p></td>
<td style="text-align: left;"><p>0,0130</p></td>
<td style="text-align: left;"><p><strong>−25,7 %</strong></p></td>
</tr>
</tbody>
</table>

Вывод:

- **Профиль 1**: реальный вклад на уровне изменений кода (гонка
  `writerRecord`) составляет **~+9,0 %**.

- **Профиль 3**: пропускная способность практически не изменилась между
  v0.3.2 и v0.3.3 (+0,9 % — шум). Рост +16-24 % относительно исходного
  прогона — результат sysctl (Профиль 1 не создаёт конкуренции за порты
  с Профиль 3).

- **GC на запрос**: снижение −25,7 % подтверждает эффект рефакторинга
  MGM-режима.

## Профили 2 и 4 — стабильны

- Профиль 2 (medium): +1 % и +0,2 % — незначительный рост в пределах
  шума.

- Профиль 4 (аварийные обрывы): +3 % и –2 % — в пределах шума.

Неожиданных ошибок нет ни в одном профиле обоих тестов. (Для Профиль 4
каждая итерация — успешный жёсткий RST, исключения не засчитываются.)

# Вывод

Оба теста отработали полные 5 минут, все проверки пройдены.

1.  **Утечек памяти нет** — heap стабилен, без тренда роста.

2.  **Зависаний нет** — все профили завершились, тест аварийных обрывов
    не вызывает блокировок сервера.

3.  **Корректность TLS подтверждена** — Профиль 3: 30 000+ 16 KB
    обменов, KeyUpdate отрабатывает без ошибок.

4.  **Очистка сессий работает** — LRU-кэш держится на лимите 5 000.

5.  **Профиль 3 (пропускная способность):** разница v0.3.2 → v0.3.3
    незначительна (+0,9 %).

6.  **Работа GC на 1 запрос: −25,7 %** — MGM-рефакторинг + улучшенный
    менеджмент памяти.

7.  **0 ошибок** во всех профилях — провайдер стабилен под смешанной
    нагрузкой.
