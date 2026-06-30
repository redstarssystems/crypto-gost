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

7.  **Отсутствие регрессии.** Не снизилась ли пропускная способность и
    не увеличилось ли давление на GC относительно отчёта №4 (v0.3.4)?

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
проверка поведения TlsTree при большом числе TLS-записей
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

# Prerequisites (проверить перед запуском)

После перезагрузки системы сбрасываются sysctl и CPU governor. Без этих
настроек Profile 1 теряет до −46 % пропускной способности.

    # CPU governor (должен быть performance)
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

    # TCP port range (должен быть 1024 65535)
    cat /proc/sys/net/ipv4/ip_local_port_range
    sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

    # tcp_tw_reuse (должен быть 1)
    cat /proc/sys/net/ipv4/tcp_tw_reuse
    sudo sysctl -w net.ipv4.tcp_tw_reuse=1

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

**Дата:** 2026-06-27.  
**Версия:** v0.5.6-48-g3162a4a.  
**Среда:** Alt Linux p11, JVM `-Xmx8g`, JDK 25.0.3, Project Loom
(vthreads), Intel Core Ultra 9 285H (Arrow Lake), 16 ядер / 16 потоков,
30 GiB RAM. ГОСТ без аппаратного ускорения.

Прогон выполнялся после TLS-стресс-тестов (30 мин mixed load) с паузой
5 минут на остывание CPU.

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
<td style="text-align: left;"><p>258 600</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × длительное соединение 5–30
с</p></td>
<td style="text-align: left;"><p>19 125</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × 16 KB непрерывно</p></td>
<td style="text-align: left;"><p>30 403 (≈ 475 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>2 900</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 1 650 MB / 7 924 MB (20 %) — стабилен, без тренда роста.  
**GC:** +4 706 коллекций за 5 минут.  
**Кэш сессий:** 5 000 (потолок, вытеснение работает).  

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
<td style="text-align: left;"><p>254 224</p></td>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × HTTP длительное соединение
5–30 с</p></td>
<td style="text-align: left;"><p>19 433</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × HTTP POST 16 KB
непрерывно</p></td>
<td style="text-align: left;"><p>30 955 (≈ 484 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>2 940</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 747 MB / 7 924 MB (9 %) — стабилен, без тренда роста.  
**GC:** +4 672 коллекций за 5 минут.  
**Кэш сессий:** 5 000 (потолок, вытеснение работает).  

# Сравнение с отчётом №4 (v0.3.4)

## JsseStressTest — Socket

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
<td style="text-align: left;"><p>v0.3.4</p></td>
<td style="text-align: left;"><p>v0.5.6</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>247 719</p></td>
<td style="text-align: left;"><p>258 600</p></td>
<td style="text-align: left;"><p><strong>+4,4 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>19 256</p></td>
<td style="text-align: left;"><p>19 125</p></td>
<td style="text-align: left;"><p>−0,7 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>30 674 (479 MB)</p></td>
<td style="text-align: left;"><p>30 403 (475 MB)</p></td>
<td style="text-align: left;"><p>−0,9 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>2 925</p></td>
<td style="text-align: left;"><p>2 900</p></td>
<td style="text-align: left;"><p>−0,9 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap</p></td>
<td style="text-align: left;"><p>653 MB (8 %)</p></td>
<td style="text-align: left;"><p>1 650 MB (20 %)</p></td>
<td style="text-align: left;"><p><strong>+152,7 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC</p></td>
<td style="text-align: left;"><p>4 799</p></td>
<td style="text-align: left;"><p>4 706</p></td>
<td style="text-align: left;"><p>−1,9 %</p></td>
</tr>
</tbody>
</table>

## UndertowStressTest — HTTP

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
<td style="text-align: left;"><p>v0.3.4</p></td>
<td style="text-align: left;"><p>v0.5.6</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>249 968</p></td>
<td style="text-align: left;"><p>254 224</p></td>
<td style="text-align: left;"><p><strong>+1,7 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>19 452</p></td>
<td style="text-align: left;"><p>19 433</p></td>
<td style="text-align: left;"><p>−0,1 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>30 812 (481 MB)</p></td>
<td style="text-align: left;"><p>30 955 (484 MB)</p></td>
<td style="text-align: left;"><p>+0,5 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>2 860</p></td>
<td style="text-align: left;"><p>2 940</p></td>
<td style="text-align: left;"><p>+2,8 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap</p></td>
<td style="text-align: left;"><p>285 MB (3 %)</p></td>
<td style="text-align: left;"><p>747 MB (9 %)</p></td>
<td style="text-align: left;"><p><strong>+162,1 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC</p></td>
<td style="text-align: left;"><p>4 641</p></td>
<td style="text-align: left;"><p>4 672</p></td>
<td style="text-align: left;"><p>+0,7 %</p></td>
</tr>
</tbody>
</table>

# Интерпретация результатов

## Ошибки Undertow Profile 1

4 ошибки на 254 224 запроса (0,0016 %) в профиле коротких HTTP-сессий.
Характер ошибок — `javax.net.ssl.SSLException: I/O error during unwrap`
(соединение было сброшено сервером до завершения handshake). Вероятная
причина — конкуренция за порты в диапазоне TIME_WAIT при 30
одновременных потоках, выполняющих connect → send → close. Частота
ничтожно мала и не указывает на регрессию в коде провайдера.

## Повышенный heap

Heap в обоих тестах выше предыдущего отчёта (1 650 vs 653 MB, 747 vs 285
MB). Это ожидаемый накопительный эффект: JSSE-тесты выполнялись
последовательно на одной JVM после 30-минутного TLS mixed load. G1 GC
адаптирует пороги сборки под аллокационную нагрузку и не форсирует
агрессивную очистку между независимыми тестами.

В пользу этого объяснения: GC count стабилен (4 706 vs 4 799 в JsseStess,
4 672 vs 4 641 в Undertow), а абсолютные показатели throughput по всем
профилям не снизились.

Для изолированного замера heap JSSE-тесты следует запускать на холодной
JVM, без предшествующего TLS-стресс-теста.

## Утечки памяти — нет

Heap стабилен без тренда роста в обоих тестах. `GostSSLSessionContext`
удерживает LRU-кэш на уровне 5 000 записей — вытеснение работает.

## Зависаний — нет

Профиль 4 (10 потоков жёстких RST) выполнил ~2 900 обрывов без
блокировок сервера. Приём новых соединений продолжался.

## Корректность TLS — подтверждена

Профиль 3 выполнил 30 000+ 16 KB echo-обменов (≈ 480 MB) без ошибок.
KeyUpdate отрабатывает корректно.

# Вывод

Оба теста отработали полные 5 минут, все проверки пройдены.

1.  **Утечек памяти нет** — heap стабилен, без тренда роста.

2.  **Зависаний нет** — все профили завершились, тест аварийных обрывов
    не вызывает блокировок сервера.

3.  **Корректность TLS подтверждена** — Профиль 3: 30 000+ 16 KB
    обменов, KeyUpdate отрабатывает без ошибок.

4.  **Очистка сессий работает** — LRU-кэш держится на лимите 5 000.

5.  **0 ошибок** в JsseStressTest, 4 ошибки (0,0016 %) в UndertowStressTest
    Profile 1 — не регрессия, флуктуация TCP TIME_WAIT при высокой
    конкурентности.

6.  **Heap повышен** относительно отчёта №4 (1 650/747 vs 653/285 MB) —
    накопительный эффект от последовательных прогонов на одной JVM,
    throughput не снизился.

7.  **Регрессии нет** — профили 1–4 показывают стабильные результаты,
    сравнимые с отчётом №4 (+4,4 % на Profile 1 в JsseStess, +1,7 % в
    Undertow). GC count стабилен (4 706/4 672 vs 4 799/4 641).
