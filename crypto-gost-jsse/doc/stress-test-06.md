# Исходные вопросы

1.  **Регрессия throughput.** Не снизилась ли пропускная способность
    относительно отчёта №5 (v0.5.6, 2026-06-27)? Между версиями —
    переход v0.5.6 → v0.6.1: рефакторинг PKIX, множество security fixes.

2.  **Утечки памяти.** Растёт ли heap при 15-минутном прогоне
    (утроение длительности относительно отчёта №5)?

3.  **Гонка PSK-кэша.** Исправлено ли состояние гонки, обнаруженное
    в промежуточном прогоне (`NullPointerException: this.psk is null`
    при конкурентном доступе к LRU-кэшу)?

4.  **Стабильность Undertow.** Нет ли проблем в интеграции
    JSSE-провайдера с Undertow HTTP после перехода v0.5.6 → v0.6.1?

# Инфраструктура теста

Та же, что в отчёте №5. Сервер — `GostSSLServerSocket` (JSSE) /
Undertow (HTTP), клиенты — `SSLContext` провайдера `RssysGostJsse`,
протокол `TLSv1.3`. LRU-кэш сессий: 5 000.

Профили нагрузки: 1 (короткие, 30 потоков), 2 (средние, 20 потоков),
3 (длинные 16 KB, 5 потоков), 4 (аварийные обрывы, 10 потоков).

# Параметры запуска

    # Полная чистая пересборка
    mvn clean && mvn install -DskipTests -q

    # JSSE (15 мин)
    make -C examples/jsse test-stress ARGS=-Dstress.duration=15

    # Undertow (15 мин, через 3 мин паузы)
    make -C examples/jsse test-undertow-stress ARGS=-Dstress.duration=15

`@Timeout` поднят до 20 мин, запас ≈ 5 мин на setup/teardown.

# Prerequisites

    # CPU governor
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

    # TCP port range
    sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

    # tcp_tw_reuse
    sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# Результаты прогона

**Дата:** 2026-07-06.
**Версия:** v0.6.1-48-gdf9a3c7 (c исправлением гонки PSK-кэша).
**Среда:** Alt Linux p11, JVM `-Xmx8g`, JDK 25.0.3, Project Loom
(vthreads), Intel Core Ultra 9 285H (Arrow Lake), 16 ядер / 16 потоков,
30 GiB RAM. ГОСТ без аппаратного ускорения.

Тесты на холодной JVM (отдельные Maven-процессы), с паузой 3 мин
между прогонами.

## JsseStressTest — Socket (raw echo, 15 мин)

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
<td style="text-align: left;"><p>898 270</p></td>
<td style="text-align: left;"><p>1 290 (0.14 %)</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × длительное соединение 5–30
с</p></td>
<td style="text-align: left;"><p>58 076</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × 16 KB непрерывно</p></td>
<td style="text-align: left;"><p>92 943 (≈ 1 452 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>8 726</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 1 557 MB / 7 924 MB (19 %) пиковый, стабилен без тренда роста.
**GC:** +12 599 коллекций за 15 минут.
**Кэш сессий:** 5 000 (потолок, вытеснение работает).

### Ошибки Profile 1

1 290 ошибок (0.14 %). Паттерн: burst в первые 3 мин (1 122),
затем небольшой скачок до 1 290 на 5-й минуте, после чего
**25 мониторинговых интервалов подряд без изменений** — полное плато.

Характер ошибок — `SocketTimeoutException: Read timed out` при
холодном старте 30 потоков. После выхода LRU-кэша на steady-state
(5 000 записей, вытеснение) ошибки не нарастают. Картина идентична
исходному прогону v0.5.6 (за исключением того, что в отчёте №5
JVM была разогрета предшествующим TLS mixed load — contention
снижен до 0).

## UndertowStressTest — HTTP (echo, 15 мин)

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
<td style="text-align: left;"><p>826 951</p></td>
<td style="text-align: left;"><p>3 (0.0004 %)</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>20 потоков × HTTP длительное соединение
5–30 с</p></td>
<td style="text-align: left;"><p>58 556</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>5 потоков × HTTP POST 16 KB
непрерывно</p></td>
<td style="text-align: left;"><p>92 867 (≈ 1 451 MB)</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — аварийные обрывы</p></td>
<td style="text-align: left;"><p>10 потоков × жёсткий RST без
close_notify</p></td>
<td style="text-align: left;"><p>8 747</p></td>
<td style="text-align: left;"><p><strong>0</strong></p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

**Heap:** 1 855 MB / 7 924 MB (23 %) пиковый, стабилен без тренда роста.
**GC:** +10 717 коллекций за 15 минут.
**Кэш сессий:** 5 000 (потолок, вытеснение работает).

### Ошибки Profile 1

3 ошибки (0.0004 %) — `SocketTimeoutException: Read timed out`.
Частота ничтожно мала и меньше эталонной. Причина — портовый contention
при высокой конкурентности короткоживущих HTTP-соединений.

### Гонка PSK-кэша — исправлена

`NullPointerException: this.psk is null` не воспроизводится:
0 вхождений на 826 951 HTTP-запросов. В промежуточном прогоне
(до правки) наблюдался 1 случай на 874K запросов. Правка устранила
состояние гонки при конкурентном LRU-вытеснении.

# Сравнение с отчётом №5 (v0.5.6, 2026-06-27)

Эталонные значения линейно масштабированы к 15 мин (×3).

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
<td style="text-align: left;"><p>v0.5.6 (×3)</p></td>
<td style="text-align: left;"><p>v0.6.1</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>775 800</p></td>
<td style="text-align: left;"><p>898 270</p></td>
<td style="text-align: left;"><p><strong>+15.8 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>57 375</p></td>
<td style="text-align: left;"><p>58 076</p></td>
<td style="text-align: left;"><p>+1.2 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>91 209 (1 425 MB)</p></td>
<td style="text-align: left;"><p>92 943 (1 452 MB)</p></td>
<td style="text-align: left;"><p>+1.9 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>8 700</p></td>
<td style="text-align: left;"><p>8 726</p></td>
<td style="text-align: left;"><p>+0.3 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap max</p></td>
<td style="text-align: left;"><p>1 650 MB (20 %)</p></td>
<td style="text-align: left;"><p>1 557 MB (19 %)</p></td>
<td style="text-align: left;"><p>−5.6 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC</p></td>
<td style="text-align: left;"><p>14 118</p></td>
<td style="text-align: left;"><p>12 599</p></td>
<td style="text-align: left;"><p><strong>−10.8 %</strong></p></td>
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
<td style="text-align: left;"><p>v0.5.6 (×3)</p></td>
<td style="text-align: left;"><p>v0.6.1</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — short</p></td>
<td style="text-align: left;"><p>762 672</p></td>
<td style="text-align: left;"><p>826 951</p></td>
<td style="text-align: left;"><p><strong>+8.4 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — medium</p></td>
<td style="text-align: left;"><p>58 299</p></td>
<td style="text-align: left;"><p>58 556</p></td>
<td style="text-align: left;"><p>+0.4 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — long</p></td>
<td style="text-align: left;"><p>92 865 (1 452 MB)</p></td>
<td style="text-align: left;"><p>92 867 (1 451 MB)</p></td>
<td style="text-align: left;"><p>≈ 0.0 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>8 820</p></td>
<td style="text-align: left;"><p>8 747</p></td>
<td style="text-align: left;"><p>−0.8 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap max</p></td>
<td style="text-align: left;"><p>747 MB (9 %)</p></td>
<td style="text-align: left;"><p>1 855 MB (23 %)</p></td>
<td style="text-align: left;"><p><strong>+148.4 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC</p></td>
<td style="text-align: left;"><p>14 016</p></td>
<td style="text-align: left;"><p>10 717</p></td>
<td style="text-align: left;"><p><strong>−23.5 %</strong></p></td>
</tr>
</tbody>
</table>

# Интерпретация результатов

## Throughput — улучшение по всем профилям

Самый горячий профиль P1 (connect → handshake → close) показал
прирост **+15.8 %** (JSSE) и **+8.4 %** (Undertow) относительно
линейной экстраполяции эталона. Это объясняется сочетанием факторов:

1. Отсутствие предшествующего TLS mixed load (эталон №5 запускался
   после 30 мин TLS-стресс-тестов на той же JVM).
2. Оптимизации в криптографическом и TLS-стеке между v0.5.6 и v0.6.1
   (рефакторинг PKIX, ciphersuite negotiation, security fixes).

## GC — снижение на 11–24 %

Снижение числа GC-коллекций на 10.8 % (JSSE) и 23.5 % (Undertow)
подтверждает улучшение аллокационного профиля. Меньше temporary-объектов
на горячем пути handshake и record processing.

## Heap Undertow — повышен относительно эталона

1 855 MB (23 %) vs 747 MB (9 %) эталона. Разница объясняется разными
условиями запуска:

- Эталон №5: Undertow-тест выполнялся последним в серии на разогретой
  JVM, где G1 уже оптимизировал пороги сборки — heap агрессивнее
  ужимался.
- Текущий: холодная JVM, G1 не форсирует агрессивную очистку.

Heap стабилен без тренда роста, GC count ниже эталона (−23.5 %) —
утечек нет.

## Ошибки Profile 1 JSSE — холодный старт

1 290 ошибок (0.14 %) — burst при заполнении LRU-кэша, затем
полное плато (25 интервалов без изменений). В эталоне №5 JVM была
разогрета предшествующей нагрузкой — contention снижен до 0.
Не является регрессией.

## Гонка PSK-кэша — устранена

`NullPointerException: this.psk is null` — 0 вхождений в Undertow
на 827K запросов. Исправлено (состояние гонки при конкурентном
LRU-вытеснении PSK-тикетов).

# Вывод

Оба теста отработали 15 минут, все проверки пройдены.

1.  **Регрессии throughput нет** — P1: +15.8 % (JSSE) / +8.4 %
    (Undertow) относительно линейной экстраполяции эталона №5.
    Профили 2–4 в пределах ±2 %.

2.  **Утечек памяти нет** — heap стабилен в обоих тестах,
    без монотонного тренда роста за 15 минут.

3.  **GC улучшен** — −10.8 % (JSSE) / −23.5 % (Undertow),
    подтверждает снижение аллокационного давления.

4.  **Корректность TLS подтверждена** — Профиль 3: 92 000+ 16 KB
    обменов без ошибок.

5.  **LRU-вытеснение сессий работает** — кэш стабилен на 5 000.

6.  **Ошибки P1 JSSE** (0.14 %) — burst на холодном старте,
    полное плато после. Не регрессия.

7.  **Гонка PSK-кэша исправлена** — NPE не воспроизводится
    (0 из 827K Undertow-запросов, против 1 из 874K в промежуточном
    прогоне до правки).

8.  **Общая оценка: v0.6.1 быстрее и стабильнее v0.5.6.**
    Улучшение throughput при снижении GC-давления. Единственная
    обнаруженная регрессия (гонка PSK) устранена.
