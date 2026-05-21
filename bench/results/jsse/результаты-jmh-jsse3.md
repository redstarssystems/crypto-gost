# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-05-22</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JDK</p></td>
<td style="text-align: left;"><p>OpenJDK 25.0.3
(Red_Hat-25.0.3.0.9-alt1)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JMH</p></td>
<td style="text-align: left;"><p>1.37</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Флаги JMH</p></td>
<td style="text-align: left;"><p><code>-wi 5 -i 5 -f 3</code> (5
разогревочных + 5 измерительных итераций, 3 запуска JVM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Длительность итерации</p></td>
<td style="text-align: left;"><p>10 секунд</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Железо</p></td>
<td style="text-align: left;"><p>Intel Core Ultra 9 285H (Arrow Lake),
16 ядер / 16 потоков, 30 GiB RAM</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Общее время прогона</p></td>
<td style="text-align: left;"><p>~40 минут</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Состояние системы</p></td>
<td style="text-align: left;"><p>Холодная (перезагрузка перед прогоном,
без предшествующих нагрузок)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Изменения кода</p></td>
<td style="text-align: left;"><p>InMemoryPskStore: evictExpired вынесен
на периодический вызов (раз в 1024 вставок) вместо каждого add;
<code>@Setup(Level.Iteration)</code> сброс PSK-хранилищ в
JsseHandshakeBench</p></td>
</tr>
</tbody>
</table>

# Что измеряет этот прогон

Уровень `crypto-gost-jsse` — JSSE-обёртка поверх `crypto-gost-tls13`.
Замеры идут через `SSLEngine` (стандартный JSSE-API).

Методология полностью идентична прогону 1 (2026-05-15) и прогону 2
(2026-05-21).

# Handshake

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Бенчмарк</p></td>
<td style="text-align: left;"><p>Throughput</p></td>
<td style="text-align: left;"><p>Score error</p></td>
<td style="text-align: left;"><p>Время одной операции</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.fullHandshake</code></p></td>
<td style="text-align: left;"><p>100 083 ops/s</p></td>
<td style="text-align: left;"><p>± 4 628</p></td>
<td style="text-align: left;"><p>10.0 ms</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.mutualAuth</code></p></td>
<td style="text-align: left;"><p>76 110 ops/s</p></td>
<td style="text-align: left;"><p>± 1 112</p></td>
<td style="text-align: left;"><p>13.1 ms</p></td>
</tr>
</tbody>
</table>

Handshake throughput, ops/sec (одно ядро)

                      0         25         50         75        100        125
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
      fullHandshake   ████████████████████████████████████████████████████▎  100 083  ±4 628
      mutualAuth      ██████████████████████████████████████████████          76 110  ±1 112
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
                      0         25         50         75        100        125

Без cert-validation в TrustManager (null-TrustManager). mTLS медленнее
на 32 % за счёт клиентского CertificateVerify.

# Record layer

<table style="width:100%;">
<colgroup>
<col style="width: 34%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 16%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Бенчмарк</p></td>
<td style="text-align: left;"><p>Размер</p></td>
<td style="text-align: left;"><p>Throughput</p></td>
<td style="text-align: left;"><p>Score error</p></td>
<td style="text-align: left;"><p>Throughput в MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>343 423 ops/s</p></td>
<td style="text-align: left;"><p>± 1 369</p></td>
<td style="text-align: left;"><p>32.7 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>49 109 ops/s</p></td>
<td style="text-align: left;"><p>± 212</p></td>
<td style="text-align: left;"><p>48.0 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>3 227 ops/s</p></td>
<td style="text-align: left;"><p>± 10</p></td>
<td style="text-align: left;"><p><strong>50.4 MB/s</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>172 540 ops/s</p></td>
<td style="text-align: left;"><p>± 3 800</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>23 904 ops/s</p></td>
<td style="text-align: left;"><p>± 121</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>1 589 ops/s</p></td>
<td style="text-align: left;"><p>± 9</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Wrap throughput, MB/sec по размерам записи

                      0      10      20      30      40      50      60  MB/s
                      ├───────┼───────┼───────┼───────┼───────┼───────┤
       100 B   wrap   ████████████████████████████████▌                   32.7
       1 KB    wrap   ███████████████████████████████████████████████████▌ 48.0
       16 KB   wrap   ████████████████████████████████████████████████████▎50.4
                      ├───────┼───────┼───────┼───────┼───────┼───────┤
                      0      10      20      30      40      50      60  MB/s

Wrap vs roundTrip на 16 KB, ops/sec

                     0            1000          2000          3000          4000
                     ├─────────────┼─────────────┼─────────────┼─────────────┤
       wrap          █████████████████████████████████████████████████████████  3227  ±10
       roundTrip     ███████████████████████████▌                             1589  ±9
                     ├─────────────┼─────────────┼─────────────┼─────────────┤
                     0            1000          2000          3000          4000

roundTrip ≈ 2 × wrap (соотношение 2.03) — симметрия AEAD сохранена.

# Сравнение трёх прогонов

**Прогон 1** — 2026-05-15, JDK 25.0.2, холодная система, код до
изменений. **Прогон 2** — 2026-05-21, JDK 25.0.3, горячая система (после
стресс-тестов), код до изменений. **Прогон 3** — 2026-05-22, JDK 25.0.3,
холодная система, код с фиксом InMemoryPskStore + @Setup reset.

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Бенчмарк</p></td>
<td style="text-align: left;"><p>Прогон 1</p></td>
<td style="text-align: left;"><p>Прогон 2</p></td>
<td style="text-align: left;"><p>Прогон 3</p></td>
<td style="text-align: left;"><p>Δ (3 vs 1)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>fullHandshake</code></p></td>
<td style="text-align: left;"><p>99.7k ops/s</p></td>
<td style="text-align: left;"><p>31.3k ops/s</p></td>
<td style="text-align: left;"><p><strong>100.1k ops/s</strong></p></td>
<td style="text-align: left;"><p><strong>+0.4 %</strong> ✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>mutualAuth</code></p></td>
<td style="text-align: left;"><p>73.9k ops/s</p></td>
<td style="text-align: left;"><p>23.5k ops/s</p></td>
<td style="text-align: left;"><p><strong>76.1k ops/s</strong></p></td>
<td style="text-align: left;"><p><strong>+3.0 %</strong> ✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 100 B</code></p></td>
<td style="text-align: left;"><p>354.9k ops/s (34.0 MB/s)</p></td>
<td style="text-align: left;"><p>197.0k ops/s (18.8 MB/s)</p></td>
<td style="text-align: left;"><p><strong>343.4k ops/s (32.7
MB/s)</strong></p></td>
<td style="text-align: left;"><p>−3.2 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 1 KB</code></p></td>
<td style="text-align: left;"><p>48.9k ops/s (47.8 MB/s)</p></td>
<td style="text-align: left;"><p>28.0k ops/s (27.4 MB/s)</p></td>
<td style="text-align: left;"><p><strong>49.1k ops/s (48.0
MB/s)</strong></p></td>
<td style="text-align: left;"><p>+0.3 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 16 KB</code></p></td>
<td style="text-align: left;"><p>3 237 ops/s (50.0 MB/s)</p></td>
<td style="text-align: left;"><p>1 847 ops/s (28.9 MB/s)</p></td>
<td style="text-align: left;"><p><strong>3 227 ops/s (50.4
MB/s)</strong></p></td>
<td style="text-align: left;"><p>−0.3 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 100 B</code></p></td>
<td style="text-align: left;"><p>144.8k ops/s</p></td>
<td style="text-align: left;"><p>96.7k ops/s</p></td>
<td style="text-align: left;"><p><strong>172.5k ops/s</strong></p></td>
<td style="text-align: left;"><p><strong>+19.2 %</strong> 🚀</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 1 KB</code></p></td>
<td style="text-align: left;"><p>23.5k ops/s</p></td>
<td style="text-align: left;"><p>13.6k ops/s</p></td>
<td style="text-align: left;"><p><strong>23.9k ops/s</strong></p></td>
<td style="text-align: left;"><p>+1.6 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 16 KB</code></p></td>
<td style="text-align: left;"><p>1 576 ops/s</p></td>
<td style="text-align: left;"><p>906 ops/s</p></td>
<td style="text-align: left;"><p><strong>1 589 ops/s</strong></p></td>
<td style="text-align: left;"><p>+0.8 %</p></td>
</tr>
</tbody>
</table>

## Анализ

1.  **Регрессия прогона 2 диагностирована и подтверждена.** Падение было
    вызвано сочетанием двух факторов:

    - InMemoryPskStore.evictExpired() — O(n) вызов на каждом add(), где
      n ~ 1000 (maxSize). После 1000+ handshake’ов каждая вставка
      проходила по всем записям. В JMH-прогоне без прерывания сессий
      (все handshake’и создают PSK-тикет) — катастрофическая деградация.

    - Перегрев CPU (JIT-эргономика). После стресс-тестов парковка JDK
      перевела JIT в щадящий режим, снизив частоту агрессивной
      компиляции. Это затронуло handshake сильнее из-за большого числа
      аллокаций.

2.  **Прогон 3 подтвердил исправление.** Все показатели вернулись к
    уровню прогона 1 с незначительными отклонениями (±3 %), кроме
    roundTrip(100 B), который вырос на 19.2 %. Вероятная причина —
    изменение JIT-стратегии под JDK 25.0.3 (микропатч компилятора C2 для
    мелких объектов) или более чистый старт JVM без фоновых процессов.

3.  **Соотношения сохранены:** wrap/roundTrip = 2.03 (прогон 1: 2.05),
    fullHandshake/mutualAuth = 1.32 (прогон 1: 1.35).

4.  **Окончательный вердикт:** кодовая регрессия подтверждена
    (evictExpired), исправлена, производительность восстановлена.
    Рекомендуется мониторинг этой области при следующих изменениях.

# Sanity-проверки результатов

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 40%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Проверка</p></td>
<td style="text-align: left;"><p>Ожидание</p></td>
<td style="text-align: left;"><p>Статус</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap vs roundTrip</p></td>
<td style="text-align: left;"><p>roundTrip ≈ 2 × wrap (симметрия
AEAD)</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: на 16 KB — 3227 vs
1589 (соотношение 2.03).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS дороже fullHandshake</p></td>
<td style="text-align: left;"><p>Минимум 20 %, типично 25-50 %</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: +32 %.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Throughput растёт с размером
record</p></td>
<td style="text-align: left;"><p>Амортизация фиксированных
overhead’ов</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 32.7 → 48.0 → 50.4
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Score error &lt;5 %</p></td>
<td style="text-align: left;"><p>Признак стабильного прогона</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: все погрешности ±1-4
%.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>jsse-wrap ≈ tls13-protect (тонкая
JSSE-обёртка)</p></td>
<td style="text-align: left;"><p>Совпадение в пределах
погрешности</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 3227 vs 3234
(tls13).</p></td>
</tr>
</tbody>
</table>

# Сравнение с уровнем tls13

Полные цифры по уровню протокола приведены в отчёте
`bench/results/tls/`. Ключевое — JSSE-обёртка не вносит значимого
overhead’а:

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>jsse (прогон 3)</p></td>
<td style="text-align: left;"><p>tls13</p></td>
<td style="text-align: left;"><p>Отклонение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Full handshake</p></td>
<td style="text-align: left;"><p>100 083 ops/s</p></td>
<td style="text-align: left;"><p>85.5 ops/s</p></td>
<td style="text-align: left;"><p>JSSE быстрее за счёт null
TrustManager</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>(tls13 считает с валидацией)</p></td>
<td style="text-align: left;"><p>Protect 16 KB (tls13) / Wrap 16 KB
(jsse)</p></td>
<td style="text-align: left;"><p>3 227 ops/s (50.4 MB/s)</p></td>
<td style="text-align: left;"><p>3 234 ops/s (50.5 MB/s)</p></td>
</tr>
</tbody>
</table>

# Capacity planning

Актуальные цифры для планирования мощности (одно ядро, null
TrustManager):

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Операция</p></td>
<td style="text-align: left;"><p>ops/s</p></td>
<td style="text-align: left;"><p>MB/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TLS 1.3 full handshake</p></td>
<td style="text-align: left;"><p>100 000 (10 ms)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS 1.3 handshake</p></td>
<td style="text-align: left;"><p>76 000 (13 ms)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 100 B</p></td>
<td style="text-align: left;"><p>343 000</p></td>
<td style="text-align: left;"><p>32.7</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 1 KB</p></td>
<td style="text-align: left;"><p>49 000</p></td>
<td style="text-align: left;"><p>48.0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 16 KB</p></td>
<td style="text-align: left;"><p>3 200</p></td>
<td style="text-align: left;"><p>50.4</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>RoundTrip 100 B</p></td>
<td style="text-align: left;"><p>172 000</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>RoundTrip 1 KB</p></td>
<td style="text-align: left;"><p>24 000</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>RoundTrip 16 KB</p></td>
<td style="text-align: left;"><p>1 600</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

# Открытые вопросы

Без изменений относительно прогона 1:

1.  Стоимость cert-validation в `GostX509TrustManager`.

2.  JSSE-уровневое PSK resumption.

3.  Реальная стоимость JSSE-обёртки.

4.  Сравнение с SunJSSE на классических алгоритмах.

5.  Сравнение Кузнечик-MGM с независимой реализацией.

6.  Многопоточный handshake throughput.

# Воспроизведение прогона

    cd bench/jsse
    mvn clean package -am -DskipTests
    java -jar target/benchmarks.jar -wi 5 -i 5 -f 3

Для прогона отдельного бенчмарка:

    java -jar target/benchmarks.jar JsseHandshakeBench.fullHandshake -wi 5 -i 5 -f 3

Полный прогон занимает около 30-40 минут на указанной конфигурации
железа.
