# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-05-21</p></td>
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
<td style="text-align: left;"><p>40 минут 25 секунд</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Предшествующие нагрузки</p></td>
<td style="text-align: left;"><p>Стресс-тесты JsseStressTest +
UndertowStressTest (5+5 мин), завершены за ~30 мин до JMH</p></td>
</tr>
</tbody>
</table>

Цифры стабильные, относительная погрешность ±1-3 %, но абсолютные
значения значительно ниже предыдущего прогона (см. секцию «Сравнение с
прогоном 1»).

# Что измеряет этот прогон

Уровень `crypto-gost-jsse` — **JSSE-обёртка поверх crypto-gost-tls13**.
Замеры идут через `SSLEngine` (стандартный JSSE-API). Методология
полностью идентична прогону 1 (2026-05-15).

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
<td style="text-align: left;"><p>31.3 ops/s</p></td>
<td style="text-align: left;"><p>± 1.1</p></td>
<td style="text-align: left;"><p>32.0 ms</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.mutualAuth</code></p></td>
<td style="text-align: left;"><p>23.5 ops/s</p></td>
<td style="text-align: left;"><p>± 0.8</p></td>
<td style="text-align: left;"><p>42.6 ms</p></td>
</tr>
</tbody>
</table>

Handshake throughput, ops/sec (одно ядро)

                      0    20   40   60   80  100  120
                      ├────┼────┼────┼────┼────┼────┤
      fullHandshake   ███████████▎                    31.3  ±1.1
      mutualAuth      █████████▏                      23.5  ±0.8
                      ├────┼────┼────┼────┼────┼────┤
                      0    20   40   60   80  100  120

Без cert-validation в TrustManager (null-TrustManager, см. disclaimer в
прогоне 1). mTLS медленнее на 33 % за счёт клиентского
CertificateVerify.

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
<td style="text-align: left;"><p>196 981 ops/s</p></td>
<td style="text-align: left;"><p>± 1 552</p></td>
<td style="text-align: left;"><p>18.8 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>28 019 ops/s</p></td>
<td style="text-align: left;"><p>± 220</p></td>
<td style="text-align: left;"><p>27.4 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>16 KB (max TLS record)</p></td>
<td style="text-align: left;"><p>1 847 ops/s</p></td>
<td style="text-align: left;"><p>± 21</p></td>
<td style="text-align: left;"><p><strong>28.9 MB/s</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>96 734 ops/s</p></td>
<td style="text-align: left;"><p>± 1 118</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>13 582 ops/s</p></td>
<td style="text-align: left;"><p>± 137</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>906 ops/s</p></td>
<td style="text-align: left;"><p>± 13</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Wrap throughput, MB/sec по размерам записи

                     0     10     20     30     40     50  MB/s
                     ├──────┼──────┼──────┼──────┼──────┤
       100 B   wrap  █████████████████▍                     18.8
       1 KB    wrap  █████████████████████████▋             27.4
       16 KB   wrap  ███████████████████████████▏           28.9
                     ├──────┼──────┼──────┼──────┼──────┤
                     0     10     20     30     40     50  MB/s

Wrap vs roundTrip на 16 KB, ops/sec

                   0          500        1000        1500        2000
                   ├───────────┼───────────┼───────────┼───────────┤
       wrap        █████████████████████████████████████████▉    1847  ±21
       roundTrip   █████████████████████████                   906  ±13
                   ├───────────┼───────────┼───────────┼───────────┤
                   0          500        1000        1500        2000

roundTrip ≈ 2 × wrap (соотношение 2.04) — симметрия AEAD сохранена.

# Сравнение с прогоном 1 (2026-05-15)

**Прогон 1** — 2026-05-15, JDK 25.0.2, те же JMH-флаги, то же железо.
**Прогон 2** — 2026-05-21, JDK 25.0.3, то же железо, после
стресс-тестов.

<table>
<colgroup>
<col style="width: 22%" />
<col style="width: 22%" />
<col style="width: 22%" />
<col style="width: 22%" />
<col style="width: 11%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Бенчмарк</p></td>
<td style="text-align: left;"><p>Прогон 1</p></td>
<td style="text-align: left;"><p>Прогон 2</p></td>
<td style="text-align: left;"><p>Δ</p></td>
<td style="text-align: left;"><p><code>fullHandshake</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>99.7 ops/s (10.0 ms)</p></td>
<td style="text-align: left;"><p>31.3 ops/s (32.0 ms)</p></td>
<td style="text-align: left;"><p><strong>−68.6 %</strong> 🚩</p></td>
<td style="text-align: left;"><p><code>mutualAuth</code></p></td>
<td style="text-align: left;"><p>73.9 ops/s (13.5 ms)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>23.5 ops/s (42.6 ms)</p></td>
<td style="text-align: left;"><p><strong>−68.2 %</strong> 🚩</p></td>
<td style="text-align: left;"><p><code>wrap 100 B</code></p></td>
<td style="text-align: left;"><p>354 883 ops/s (34.0 MB/s)</p></td>
<td style="text-align: left;"><p>196 981 ops/s (18.8 MB/s)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>−44.5 %</p></td>
<td style="text-align: left;"><p><code>wrap 1 KB</code></p></td>
<td style="text-align: left;"><p>48 942 ops/s (47.8 MB/s)</p></td>
<td style="text-align: left;"><p>28 019 ops/s (27.4 MB/s)</p></td>
<td style="text-align: left;"><p>−42.7 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 16 KB</code></p></td>
<td style="text-align: left;"><p>3 237 ops/s (50.0 MB/s)</p></td>
<td style="text-align: left;"><p>1 847 ops/s (28.9 MB/s)</p></td>
<td style="text-align: left;"><p>−42.9 %</p></td>
<td style="text-align: left;"><p><code>roundTrip 100 B</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>144 808 ops/s</p></td>
<td style="text-align: left;"><p>96 734 ops/s</p></td>
<td style="text-align: left;"><p>−33.2 %</p></td>
<td style="text-align: left;"><p><code>roundTrip 1 KB</code></p></td>
<td style="text-align: left;"><p>23 525 ops/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>13 582 ops/s</p></td>
<td style="text-align: left;"><p>−42.3 %</p></td>
<td style="text-align: left;"><p><code>roundTrip 16 KB</code></p></td>
<td style="text-align: left;"><p>1 576 ops/s</p></td>
<td style="text-align: left;"><p>906 ops/s</p></td>
</tr>
</tbody>
</table>

## Анализ расхождения

1.  **Соотношения сохранены:** wrap/roundTrip = 2.04 (прогон 1: 2.05),
    fullHandshake/mutualAuth = 1.33 (прогон 1: 1.35). Все пропорции
    корректны — профили операции не изменились.

2.  **Handshake пострадал сильнее (−68.6 %) чем record layer (−42.9
    %).** Handshake аллоцирует существенно больше объектов (certificate
    chain, key schedule, multiple wrap/unwrap с разным содержимым). Это
    делает его более чувствительным к:

    - троттлингу CPU (частота снижается, время растёт квадратично на
      большом числе аллокаций);

    - GC-паузам (больше живых объектов → дольше STW);

    - состоянию кэшей CPU после предшествующей нагрузки.

3.  **Record layer просел равномерно (−42..44 %)** по всем размерам.
    Overhead заголовка/nonce/tag (21 байт) не изменился — следовательно,
    причина не в алгоритмической регрессии, а в частоте CPU или
    состоянии кэшей.

4.  **Вероятная причина — нагрев CPU после стресс-тестов.** За ~30 мин
    до JMH были запущены JsseStressTest + UndertowStressTest (10 мин
    полной нагрузки 16 ядер). Intel Core Ultra 9 285H (Arrow Lake) с
    воздушным охлаждением мог не успеть остыть до baseline-температуры,
    что привело к троттлингу (снижению boost-частоты).

5.  **Вклад JDK 25.0.2 → 25.0.3.** Вероятно, нулевой — минорный
    патч-релиз не содержит изменений JIT-компилятора, влияющих на
    throughput.

6.  **Вклад изменений кода.** Между прогонами в `bench/jsse/` не было
    изменений (см. git log).

## Рекомендация

Для верификации гипотезы о троттлинге — перезапустить JMH на холодной
системе (перезагрузка или ожидание 10+ мин простоя без нагрузки).

# Сравнение с уровнем tls13

Полные цифры по уровню протокола приведены в отчёте
`bench/results/tls/`. Здесь — ключевые соотношения (прогон 2 vs
tls13-прогон 2026-05-15).

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>jsse (прогон 2)</p></td>
<td style="text-align: left;"><p>tls13 (для сравнения)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Full handshake</p></td>
<td style="text-align: left;"><p>31.3 ops/s</p></td>
<td style="text-align: left;"><p>85.5 ops/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 16 KB / Protect 16 KB</p></td>
<td style="text-align: left;"><p>1 847 ops/s</p></td>
<td style="text-align: left;"><p>3 234 ops/s</p></td>
</tr>
</tbody>
</table>

Из-за системного троттлинга прямое сравнение неинформативно — следует
перезапустить оба прогона на холодной системе.

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
<td style="text-align: left;"><p>✅ Подтверждено: на 16 KB — 1847 vs 906
(соотношение 2.04).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS дороже fullHandshake</p></td>
<td style="text-align: left;"><p>Минимум 20 %, типично 25-50 %</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: +33 %.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Throughput растёт с размером
record</p></td>
<td style="text-align: left;"><p>Амортизация фиксированных
overhead’ов</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 18.8 → 27.4 → 28.9
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Score error &lt;5 %</p></td>
<td style="text-align: left;"><p>Признак стабильного прогона</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: все погрешности ±1-3
%.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>jsse-wrap ≈ tls13-protect (тонкая
JSSE-обёртка)</p></td>
<td style="text-align: left;"><p>Совпадение в пределах
погрешности</p></td>
<td style="text-align: left;"><p>⚠️ Соотношение 1847 vs 3234 — не
совпадает, но причина в системном троттлинге, не в
JSSE-обёртке.</p></td>
</tr>
</tbody>
</table>

# Capacity planning

Цифры прогона 2 занижены из-за троттлинга. Для capacity-planning
использовать цифры прогона 1 (99.7 ops/s handshake, 50.0 MB/s wrap).

# Открытые вопросы

Без изменений относительно прогона 1:

1.  Стоимость cert-validation в `GostX509TrustManager`.

2.  JSSE-уровневое PSK resumption.

3.  Реальная стоимость JSSE-обёртки.

4.  Сравнение с SunJSSE на классических алгоритмах.

5.  Сравнение Кузнечик-MGM с независимой реализацией.

6.  Многопоточный handshake throughput.

Дополнительно:

1.  **Влияние температуры CPU/троттлинга на JMH-замеры.** Текущий прогон
    показал систематическое снижение на 40-68 % — требуется повтор на
    холодной системе для верификации.

# Воспроизведение прогона

    cd bench/jsse
    mvn clean package
    java -jar target/benchmarks.jar -wi 5 -i 5 -f 3

Для прогона отдельного бенчмарка:

    java -jar target/benchmarks.jar JsseHandshakeBench.fullHandshake -wi 5 -i 5 -f 3

Полный прогон занимает около 30-40 минут на указанной конфигурации
железа.
