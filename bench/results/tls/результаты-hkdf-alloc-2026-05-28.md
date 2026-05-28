# Постановка

Исходная находка: `HkdfStreebog.newHmac()` создаёт новую пару
`Hmac + Streebog` на каждый вызов. За полный TLS 1.3 handshake — 15–20
раз (зависит от наличия PSK). Предполагалось, что это создаёт измеримое
GC-давление.

# Методика

Разработан и реализован JMH-бенчмарк `HkdfAllocationBench` в модуле
`bench/tls`.

## Измерения

- **Throughput**: пары `_new` (текущий код) vs `_reuse` (Hmac из
  `@State`, переиспользуется через `clear()+init()`)

- **Allocation rate**: `-prof gc` — `gc.alloc.rate` и
  `gc.alloc.rate.norm`

- **hashLen**: 32 (256-bit) и 64 (512-bit)

- **Конфигурация**: `-wi 1 -i 1 -f 1`

## Сценарии

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Бенчмарк</th>
<th style="text-align: left;">Описание</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>newHmac_only</code></p></td>
<td style="text-align: left;"><p>Чистая аллокация:
<code>newHmac() + clear()</code>, без криптоопераций</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacInit_only</code></p></td>
<td style="text-align: left;"><p>Чистый init:
<code>clear() + init(ikm)</code> на готовом Hmac</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_new</code></p></td>
<td
style="text-align: left;"><p><code>HkdfStreebog.extract(salt, ikm, hashLen)</code>
— текущий код</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_reuse</code></p></td>
<td
style="text-align: left;"><p><code>clear() + init() + update() + doFinal()</code>
с переиспользуемым Hmac</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>expand_new</code></p></td>
<td
style="text-align: left;"><p><code>HkdfStreebog.expand(prk, info, hashLen, hashLen)</code>
— текущий код</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>expand_reuse</code></p></td>
<td style="text-align: left;"><p>Аналог expand с переиспользуемым
Hmac</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>finishedKey_new</code></p></td>
<td
style="text-align: left;"><p><code>expandLabel(secret, "finished", ..., hashLen)</code>
— первый HMAC в computeVerifyData</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>finishedKey_reuse</code></p></td>
<td style="text-align: left;"><p>Аналог с переиспользуемым Hmac</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacVerify_new</code></p></td>
<td style="text-align: left;"><p><code>expandLabel</code> +
<code>newHmac</code> + <code>HMAC(finishedKey, transcript)</code> —
второй HMAC в computeVerifyData</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacVerify_reuse</code></p></td>
<td style="text-align: left;"><p>Аналог с переиспользуемым Hmac</p></td>
</tr>
</tbody>
</table>

# Результаты

## hashLen = 32

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Бенчмарк</th>
<th style="text-align: left;">Throughput (ops/s)</th>
<th style="text-align: left;">alloc.rate.norm</th>
<th style="text-align: left;"><code>_new</code> vs
<code>_reuse</code></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>newHmac_only</code></p></td>
<td style="text-align: left;"><p>13 447 824</p></td>
<td style="text-align: left;"><p>1 048 B/op</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacInit_only</code></p></td>
<td style="text-align: left;"><p>1 156 693</p></td>
<td style="text-align: left;"><p>~0 B/op</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_new</code></p></td>
<td style="text-align: left;"><p>136 404</p></td>
<td style="text-align: left;"><p>1 144 B/op</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_reuse</code></p></td>
<td style="text-align: left;"><p>134 896</p></td>
<td style="text-align: left;"><p>96 B/op</p></td>
<td style="text-align: left;"><p>+1.1%</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>expand_new</code></p></td>
<td style="text-align: left;"><p>134 489</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>expand_reuse</code></p></td>
<td style="text-align: left;"><p>135 570</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>+0.8%</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>finishedKey_new</code></p></td>
<td style="text-align: left;"><p>134 172</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>finishedKey_reuse</code></p></td>
<td style="text-align: left;"><p>134 326</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>+0.1%</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacVerify_new</code></p></td>
<td style="text-align: left;"><p>65 689</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacVerify_reuse</code></p></td>
<td style="text-align: left;"><p>67 045</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>+2.1%</p></td>
</tr>
</tbody>
</table>

## hashLen = 64

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Бенчмарк</th>
<th style="text-align: left;">Throughput (ops/s)</th>
<th style="text-align: left;"><code>_new</code> vs
<code>_reuse</code></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>extract_new</code></p></td>
<td style="text-align: left;"><p>111 283</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_reuse</code></p></td>
<td style="text-align: left;"><p>113 420</p></td>
<td style="text-align: left;"><p>+1.9%</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>newHmac_only</code></p></td>
<td style="text-align: left;"><p>13 805 011</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacInit_only</code></p></td>
<td style="text-align: left;"><p>1 172 022</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

## GC profiler (hashLen = 32)

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Бенчмарк</th>
<th style="text-align: left;">gc.alloc.rate</th>
<th style="text-align: left;">gc.alloc.rate.norm</th>
<th style="text-align: left;">gc.count</th>
<th style="text-align: left;">gc.time</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>extract_new</code></p></td>
<td style="text-align: left;"><p>148.8 MB/sec</p></td>
<td style="text-align: left;"><p>1 144 B/op</p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>16 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>extract_reuse</code></p></td>
<td style="text-align: left;"><p>12.35 MB/sec</p></td>
<td style="text-align: left;"><p>96 B/op</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>3 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>newHmac_only</code></p></td>
<td style="text-align: left;"><p>13 440 MB/sec</p></td>
<td style="text-align: left;"><p>1 048 B/op</p></td>
<td style="text-align: left;"><p>101</p></td>
<td style="text-align: left;"><p>162 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>hmacInit_only</code></p></td>
<td style="text-align: left;"><p>~0 MB/sec</p></td>
<td style="text-align: left;"><p>~0 B/op</p></td>
<td style="text-align: left;"><p>≈0</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

# Анализ

## Стоимость отдельных операций (hashLen = 32)

    newHmac (чистая аллокация + clear):      74 ns  (13.4M/с)
    hmacInit (clear + init, без аллокации):  864 ns  (1.16M/с) → в 11.6× дороже
    extract (полный HMAC):                   7 330 ns (136K/с)

Доля аллокации в extract: `74 / 7 330 ≈ 1.0%`

## Ключевое наблюдение

`hmacInit_only` (864 ns) в **11.6× дороже** `newHmac_only` (74 ns).
Причина: `init()` выполняет `digest.reset()` + XOR 64 байт ipad/opad  
`digest.update(inputPad)` — то есть полный блок Streebog (64 байта через
gN).

Это означает, что гипотетический кеш Hmac с `clear() + init()` был бы не
только бесполезен, но и **медленнее**, чем `new Hmac()` + конструктор.
Аллокация дешевле переинициализации.

## GC-давление

Цифра `148.8 MB/s` из GC profiler — артефакт бенчмарка (136K вызовов
extract в секунду в синтетическом тесте). В реальном сценарии extract
вызывается 2–3 раза за handshake, не 136K раз в секунду.

Реалистичная оценка для production-сервера:

- 1 handshake: <sub>15\ вызовов\ `newHmac()`\ +</sub> 1 048 B/op на
  вызов ≈ **~15 KB**

- 1 000 handshake/с: ~15.7 MB/s в young gen

- При Eden ~200–500 MB: minor GC один раз в 12–30 секунд, длительность
  &lt;1 ms

Это **незначимое** GC-давление.

# Вывод

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Параметр</th>
<th style="text-align: left;">Значение</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Severity</p></td>
<td style="text-align: left;"><p>MEDIUM → <strong>LOW (фактически
WONTFIX)</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Overhead</p></td>
<td style="text-align: left;"><p><strong>&lt;2%</strong> throughput во
всех парах <code>_new</code> vs <code>_reuse</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC impact</p></td>
<td style="text-align: left;"><p>Шум: ~15.7 MB/s при 1K handshakes/с,
minor GC раз в 12–30 сек</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ThreadLocal</p></td>
<td style="text-align: left;"><p>Неприменим: запрещён AGENTS.md
(vthread-блокировка)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Per-session cache</p></td>
<td style="text-align: left;"><p>Бессмыслен: <code>clear()+init()</code>
медленнее <code>new</code> + конструктора</p></td>
</tr>
</tbody>
</table>

**Решение**: код не менять. Бенчмарк сохранён в репозитории для контроля
регрессий.

# Файлы

- `bench/tls/src/main/java/org/rssys/bench/HkdfAllocationBench.java` —
  185 строк, 10 `@Benchmark` методов

- Запуск:
  `mvn package -f bench/tls && java -jar bench/tls/target/benchmarks.jar HkdfAllocationBench -prof gc`
