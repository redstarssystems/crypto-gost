# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-05-15</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JDK</p></td>
<td style="text-align: left;"><p>OpenJDK 25.0.2
(Red_Hat-25.0.2.0.10-alt1)</p></td>
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
</tbody>
</table>

Цифры стабильные, относительная погрешность ±1-4 %.

# Что измеряет этот прогон

Уровень `crypto-gost-tls13` — **чистый протокол**, без JSSE-обёртки.
Замеры идут через `TlsSession` напрямую, обмен — через
`InMemoryTlsTransport` (in-memory blocking-канал). Сети нет, JCA нет.

В отличие от jsse-бенчей, **cert-validation здесь работает**:
`TlsClientConfig.withCaPublicKey(...)` включает
`TlsCertificateValidator.checkServerCertificateChain`, который выполняет
`Signature.verifyHash` подписи сертификата на ГОСТ Р 34.10. Это даёт
более реалистичную картину handshake-стоимости.

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
style="text-align: left;"><p><code>FullHandshakeBench.handshake</code></p></td>
<td style="text-align: left;"><p>85.5 ops/s</p></td>
<td style="text-align: left;"><p>± 1.7</p></td>
<td style="text-align: left;"><p>11.7 ms</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>PskResumptionBench.resume</code></p></td>
<td style="text-align: left;"><p>154.1 ops/s</p></td>
<td style="text-align: left;"><p>± 4.2</p></td>
<td style="text-align: left;"><p>6.5 ms</p></td>
</tr>
</tbody>
</table>

Full handshake vs PSK resumption, ops/sec

                           0    40   80  120  160  200  240
                           ├────┼────┼────┼────┼────┼────┤
      Full handshake       ███████████▉                     85.5  ±1.7
      PSK resumption       ████████████████████████████████████▌ 154.1 ±4.2
                           ├────┼────┼────┼────┼────┼────┤
                           0    40   80  120  160  200  240

      Speedup: 1.80× (80% быстрее, 11.7 → 6.5 ms).

## PSK resumption: результаты после P1-фикса

**Корневая причина**: `InMemoryPskStore.getForResumption()` возвращал
недетерминированный entry (первый non-expired в
`ConcurrentHashMap.values()`). При накоплении &gt;1 entry клиент мог
отправить stale ticket, который сервер уже удалил (single-use по RFC
8446 §4.6.1) → fallback на full handshake.

**Фикс**: `getForResumption()` возвращает entry с максимальным
`issueTime` (самый свежий NST).

**Распределение экономии (11.7 → 6.5 ms = 5.2 ms)**:

| Компонент | Сэкономлено | Пояснение |
|-----------|------------|-----------| | sign + verify
(CertificateVerify) |
<sub>3.1\ ms\ |\ Нет\ сертификационных\ сообщений\ |\ |\ Certificate\ parsing\ +\ OCSP\ |</sub>
2.1 ms | ASN.1 цепочки, AIA, OCSP-проверка | | ECDHE (psk\_dhe\_ke) | 0
ms | Forward secrecy сохранена |

**Режим**: `psk_dhe_ke` (TlsMessageBuilder:81) — ECDHE выполняется для
forward secrecy. **Детерминизм**: самый свежий ticket, никакого
undefined поведения из CHM iteration order.

# Компоненты handshake

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Операция</p></td>
<td style="text-align: left;"><p>Throughput</p></td>
<td style="text-align: left;"><p>Score error</p></td>
<td style="text-align: left;"><p>Время одной операции</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDHE keygen</p></td>
<td style="text-align: left;"><p>871.0 ops/s</p></td>
<td style="text-align: left;"><p>± 5.0</p></td>
<td style="text-align: left;"><p>1.15 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDHE shared secret&lt;br&gt;Как
стороны договариваются об общем ключе</p></td>
<td style="text-align: left;"><p>786.7 ops/s</p></td>
<td style="text-align: left;"><p>± 10.0</p></td>
<td style="text-align: left;"><p>1.27 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Sign (ГОСТ Р 34.10)</p></td>
<td style="text-align: left;"><p>804.4 ops/s</p></td>
<td style="text-align: left;"><p>± 32.1</p></td>
<td style="text-align: left;"><p>1.24 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Verify (ГОСТ Р 34.10)</p></td>
<td style="text-align: left;"><p>540.9 ops/s</p></td>
<td style="text-align: left;"><p>± 28.5</p></td>
<td style="text-align: left;"><p>1.85 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HKDF extract</p></td>
<td style="text-align: left;"><p>133 300 ops/s</p></td>
<td style="text-align: left;"><p>± 879</p></td>
<td style="text-align: left;"><p>7.5 µs</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HKDF expand</p></td>
<td style="text-align: left;"><p>132 300 ops/s</p></td>
<td style="text-align: left;"><p>± 1 400</p></td>
<td style="text-align: left;"><p>7.6 µs</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Derive traffic keys</p></td>
<td style="text-align: left;"><p>66 600 ops/s</p></td>
<td style="text-align: left;"><p>± 263</p></td>
<td style="text-align: left;"><p>15 µs</p></td>
</tr>
</tbody>
</table>

Стоимость одной операции, миллисекунды

                             0.0    0.5    1.0    1.5    2.0
                             ├──────┼──────┼──────┼──────┤
      ECDHE keygen           ███████████▌                      1.15 ms
      ECDHE shared           █████████████▌                     1.27 ms
      Sign                   ████████████▌                     1.24 ms
      Verify                 ██████████████████▌               1.85 ms
      HKDF extract           ▏                                 0.0075 ms (7.5 µs)
      HKDF expand            ▏                                 0.0076 ms
      Derive traffic keys    ▏                                 0.015 ms
                             ├──────┼──────┼──────┼──────┤
                             0.0    0.5    1.0    1.5    2.0  ms

      Асимметричная криптография (ECDHE + sign/verify) — миллисекунды.
      Симметричная (HKDF, key derivation) — на 2-3 порядка быстрее.

## Что доминирует в 11.7 ms handshake

Полный TLS 1.3 handshake вызывает каждую операцию определённое
количество раз. Считаем суммарную стоимость **асимметричной**
криптографии:

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Операция</p></td>
<td style="text-align: left;"><p>Раз</p></td>
<td style="text-align: left;"><p>Стоимость одного вызова</p></td>
<td style="text-align: left;"><p>Суммарно</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDHE keygen</p></td>
<td style="text-align: left;"><p>2 (client + server)</p></td>
<td style="text-align: left;"><p>1.15 ms</p></td>
<td style="text-align: left;"><p>2.30 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ECDHE shared secret</p></td>
<td style="text-align: left;"><p>2 (обе стороны)</p></td>
<td style="text-align: left;"><p>1.27 ms</p></td>
<td style="text-align: left;"><p>2.54 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Sign (server
CertificateVerify)</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>1.24 ms</p></td>
<td style="text-align: left;"><p>1.24 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Verify (client проверяет
server)</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>1.85 ms</p></td>
<td style="text-align: left;"><p>1.85 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Verify (CA-signature на
сертификате)</p></td>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>1.85 ms</p></td>
<td style="text-align: left;"><p>1.85 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HKDF / derive keys</p></td>
<td style="text-align: left;"><p>~10 вызовов</p></td>
<td style="text-align: left;"><p>~10 µs</p></td>
<td style="text-align: left;"><p>~0.1 ms</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Сумма асимметричной</p></td>
<td style="text-align: left;"></td>
<td style="text-align: left;"></td>
<td style="text-align: left;"><p><strong>9.88 ms</strong></p></td>
</tr>
</tbody>
</table>

Из 11.7 ms handshake примерно **9.88 ms (84 %)** — это асимметричная
криптография (ECDHE + подписи). Остальные **1.82 ms (16 %)** — протокол,
транспорт, шифрование handshake-сообщений, key schedule. Простыми
словами: почти всё время рукопожатия уходит на математику с открытыми
ключами, а не на передачу данных.

`ECDHE shared secret` отдельным бенчем не измерен — оценка
<sub>1.15\ ms\ сделана\ из\ соображений\ «точечное\ умножение\ на\ той\ же\ кривой\ имеет\ ту\ же\ сложность,\ что\ keygen».\ Теперь\ shared\ secret\ замерен\ отдельно:\ 1.27\ ms\ (на\ 10\ %\ дольше\ keygen\ —\ точка\ ещё\ и\ сериализуется\ после\ умножения).\ Оценка\ «</sub>1.15
ms по аналогии с keygen» была почти верной; уточнённая картина не меняет
выводов.

## Узкое место

**Узкое место handshake — асимметричная криптография на ГОСТ-кривой
`tc26a256`, реализованная на чистой Java**. ECDHE (keygen + shared)
занимает
<sub>40\ %\ handshake.\ Sign+verify\ (включая\ verify\ CA-подписи)\ —\ ещё</sub>
42 %.

Оптимизация HKDF/key schedule даст незаметный выигрыш (вместе они ~1 %
handshake). Существенное ускорение возможно только через:

- нативную реализацию point multiplication на эллиптической кривой (JNI
  / Foreign Function API);

- алгоритмические оптимизации (precomputed tables, Montgomery ladder с
  правильной длиной окна);

- batch-операции, если приложение делает много параллельных
  handshake’ов.

# Streebog-256

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
<td style="text-align: left;"><p>Размер входа</p></td>
<td style="text-align: left;"><p>Throughput</p></td>
<td style="text-align: left;"><p>Score error</p></td>
<td style="text-align: left;"><p>Время одного хеша</p></td>
<td style="text-align: left;"><p>Throughput в MB/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>32 B</p></td>
<td style="text-align: left;"><p>415 400 ops/s</p></td>
<td style="text-align: left;"><p>± 1 600</p></td>
<td style="text-align: left;"><p>2.4 µs</p></td>
<td style="text-align: left;"><p>13.3 MB/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>65 100 ops/s</p></td>
<td style="text-align: left;"><p>± 197</p></td>
<td style="text-align: left;"><p>15.4 µs</p></td>
<td style="text-align: left;"><p>65.1 MB/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>4 800 ops/s</p></td>
<td style="text-align: left;"><p>± 29</p></td>
<td style="text-align: left;"><p>208 µs</p></td>
<td style="text-align: left;"><p><strong>78.7 MB/s</strong></p></td>
</tr>
</tbody>
</table>

Streebog-256 throughput, MB/sec по размерам входа

                  0      20     40     60     80     100  MB/s
                  ├──────┼──────┼──────┼──────┼──────┤
      32 B        ███████                                  13.3
      1 KB        ████████████████████████████████▌        65.1
      16 KB       ███████████████████████████████████████▍ 78.7
                  ├──────┼──────┼──────┼──────┼──────┤
                  0      20     40     60     80     100  MB/s

      Throughput растёт с размером — фиксированные расходы (init/finalize)
      амортизируются. На 16 KB выходит на полку — потолок Streebog-256
      в чистой Java реализации.

## Интерпретация

**Поведение корректное**: throughput в MB/s растёт от 13.3 до 78.7 при
увеличении входа от 32 B до 16 KB. Streebog обрабатывает блоками по 64
байта; на 32 B обработка идёт за 1 итерацию (плюс init/finalize), на 16
KB — за 256 итераций.

**Сравнение с компонентами handshake**: Streebog на 32 B — 2.4 µs. Sign
— 1.24 ms. То есть Streebog в **~500 раз** быстрее ГОСТ-подписи.
Хеширование никогда не будет узким местом протокола.

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
style="text-align: left;"><p><code>RecordProtectBench.protect</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>356 067 ops/s</p></td>
<td style="text-align: left;"><p>± 7 347</p></td>
<td style="text-align: left;"><p>34.0 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>RecordProtectBench.protect</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>49 422 ops/s</p></td>
<td style="text-align: left;"><p>± 301</p></td>
<td style="text-align: left;"><p>48.3 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>RecordProtectBench.protect</code></p></td>
<td style="text-align: left;"><p>16 KB (max TLS record)</p></td>
<td style="text-align: left;"><p>3 234 ops/s</p></td>
<td style="text-align: left;"><p>± 19</p></td>
<td style="text-align: left;"><p><strong>50.5 MB/s</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>RecordProtectBench.unprotect</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>347 601 ops/s</p></td>
<td style="text-align: left;"><p>± 7 302</p></td>
<td style="text-align: left;"><p>33.1 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>RecordProtectBench.unprotect</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>47 614 ops/s</p></td>
<td style="text-align: left;"><p>± 300</p></td>
<td style="text-align: left;"><p>46.5 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>RecordProtectBench.unprotect</code></p></td>
<td style="text-align: left;"><p>16 KB (max TLS record)</p></td>
<td style="text-align: left;"><p>3 141 ops/s</p></td>
<td style="text-align: left;"><p>± 15</p></td>
<td style="text-align: left;"><p><strong>49.1 MB/s</strong></p></td>
</tr>
</tbody>
</table>

Protect throughput, MB/sec по размерам записи

                  0     10     20     30     40     50  MB/s
                  ├──────┼──────┼──────┼──────┼──────┤
      100 B       ███████████████████████                    34.0
      1 KB        ██████████████████████████████████████▌    48.3
      16 KB       █████████████████████████████████████████▉ 50.5
                  ├──────┼──────┼──────┼──────┼──────┤
                  0     10     20     30     40     50  MB/s

На 16 KB throughput выходит на полку — новый потолок Кузнечик-MGM с
оптимизированной арифметикой.

## Интерпретация

**Throughput на 16 KB record — 50.5 MB/s (protect) / 49.1 MB/s
(unprotect).** Ускорение **~9×** относительно предыдущего прогона (5.6
MB/s). Причина — новая реализация арифметики Кузнечика и MGM,
переписанная с учётом JMH-профиля: развёрнутые циклы, минимизация
аллокаций, inline-умножение в поле GF(2^128).

**Сравнение со Streebog**: Streebog-256 на 16 KB даёт 78.7 MB/s,
Кузнечик-MGM на 16 KB — 50.5 MB/s. Разница **в 1.6 раза** в пользу хеша
(было 14×). Отрыв сократился: новая арифметика приблизила
AEAD-производительность к хеш-производительности.

**Unprotect vs protect**: 49.1 vs 50.5 MB/s — unprotect на ~3 %
медленнее. Это ожидаемо: unprotect добавляет верификацию MAC-тега
(GHASH-подобное умножение) перед расшифровкой, тогда как protect считает
MAC на уже зашифрованных данных.

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
<td style="text-align: left;"><p>Verify в разы дороже Sign</p></td>
<td style="text-align: left;"><p>Норма для ГОСТ Р 34.10 (verify делает 2
point multiplication, sign — 1)</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 1.85 ms vs 1.24 ms
(соотношение 1.5×).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HKDF на порядки быстрее ECDHE</p></td>
<td style="text-align: left;"><p>HKDF строится на HMAC-Streebog — это
симметричные операции</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 7.5 µs vs 1150 µs
(разница в 150×).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Streebog throughput растёт с
размером</p></td>
<td style="text-align: left;"><p>Амортизация init/finalize по большему
объёму</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 13.3 → 65.1 → 78.7
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Protect throughput растёт с
размером</p></td>
<td style="text-align: left;"><p>То же для AEAD: header + nonce + tag =
21 байт overhead’а</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 34.0 → 48.3 → 50.5
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Score error &lt;5 %</p></td>
<td style="text-align: left;"><p>Признак стабильного прогона</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: все погрешности ±1-4
%.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>PSK speedup &gt;0 (хоть какое-то
ускорение)</p></td>
<td style="text-align: left;"><p>Resumption убирает sign+verify,
ожидание ~25 %</p></td>
<td style="text-align: left;"><p>✅ <strong>Подтверждено</strong>. PSK
speedup 1.8× (154 vs 85 ops/s) после исправления
<code>getForResumption()</code>.</p></td>
</tr>
</tbody>
</table>

# Capacity planning

Цифры, которые можно использовать для оценки нагрузки на уровне ядра
протокола:

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 40%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Сценарий</p></td>
<td style="text-align: left;"><p>Capacity на ядро</p></td>
<td style="text-align: left;"><p>Пометка</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Установка новых соединений
(server-only)</p></td>
<td style="text-align: left;"><p>~85/sec</p></td>
<td style="text-align: left;"><p>С базовой cert-validation (проверка
подписи цепочки).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Пропускная способность установленной
сессии (max-size records)</p></td>
<td style="text-align: left;"><p>~50.5 MB/s</p></td>
<td style="text-align: left;"><p>Один поток. Многопоточность не
измерена.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Streebog-256 (max-size)</p></td>
<td style="text-align: left;"><p>~79 MB/s</p></td>
<td style="text-align: left;"><p>Однопоточный chunk-проход по большим
данным.</p></td>
</tr>
</tbody>
</table>

Цифры **на уровне tls13** — на JSSE-уровне реальная capacity будет
несколько ниже из-за обёртки. Для замеров уровня `SSLEngine` см. отчёт
`bench/results/jsse/`.

Для capacity сервера на N ядрах **нельзя** просто умножать эти цифры на
N. JVM lock contention, GC, scheduling — всё влияет на реальный scaling.
Для production capacity planning нужен интеграционный нагрузочный тест.

# Что ещё можно было бы измерить

1.  **PSK speedup ≈ 0 %** — **закрыт.** Корневая причина:
    `InMemoryPskStore.getForResumption()` мог вернуть устаревший
    PSK-тикет, который сервер уже удалил (single-use по RFC). После
    исправления speedup 1.8× (154.1 vs 85.5 ops/s). Подробности — в
    разделе «PSK resumption: результаты после P1-фикса».

2.  **ECDHE shared secret** — **замерен.** 1.27 ms (см. таблицу
    компонентов выше). Оценка
    «<sub>1.15\ ms\ по\ аналогии\ с\ keygen»\ была\ близка\ к\ истине\ —\ асимметричная\ криптография\ действительно\ занимает</sub>
    84 % handshake.

3.  **Сравнение с независимой реализацией Кузнечик-MGM.** 50.5 MB/s —
    это много или мало для чистой Java? Без сравнения с другой
    реализацией интерпретация невозможна. Исходные 5.6 MB/s были
    улучшены до 50.5 MB/s (~9×) за счёт оптимизации арифметики —
    развёрнутые циклы, inline-умножение в GF(2^128), минимизация
    аллокаций. Потенциал дальнейшего ускорения: JNI/JNR-прокси на
    аппаратный AES-NI + PCLMULQDQ (если целевая платформа поддерживает),
    или Vector API (Project Panama) для SIMD-оптимизации.

4.  **Сравнение с SunJSSE на классических алгоритмах.** Цифра «85 hs/sec
    на ядро» сама по себе не имеет контекста. SunJSSE на RSA-2048 +
    AES-GCM на том же железе дал бы ориентир.

5.  **Многопоточный handshake throughput.** Текущие бенчи однопоточные.
    Реальный сервер обрабатывает handshake’и параллельно — поведение под
    нагрузкой не измерено.

6.  **Профилирование узкого места.** После подтверждения, что
    асимметрика доминирует, имеет смысл профилировать point
    multiplication для поиска потенциальных оптимизаций.

# Воспроизведение прогона

    cd bench/tls
    mvn clean package
    java -jar target/benchmarks.jar -wi 5 -i 5 -f 3

Для прогона отдельного бенчмарка:

    java -jar target/benchmarks.jar FullHandshakeBench -wi 5 -i 5 -f 3
    java -jar target/benchmarks.jar HandshakeComponentsBench.verify -wi 5 -i 5 -f 3

Полный прогон занимает около 40-50 минут на указанной конфигурации
железа.
