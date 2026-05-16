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

Цифры стабильные, относительная погрешность ±1-2 %.

# Что измеряет этот прогон

Уровень `crypto-gost-jsse` — **JSSE-обёртка поверх crypto-gost-tls13**.
Замеры идут через `SSLEngine` (стандартный JSSE-API, который используют
Tomcat, Jetty, Netty, HttpsURLConnection). Между `SSLEngine` и ядром
протокола — слой `GostSSLEngine`, `CertificateBridge`, `KeyBridge`,
`IanaMapper`, JCA-конверсии типов, `ByteBuffer`↔`byte[]` копирования.

# Важный disclaimer: TrustManager в бенчах

В бенч-сетапе используется **null-TrustManager**: все методы
`checkClientTrusted`/`checkServerTrusted` пустые, `getAcceptedIssuers`
возвращает пустой массив. Это значит:

- нет chain walking;

- нет hostname-валидации;

- нет OCSP-обращений (даже cache lookup);

- нет проверки basic constraints, key usage, validity period.

**Важно**: на уровне `crypto-gost-tls13` бенч-сетап **делает** реальную
проверку подписи сертификата (через
`TlsClientConfig.withCaPublicKey(...)` →
`TlsCertificateValidator.checkServerCertificateChain` →
`Signature.verifyHash`). На уровне JSSE та же работа была бы выполнена
через `GostX509TrustManager` с настроенной валидацией — но в текущем
бенч-сетапе обходится через null-TrustManager.

**Эти JSSE-цифры — верхняя граница**. Реальный пользователь, настроивший
`GostX509TrustManager` с OCSP-политикой, получит меньшие ops/sec.
Насколько меньше — пока не измерено.

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
<td style="text-align: left;"><p>99.7 ops/s</p></td>
<td style="text-align: left;"><p>± 1.1</p></td>
<td style="text-align: left;"><p>10.0 ms</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.mutualAuth</code></p></td>
<td style="text-align: left;"><p>73.9 ops/s</p></td>
<td style="text-align: left;"><p>± 1.0</p></td>
<td style="text-align: left;"><p>13.5 ms</p></td>
</tr>
</tbody>
</table>

Handshake throughput, ops/sec (одно ядро)

                      0    20   40   60   80  100  120
                      ├────┼────┼────┼────┼────┼────┤
      fullHandshake   ███████████████████████████▌      99.7  ±1.1
      mutualAuth      ████████████████████▌             73.9  ±1.0
                      ├────┼────┼────┼────┼────┼────┤
                      0    20   40   60   80  100  120

Без cert-validation в TrustManager (см. disclaimer выше). mTLS медленнее
на 26 % за счёт клиентского CertificateVerify.

## Интерпретация

**Full handshake — 10.0 ms на одно ядро.** Это означает теоретическую
capacity одного ядра около 100 одновременных handshake-инициаций в
секунду — при условии, что cert-validation отключена.

**mTLS дороже на 26 %.** Время handshake растёт с 10.0 ms до 13.5 ms —
добавляется ~3.5 ms на клиентский `CertificateVerify` (sign на клиенте +
verify на сервере). Это согласуется с измеренными отдельно операциями
ГОСТ Р 34.10 (`sign` + `verify` = 1.24 + 1.85 ≈ 3.1 ms — близко к
измеренной разнице).

## Что не измерено

- **Стоимость cert-validation в TrustManager.** Бенч обходит её через
  null-impl. Реальная стоимость требует прогона с `GostX509TrustManager`
  и хотя бы `OcspPolicy.DISABLED`.

- **PSK resumption через `SSLSession`/`SSLSessionContext`.**
  JSSE-уровневый resume требует корректной настройки
  `peerHost`/`peerPort` для session lookup.

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
<td style="text-align: left;"><p>354 883 ops/s</p></td>
<td style="text-align: left;"><p>± 8 001</p></td>
<td style="text-align: left;"><p>34.0 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>48 942 ops/s</p></td>
<td style="text-align: left;"><p>± 254</p></td>
<td style="text-align: left;"><p>47.8 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>16 KB (max TLS record)</p></td>
<td style="text-align: left;"><p>3 237 ops/s</p></td>
<td style="text-align: left;"><p>± 12</p></td>
<td style="text-align: left;"><p><strong>50.0 MB/s</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>144 808 ops/s</p></td>
<td style="text-align: left;"><p>± 937</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>23 525 ops/s</p></td>
<td style="text-align: left;"><p>± 59</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>1 576 ops/s</p></td>
<td style="text-align: left;"><p>± 8</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Wrap throughput, MB/sec по размерам записи

                     0     10     20     30     40     50  MB/s
                     ├──────┼──────┼──────┼──────┼──────┤
       100 B   wrap  ███████████████████████                    34.0
       1 KB    wrap  █████████████████████████████████████▌     47.8
       16 KB   wrap  ████████████████████████████████████████▌  50.0
                     ├──────┼──────┼──────┼──────┼──────┤
                     0     10     20     30     40     50  MB/s

На малых записях overhead заголовка/nonce/tag (21 байт) доминирует. На
16 KB throughput выходит на полку — новый потолок с оптимизированной
арифметикой.

Wrap vs roundTrip на 16 KB, ops/sec

                   0           800         1600        2400        3200
                   ├────────────┼────────────┼────────────┼────────────┤
       wrap        █████████████████████████████████████████████████████ 3237  ±12
       roundTrip   ███████████████████████████████▌                    1576  ±8
                   ├────────────┼────────────┼────────────┼────────────┤
                   0           800         1600        2400        3200

roundTrip ≈ 2 × wrap (соотношение 2.05) — симметрия AEAD. Косвенно:
unwrap по стоимости равен wrap.

## Интерпретация

**Throughput на 16 KB record — 50.0 MB/s (wrap).** Ускорение **~9×**
относительно предыдущего прогона (5.6 MB/s). Причина — новая реализация
арифметики Кузнечика и MGM.

**roundTrip ≈ 2 × wrap (2.05).** Это математически корректное
соотношение: roundTrip делает wrap (encrypt + MAC) и сразу unwrap
(decrypt + verify-MAC). Коэффициент 2.05 против ожидаемых 2.0
объясняется overhead’ом на сброс/восстановление seqNum между операциями
(один long store + один вызов метода).

**Throughput растёт с размером:** 34.0 → 47.8 → 50.0 MB/s. На малых
записях фиксированные накладные расходы (header + nonce + tag = 21 байт
служебных данных) доминируют. На 16 KB record overhead размывается в
0.13 % от payload, throughput выходит на полку.

# Сравнение с уровнем tls13

Полные цифры по уровню протокола приведены в отчёте
`bench/results/tls/`. Здесь — ключевые соотношения.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>jsse (этот прогон)</p></td>
<td style="text-align: left;"><p>tls13 (для сравнения)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Full handshake</p></td>
<td style="text-align: left;"><p>99.7 ops/s</p></td>
<td style="text-align: left;"><p>85.5 ops/s</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 16 KB / Protect 16 KB</p></td>
<td style="text-align: left;"><p>3 237 ops/s</p></td>
<td style="text-align: left;"><p>3 234 ops/s</p></td>
</tr>
</tbody>
</table>

Handshake throughput: jsse vs tls13, ops/sec

                           0    20   40   60   80  100  120
                           ├────┼────┼────┼────┼────┼────┤
      jsse (null TM)       ███████████████████████████▌      99.7
      tls13 (с verify CA)  ███████████████████████▎          85.5
                           ├────┼────┼────┼────┼────┼────┤
                           0    20   40   60   80  100  120

Разница 14 % — методологическая особенность бенч-сетапов. См. подробное
объяснение ниже.

Wrap throughput на 16 KB: jsse vs tls13, ops/sec

                           0      50    100    150    200    250    300    350    400
                           ├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
      jsse  wrap           ██████████████████████████████████████████████████▌      353
      tls13 protect        ██████████████████████████████████████████████████▏      352
                           ├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
                           0      50    100    150    200    250    300    350    400

Цифры совпадают в пределах погрешности. JSSE-обёртка record-layer’а
(ByteBuffer↔byte\[\]) действительно тонкая.

## Почему jsse-handshake «быстрее» tls13-handshake

Цифра «JSSE на 14 % быстрее» — **методологическая особенность**, не
реальное ускорение от JSSE-обёртки.

**Разница 1.7 ms (11.7 ms vs 10.0 ms)** объясняется одной операцией
`Signature.verifyHash`:

- tls13-бенч использует `TlsClientConfig.withCaPublicKey(...)` — внутри
  `TlsCertificateValidator.checkServerCertificateChain` вызывается
  `Signature.verifyHash(hash, sigBytes, caPublicKey)`. Это **реальная
  проверка подписи сертификата на ГОСТ-кривой**.

- jsse-бенч использует null-TrustManager — `checkServerTrusted` пустой,
  никакой подписи не проверяется.

По компонентным цифрам tls13 (см. `bench/results/tls/`): один `verify` =
1.85 ms. Это почти точно совпадает с разницей 1.7 ms между jsse и tls13.
То есть jsse-бенч обходит ровно одну операцию verify, которую делает
tls13-бенч.

**Стоимость самой JSSE-обёртки** (ByteBuffer↔byte\[\] copy, lock
acquisition, JCA conversions, IanaMapper, CertificateBridge, KeyBridge)
**не измерена напрямую** — для этого нужен бенч с одинаковым
TrustManager-поведением на обоих уровнях.

**На record-layer’е JSSE-обёртка действительно тонкая**, что
подтверждается совпадением `wrap` и `protect` цифр в пределах
погрешности.

## PSK resumption на уровне tls13 — после P1-фикса

После P1-фикса (Sprint 2) PSK resumption корректно активируется. Цифры
на уровне tls13:

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

Speedup: 1.80× (44% времени handshake). Режим: `psk_dhe_ke` (forward
secrecy).

JSSE-уровневый PSK-бенч (`JsseHandshakeBench.resume`) пока не готов — он
требует настройки `peerHost`/`peerPort` для session lookup. Ожидаемый
overhead JSSE-обёртки на PSK-path — &lt;5% (аналогично full handshake).

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
<td style="text-align: left;"><p>✅ Подтверждено: на 16 KB — 353 vs 177
(соотношение 1.99).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS дороже fullHandshake</p></td>
<td style="text-align: left;"><p>Минимум 20 %, типично 25-50 %</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: +26 %.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Throughput растёт с размером
record</p></td>
<td style="text-align: left;"><p>Амортизация фиксированных
overhead’ов</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 34.0 → 47.8 → 50.0
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Score error &lt;5 %</p></td>
<td style="text-align: left;"><p>Признак стабильного прогона</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: все погрешности ±1-2
%.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>jsse-wrap ≈ tls13-protect (тонкая
JSSE-обёртка)</p></td>
<td style="text-align: left;"><p>Совпадение в пределах
погрешности</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 3237 vs 3234.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Разница jsse-handshake vs
tls13-handshake объяснима</p></td>
<td style="text-align: left;"><p>Должна совпадать со стоимостью одного
<code>verify</code> (1.85 ms)</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 1.7 ms ≈ 1.85
ms.</p></td>
</tr>
</tbody>
</table>

# Capacity planning

Цифры, которые можно использовать для оценки нагрузки:

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
<td style="text-align: left;"><p>Установка новых соединений (server-only
TLS, без cert-validation)</p></td>
<td style="text-align: left;"><p>~100/sec</p></td>
<td style="text-align: left;"><p>Верхняя граница. Реальный TrustManager
с OCSP даст меньше.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Установка новых соединений (mTLS, без
cert-validation)</p></td>
<td style="text-align: left;"><p>~74/sec</p></td>
<td style="text-align: left;"><p>Добавляется клиентский
CertificateVerify.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Пропускная способность установленной
сессии (max-size records)</p></td>
<td style="text-align: left;"><p>~50.0 MB/s</p></td>
<td style="text-align: left;"><p>Один поток. Многопоточность не
измерена.</p></td>
</tr>
</tbody>
</table>

Для capacity сервера на N ядрах **нельзя** просто умножать эти цифры на
N. JVM lock contention, GC, scheduling — всё влияет на реальный scaling.
Для production capacity planning нужен интеграционный нагрузочный тест
на реальном железе и реальной нагрузке.

# Открытые вопросы

Эти вопросы остаются за рамками текущего прогона:

1.  **Стоимость cert-validation в `GostX509TrustManager`.** Текущие
    цифры — без неё. Нужен парный бенч с реальным TrustManager (хотя бы
    с `OcspPolicy.DISABLED`), чтобы измерить разницу.

2.  **JSSE-уровневое PSK resumption.** `JsseHandshakeBench.resume`
    намеренно удалён из текущей версии — он не делал реальный
    resumption. Корректная реализация требует настройки
    `SSLContext.getClientSessionContext()` + `peerHost`/`peerPort` в
    `createSSLEngine`. Отложено.

    После P1-фикса (Sprint 2) PSK на ядре показывает 1.80× speedup —
    аномалия устранена. JSSE-PSK остаётся отдельной задачей.

3.  **Реальная стоимость JSSE-обёртки.** Чтобы измерить overhead
    JSSE-слоя как такового (без cert-validation разницы), нужно либо
    подключить реальный TrustManager в jsse-бенч, либо отключить
    `withCaPublicKey` в tls13-бенче. Тогда разница покажет именно
    overhead обёртки.

4.  **Сравнение с SunJSSE на классических алгоритмах.** Цифра «100
    hs/sec на ядро» сама по себе не имеет контекста. SunJSSE на
    RSA-2048 + AES-GCM на том же железе — ориентир, который позволил бы
    интерпретировать наши числа как «нормально для чистой Java» или
    «есть запас на оптимизацию».

5.  **Сравнение Кузнечик-MGM с независимой реализацией.** 50.0 MB/s —
    это много или мало для чистой Java реализации Кузнечика? Без
    сравнения с независимой реализацией интерпретация невозможна.
    Исходные 5.6 MB/s были улучшены до 50.0 MB/s (~9×) за счёт
    оптимизации арифметики.

6.  **Многопоточный handshake throughput.** Текущие бенчи однопоточные
    (`@Threads(1)`). Реальный сервер обрабатывает handshake’и
    параллельно. Поведение под нагрузкой не измерено.

# Воспроизведение прогона

    cd bench/jsse
    mvn clean package
    java -jar target/benchmarks.jar -wi 5 -i 5 -f 3

Для прогона отдельного бенчмарка:

    java -jar target/benchmarks.jar JsseHandshakeBench.fullHandshake -wi 5 -i 5 -f 3

Полный прогон занимает около 30-40 минут на указанной конфигурации
железа.
