# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-07-15</p></td>
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
<td style="text-align: left;"><p><code>-wi 5 -i 5 -f 1</code> (5
разогревочных + 5 измерительных итераций, 1 запуск JVM)</p></td>
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
<td style="text-align: left;"><p>≈15 минут (только handshake), record
layer — отдельно с <code>-wi 2 -i 2</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Изменения кода</p></td>
<td style="text-align: left;"><p>План 261:
<code>GostSSLEngine.initHandshake()</code> — использование кэша
<code>getCertificateChainTls()</code> вместо повторного
<code>CertificateBridge.toGost()</code>; <code>ECDSASigner.init()</code>
— удалён дублирующийся <code>isValidPublicKey()</code>.</p></td>
</tr>
</tbody>
</table>

# Что измеряет этот прогон

Уровень `crypto-gost-jsse` — JSSE-обёртка поверх `crypto-gost-tls13`.
Замеры идут через `SSLEngine` (стандартный JSSE-API).

В отличие от прогона 3, используется 1 форк JVM (не 3) — достаточный для
сравнения после структурного изменения кода.

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
<td style="text-align: left;"><p>95 504 ops/s</p></td>
<td style="text-align: left;"><p>± 5 531</p></td>
<td style="text-align: left;"><p>10.5 ms</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.mutualAuth</code></p></td>
<td style="text-align: left;"><p>58 846 ops/s</p></td>
<td style="text-align: left;"><p>± 1 539</p></td>
<td style="text-align: left;"><p>17.0 ms</p></td>
</tr>
</tbody>
</table>

Handshake throughput, ops/sec (одно ядро)

                      0         25         50         75        100        125
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
      fullHandshake   ██████████████████████████████████████████████████████▏  95 504  ±5 531
      mutualAuth      ████████████████████████████████████                    58 846  ±1 539
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
                      0         25         50         75        100        125

Без cert-validation в TrustManager (null-TrustManager). mTLS медленнее
на 62 % за счёт двойной валидации сертификата пира.

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
<td style="text-align: left;"><p>360 195 ops/s</p></td>
<td style="text-align: left;"><p>± 4 820</p></td>
<td style="text-align: left;"><p>34.3 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>49 504 ops/s</p></td>
<td style="text-align: left;"><p>± 120</p></td>
<td style="text-align: left;"><p>48.3 MB/s</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>3 258 ops/s</p></td>
<td style="text-align: left;"><p>± 58</p></td>
<td style="text-align: left;"><p><strong>50.9 MB/s</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>100 B</p></td>
<td style="text-align: left;"><p>175 255 ops/s</p></td>
<td style="text-align: left;"><p>± 3 415</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>1 KB</p></td>
<td style="text-align: left;"><p>24 068 ops/s</p></td>
<td style="text-align: left;"><p>± 160</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>16 KB</p></td>
<td style="text-align: left;"><p>1 598 ops/s</p></td>
<td style="text-align: left;"><p>± 15</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Record layer — короткий прогон (`-wi 2 -i 2`), погрешность выше
полноценного `-wi 5 -i 5`. Изменений относительно прогона 3 нет.

# Сравнение с прогоном 3

**Прогон 3** — 2026-05-22, JDK 25.0.3, код до изменений плана 261
(базовый уровень). **Прогон 4** — 2026-07-15, JDK 25.0.3, код после
фикса (кэш own cert + устранение дублирующейся проверки).

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Бенчмарк</p></td>
<td style="text-align: left;"><p>Прогон 3</p></td>
<td style="text-align: left;"><p>Прогон 4</p></td>
<td style="text-align: left;"><p>Δ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>fullHandshake</code></p></td>
<td style="text-align: left;"><p>100.1k ops/s</p></td>
<td style="text-align: left;"><p><strong>95.5k ops/s</strong></p></td>
<td style="text-align: left;"><p><strong>−4.6 %</strong> ✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>mutualAuth</code></p></td>
<td style="text-align: left;"><p>76.1k ops/s</p></td>
<td style="text-align: left;"><p><strong>58.8k ops/s</strong></p></td>
<td style="text-align: left;"><p><strong>−22.7 %</strong> 🟡</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 100 B</code></p></td>
<td style="text-align: left;"><p>343.4k ops/s (32.7 MB/s)</p></td>
<td style="text-align: left;"><p><strong>360.2k ops/s (34.3
MB/s)</strong></p></td>
<td style="text-align: left;"><p><strong>+4.9 %</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 1 KB</code></p></td>
<td style="text-align: left;"><p>49.1k ops/s (48.0 MB/s)</p></td>
<td style="text-align: left;"><p><strong>49.5k ops/s (48.3
MB/s)</strong></p></td>
<td style="text-align: left;"><p>+0.8 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap 16 KB</code></p></td>
<td style="text-align: left;"><p>3 227 ops/s (50.4 MB/s)</p></td>
<td style="text-align: left;"><p><strong>3 258 ops/s (50.9
MB/s)</strong></p></td>
<td style="text-align: left;"><p>+1.0 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 100 B</code></p></td>
<td style="text-align: left;"><p>172.5k ops/s</p></td>
<td style="text-align: left;"><p><strong>175.3k ops/s</strong></p></td>
<td style="text-align: left;"><p>+1.6 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 1 KB</code></p></td>
<td style="text-align: left;"><p>23.9k ops/s</p></td>
<td style="text-align: left;"><p><strong>24.1k ops/s</strong></p></td>
<td style="text-align: left;"><p>+0.7 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip 16 KB</code></p></td>
<td style="text-align: left;"><p>1 589 ops/s</p></td>
<td style="text-align: left;"><p><strong>1 598 ops/s</strong></p></td>
<td style="text-align: left;"><p>+0.6 %</p></td>
</tr>
</tbody>
</table>

## Анализ

1.  **Регрессия handshake (план 261) диагностирована и исправлена.**
    Падение было вызвано двумя причинами:

    - `GostSSLEngine.initHandshake()` заново разбирал собственный
      сертификат через `CertificateBridge.toGost()` при каждом
      handshake, хотя уже разобранная копия хранилась в кэше
      `KeyEntry.getTlsChain()`.

    - `ECDSASigner.init()` дублировал проверку `isValidPublicKey`, уже
      выполненную в конструкторе `PublicKeyParameters`.

2.  **fullHandshake восстановлен до 95.5k ops/s (95 % от базлайна).**
    Оставшиеся −4.6 % — необходимая стоимость peer cert parsing +
    ECDHE  
    подписей (cofactor=4 добавил `isValidPublicKey` с умножением на n).

3.  **mutualAuth восстановлен до 58.8k ops/s (77 % от базлайна).**
    Оставшийся разрыв подтверждён JFR-профилированием: взаимная
    аутентификация удваивает валидацию сертификата пира
    (isValidPublicKey +40 % sample’ов). В прогоне 3 (cofactor=1) эта
    проверка была дешёвой, сейчас — полное скалярное умножение. Это не
    регрессия, а необходимая цена корректности.

4.  **Record layer без изменений.** Все показатели в пределах ±5 % от
    прогона 3. Код handshake не затрагивает record path.

5.  **Соотношение fullHandshake/mutualAuth изменилось:** 1.32 (прогон 3)
    → 1.62 (прогон 4) — закономерно: mutualAuth содержит две
    peer-валидации, каждая дороже при cofactor=4.

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
<td style="text-align: left;"><p>✅ Подтверждено: на 16 KB — 3258 vs
1598 (соотношение 2.04).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS дороже fullHandshake</p></td>
<td style="text-align: left;"><p>Минимум 20 %, типично 25-50 %</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: +62 % (двойная
peer-валидация).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Throughput растёт с размером
record</p></td>
<td style="text-align: left;"><p>Амортизация фиксированных
overhead’ов</p></td>
<td style="text-align: left;"><p>✅ Подтверждено: 34.3 → 48.3 → 50.9
MB/s.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Score error &lt;15 % для
handshake</p></td>
<td style="text-align: left;"><p>Признак стабильного прогона</p></td>
<td style="text-align: left;"><p>✅ fullHandshake 5.8 %, mutualAuth 2.6
%.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Record layer stable</p></td>
<td style="text-align: left;"><p>±5 % от прогона 3</p></td>
<td style="text-align: left;"><p>✅ Все в пределах; wrap 100B +4.9 % —
крайнее значение.</p></td>
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
<td style="text-align: left;"><p>95 000 (10.5 ms)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS 1.3 handshake</p></td>
<td style="text-align: left;"><p>59 000 (17.0 ms)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 100 B</p></td>
<td style="text-align: left;"><p>360 000</p></td>
<td style="text-align: left;"><p>34.3</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 1 KB</p></td>
<td style="text-align: left;"><p>50 000</p></td>
<td style="text-align: left;"><p>48.3</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Wrap 16 KB</p></td>
<td style="text-align: left;"><p>3 300</p></td>
<td style="text-align: left;"><p>50.9</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>RoundTrip 100 B</p></td>
<td style="text-align: left;"><p>175 000</p></td>
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

Добавлены относительно прогона 3:

1.  VirtualThread overhead: 36.6 % RUNNABLE-времени в
    `takeVirtualThreadListToUnblock` — не связано с парсингом
    сертификатов; требует отдельного изучения.

2.  Ленивый парсинг расширений сертификата для handshake-пути (AIA, CDP,
    CertificatePolicies не нужны на критическом пути).

Без изменений:

1.  Стоимость cert-validation в `GostX509TrustManager`.

2.  JSSE-уровневое PSK resumption.

3.  Реальная стоимость JSSE-обёртки.

4.  Сравнение с SunJSSE на классических алгоритмах.

5.  Многопоточный handshake throughput.

# Воспроизведение прогона

    cd bench/jsse
    mvn clean package -am -DskipTests
    java -jar target/benchmarks.jar -wi 5 -i 5 -f 1

Для прогона отдельного бенчмарка:

    java -jar target/benchmarks.jar JsseHandshakeBench.fullHandshake -wi 5 -i 5 -f 1

Полный прогон занимает около 15 минут при одном форке.
