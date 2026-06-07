# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-05-28</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Методика</p></td>
<td style="text-align: left;"><p><a
href="../../../crypto-gost-tls13/doc/tls-session-stress.adoc">../../../crypto-gost-tls13/doc/tls-session-stress.adoc</a></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JDK</p></td>
<td style="text-align: left;"><p>OpenJDK 25.0.3
(Red_Hat-25.0.3.0.9-alt1)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Железо</p></td>
<td style="text-align: left;"><p>Intel Core Ultra 9 285H (Arrow Lake),
16 ядер / 16 потоков, 30 GiB RAM</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>ОС</p></td>
<td style="text-align: left;"><p>Alt Linux p11</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Команда запуска</p></td>
<td
style="text-align: left;"><p><code>make test-stress-tlssession</code>
(однопоточный throughput)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Вариант</p></td>
<td style="text-align: left;"><p>TlsSessionStreamTest — непрерывная
запись 16383-байтовых блоков, без ожидания echo (<a
href="../../../crypto-gost-tls13/doc/tls-session-stress.adoc#что-измеряется">подробнее</a>)</p></td>
</tr>
</tbody>
</table>

# Результат

    [RESULT] Valid runs: 5 (of 5)
    [RESULT] Min: 46.4 MB/s, Max: 48.0 MB/s, Median: 47.4 MB/s

**Valid runs:** 5 из 5 — все прогоны пригодны (отбраковки не было).

**Медиана:** **47.4 MB/s** — устойчивая оценка пропускной способности.

**Разброс:** 46.4–48.0 MB/s (~3 %) — стабильно, признаки флуктуаций
системы отсутствуют.

# Сравнение с эталоном

JMH-микробенчмарк `TlsRecord.protect` (16 KB records) показывает ~50.8
MB/s ([прогон 2026-05-25](результаты-jmh-tls-2026-05-25.adoc)).

Отклонение медианы стресс-теста от JMH-эталона:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Источник</p></td>
<td style="text-align: left;"><p>Throughput</p></td>
<td style="text-align: left;"><p>Δ от JMH</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JMH record protect 16 KB</p></td>
<td style="text-align: left;"><p>50.8 MB/s</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TlsSessionStreamTest (медиана)</p></td>
<td style="text-align: left;"><p>47.4 MB/s</p></td>
<td style="text-align: left;"><p>–6.7 %</p></td>
</tr>
</tbody>
</table>

Отклонение –6.7 % — в пределах ожиданий. Накладные расходы
TlsSession+SocketTlsTransport (handshake, record framing, TCP стэк)
добавляют ~7 % относительно JMH-микробенчмарка, меряющего только
protect().

Сравнение ориентировочное — JMH меряет только шифрование одного record,
без TCP, без TlsSession, без handshake.

# Вывод

1.  Пропускная способность TlsSession: **~47 MB/s** (однопоточный поток,
    16383-байтовые блоки, Kuznyechik-MGM-Streebog-256).

2.  Результат стабилен относительно JMH-эталона.

3.  Двусторонний обмен (full-duplex) будет ниже — методика измеряет
    только одно направление (верхняя оценка).
