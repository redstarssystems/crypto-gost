# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-07-06</p></td>
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
<td style="text-align: left;"><p>JVM</p></td>
<td style="text-align: left;"><p><code>-Xmx8g</code>,
<code>-Xms8g</code>, Project Loom (vthreads), G1 GC</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Версия библиотеки</p></td>
<td style="text-align: left;"><p>v0.6.1-47-gf47401c</p></td>
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
    [RESULT] Min: 47,2 MB/s, Max: 47,9 MB/s, Median: 47,6 MB/s

**Valid runs:** 5 из 5 — все прогоны пригодны (отбраковки не было).

**Медиана:** **47,6 MB/s** — устойчивая оценка пропускной способности.

**Разброс:** 47,2–47,9 MB/s (≈1,5 %) — стабильно, признаки флуктуаций
системы отсутствуют.

# Сравнение с предыдущим прогоном (2026-06-27)

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
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>2026-06-27 (v0.5.6)</p></td>
<td style="text-align: left;"><p>2026-07-06 (v0.6.1+)</p></td>
<td style="text-align: left;"><p>Δ</p></td>
<td style="text-align: left;"><p>Характер</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Min</p></td>
<td style="text-align: left;"><p>46,9 MB/s</p></td>
<td style="text-align: left;"><p>47,2 MB/s</p></td>
<td style="text-align: left;"><p>+0,6 %</p></td>
<td style="text-align: left;"><p>↑ естественный разброс</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Max</p></td>
<td style="text-align: left;"><p>48,1 MB/s</p></td>
<td style="text-align: left;"><p>47,9 MB/s</p></td>
<td style="text-align: left;"><p>−0,4 %</p></td>
<td style="text-align: left;"><p>→ стабильно</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Median</p></td>
<td style="text-align: left;"><p>48,0 MB/s</p></td>
<td style="text-align: left;"><p>47,6 MB/s</p></td>
<td style="text-align: left;"><p>−0,8 %</p></td>
<td style="text-align: left;"><p>→ стабильно</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Valid runs</p></td>
<td style="text-align: left;"><p>5/5</p></td>
<td style="text-align: left;"><p>5/5</p></td>
<td style="text-align: left;"><p>=</p></td>
<td style="text-align: left;"><p>без изменений</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Разброс</p></td>
<td style="text-align: left;"><p>2,5 %</p></td>
<td style="text-align: left;"><p>1,5 %</p></td>
<td style="text-align: left;"><p>−1,0 п.п.</p></td>
<td style="text-align: left;"><p>↑ уже</p></td>
</tr>
</tbody>
</table>

# Вывод

1.  Пропускная способность TlsSession: **~48 MB/s** (однопоточный поток,
    16383-байтовые блоки, Kuznyechik-MGM-Streebog-256).

2.  Медиана throughput стабильна — **47,6 MB/s** против 48,0 MB/s (−0,8
    %), в пределах естественного разброса между прогонами. Регресса нет.

3.  Результат стабильный, 5 валидных прогонов из 5.

4.  Изменения безопасности версий 0.6.1 и 0.6.2 (constant-time паддинг,
    затирание ключей, DoS-лимиты) **не повлияли** на горячий путь
    шифрования данных.
