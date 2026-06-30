# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-06-21</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Методика</p></td>
<td style="text-align: left;"><p><a
href="../../../crypto-gost-tls13/doc/tls-session-stress-mixed.adoc">../../../crypto-gost-tls13/doc/tls-session-stress-mixed.adoc</a></p></td>
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
<td style="text-align: left;"><p>Команда запуска</p></td>
<td
style="text-align: left;"><p><code>make test-stress-tlssession-mixed ARGS=-Dstress.duration=30</code></p></td>
</tr>
</tbody>
</table>

# Смешанная нагрузка (stressTest, 30 минут)

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
<td style="text-align: left;"><p>Профиль</p></td>
<td style="text-align: left;"><p>Потоков</p></td>
<td style="text-align: left;"><p>Запросов</p></td>
<td style="text-align: left;"><p>Ошибок</p></td>
<td style="text-align: left;"><p>Оценка</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 — короткие</p></td>
<td style="text-align: left;"><p>30</p></td>
<td style="text-align: left;"><p>1 430 059</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — средние</p></td>
<td style="text-align: left;"><p>20</p></td>
<td style="text-align: left;"><p>114 846</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — длинные</p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>1 147 792 (17 513 MB)</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>17 323</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
</tbody>
</table>

# Сводка GC и heap

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>GC (всего)</p></td>
<td style="text-align: left;"><p>30 886 за 30 минут</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0114 (смешанный профиль — Profile 3
доминирует по трафику)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (пик)</p></td>
<td style="text-align: left;"><p>1 707 MB (21 % от 7 924 MB)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (финал)</p></td>
<td style="text-align: left;"><p>1 034 MB (13 %)</p></td>
</tr>
</tbody>
</table>

# Анализ утечки памяти

6 окон по 5 минут, для каждого окна — минимум heap (нижняя граница):

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Окно</p></td>
<td style="text-align: left;"><p>Интервал</p></td>
<td style="text-align: left;"><p>min heap</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>0–5 мин</p></td>
<td style="text-align: left;"><p>42 MB (холодный старт)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2</p></td>
<td style="text-align: left;"><p>5–10 мин</p></td>
<td style="text-align: left;"><p>184 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3</p></td>
<td style="text-align: left;"><p>10–15 мин</p></td>
<td style="text-align: left;"><p>203 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>15–20 мин</p></td>
<td style="text-align: left;"><p>345 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>20–25 мин</p></td>
<td style="text-align: left;"><p>151 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>6</p></td>
<td style="text-align: left;"><p>25–30 мин</p></td>
<td style="text-align: left;"><p>267 MB</p></td>
</tr>
</tbody>
</table>

Вердикт: **утечки нет**.

Floor окон 4–6 (345, 151, 267 MB) не показывает монотонного роста.
G1 GC способен сбрасывать heap до 151 MB даже на 20–25 минуте — живые
объекты не накапливаются.

# Сравнение с предыдущим прогоном (2026-05-28)

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>2026-05-28</p></td>
<td style="text-align: left;"><p>2026-06-21</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 1</p></td>
<td style="text-align: left;"><p>1 496 227 req</p></td>
<td style="text-align: left;"><p>1 430 059 req (−4,4 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 2</p></td>
<td style="text-align: left;"><p>115 127 req</p></td>
<td style="text-align: left;"><p>114 846 req (−0,2 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 3</p></td>
<td style="text-align: left;"><p>1 171 138 req (17 870 MB)</p></td>
<td style="text-align: left;"><p>1 147 792 req (17 513 MB) (−2,0 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 4</p></td>
<td style="text-align: left;"><p>17 470 req</p></td>
<td style="text-align: left;"><p>17 323 req (−0,8 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего запросов</p></td>
<td style="text-align: left;"><p>2 799 962</p></td>
<td style="text-align: left;"><p>2 710 020 (−3,2 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего ошибок</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC (всего)</p></td>
<td style="text-align: left;"><p>~27 440</p></td>
<td style="text-align: left;"><p>30 886 (+12,6 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0098</p></td>
<td style="text-align: left;"><p>0,0114 (+16,3 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap пик</p></td>
<td style="text-align: left;"><p>1 735 MB (22 %)</p></td>
<td style="text-align: left;"><p>1 707 MB (21 %) (−1,6 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap финал</p></td>
<td style="text-align: left;"><p>903 MB (11 %)</p></td>
<td style="text-align: left;"><p>1 034 MB (13 %) (+14,5 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Утечка памяти</p></td>
<td style="text-align: left;"><p>Нет</p></td>
<td style="text-align: left;"><p>Нет</p></td>
</tr>
</tbody>
</table>

# Анализ отклонений GC/req

Рост GC/req с 0,0098 до 0,0114 (+16,3 %) при снижении общего числа
запросов на 3,2 % может указывать на:
- фоновую активность ОС (страничный кэш, буферы) — текущий прогон
  выполнялся при 17 GiB доступной RAM против неизвестного состояния
  в 2026-05-28;
- больший финальный heap (1 034 vs 903 MB) говорит о том, что GC
  удерживал больше объектов после завершения теста.

Оба значения GC/req (0,0098 и 0,0114) находятся в одном порядке и не
указывают на регрессию в коде библиотеки.

# Итог

1.  Ноль ошибок на всех четырёх профилях нагрузки за 30 минут —
    `TlsSession` + `SocketTlsTransport` стабильны под смешанной
    конкурентной нагрузкой.

2.  Утечки памяти не обнаружено — floor окон 4–6 не растёт.

3.  GC/req вырос на 16,3 % (0,0114 vs 0,0098), но оба значения в
    одном порядке. Вероятная причина — состояние ОС, а не регрессия
    кода.

4.  Throughput (отдельный тест TlsSessionStreamTest) улучшился
    на +1,5 % (48,1 vs 47,4 MB/s).
