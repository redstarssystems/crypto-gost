# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-06-27</p></td>
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
<td style="text-align: left;"><p>Версия библиотеки</p></td>
<td style="text-align: left;"><p>v0.5.6-48-g3162a4a</p></td>
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
<td style="text-align: left;"><p>1 551 082</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — средние</p></td>
<td style="text-align: left;"><p>20</p></td>
<td style="text-align: left;"><p>115 357</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — длинные</p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>1 199 119 (18 297 MB)</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>17 459</p></td>
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
<td style="text-align: left;"><p>32 082 за 30 минут</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0111 (смешанный профиль — Profile 3
доминирует по трафику)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (пик)</p></td>
<td style="text-align: left;"><p>1 762 MB (22 % от 7 924 MB)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (финал)</p></td>
<td style="text-align: left;"><p>638 MB (8 %)</p></td>
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
<td style="text-align: left;"><p>175 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3</p></td>
<td style="text-align: left;"><p>10–15 мин</p></td>
<td style="text-align: left;"><p>409 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>15–20 мин</p></td>
<td style="text-align: left;"><p>275 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>20–25 мин</p></td>
<td style="text-align: left;"><p>309 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>6</p></td>
<td style="text-align: left;"><p>25–30 мин</p></td>
<td style="text-align: left;"><p>307 MB</p></td>
</tr>
</tbody>
</table>

Вердикт: **утечки нет**.

Floor окон 4–6 (275, 309, 307 MB) не показывает монотонного роста.
G1 GC способен сбрасывать heap до 175 MB даже на 5–10 минуте — живые
объекты не накапливаются.

# Сравнение с предыдущим прогоном (2026-06-21)

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>2026-06-21</p></td>
<td style="text-align: left;"><p>2026-06-27</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 1</p></td>
<td style="text-align: left;"><p>1 430 059 req</p></td>
<td style="text-align: left;"><p>1 551 082 req (+8,5 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 2</p></td>
<td style="text-align: left;"><p>114 846 req</p></td>
<td style="text-align: left;"><p>115 357 req (+0,4 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 3</p></td>
<td style="text-align: left;"><p>1 147 792 req (17 513 MB)</p></td>
<td style="text-align: left;"><p>1 199 119 req (18 297 MB) (+4,5 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 4</p></td>
<td style="text-align: left;"><p>17 323 req</p></td>
<td style="text-align: left;"><p>17 459 req (+0,8 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего запросов</p></td>
<td style="text-align: left;"><p>2 710 020</p></td>
<td style="text-align: left;"><p>2 883 017 (+6,4 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего ошибок</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC (всего)</p></td>
<td style="text-align: left;"><p>30 886</p></td>
<td style="text-align: left;"><p>32 082 (+3,9 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0114</p></td>
<td style="text-align: left;"><p>0,0111 (−2,6 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap пик</p></td>
<td style="text-align: left;"><p>1 707 MB (21 %)</p></td>
<td style="text-align: left;"><p>1 762 MB (22 %) (+3,2 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap финал</p></td>
<td style="text-align: left;"><p>1 034 MB (13 %)</p></td>
<td style="text-align: left;"><p>638 MB (8 %) (−38,3 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Утечка памяти</p></td>
<td style="text-align: left;"><p>Нет</p></td>
<td style="text-align: left;"><p>Нет</p></td>
</tr>
</tbody>
</table>

# Анализ

Рост общего числа запросов на **+6,4 %** (+172 997 запросов) при
снижении GC/req на **−2,6 %** — положительная динамика. Финальный heap
снизился на 38 % (638 vs 1 034 MB) — G1 GC эффективнее сбрасывает
память в текущем прогоне.

Рост абсолютного GC (32 082 vs 30 886, +3,9 %) компенсирован ростом
числа запросов, поэтому GC/req снизился. Причина — 6,4 % больше запросов
требуют пропорционально больше GC-циклов, но эффективность на запрос
не ухудшилась.

# Итог

1.  Ноль ошибок на всех четырёх профилях нагрузки за 30 минут —
    `TlsSession` + `SocketTlsTransport` стабильны под смешанной
    конкурентной нагрузкой.

2.  Утечки памяти не обнаружено — floor окон 4–6 не растёт.

3.  GC/req снизился на 2,6 % (0,0111 vs 0,0114) — улучшение при
    росте общего числа запросов на 6,4 %.

4.  Throughput (отдельный тест TlsSessionStreamTest) стабилен:
    48,0 vs 48,1 MB/s (−0,2 %).
