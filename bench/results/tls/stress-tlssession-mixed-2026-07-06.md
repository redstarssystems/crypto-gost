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
<td style="text-align: left;"><p>v0.6.1-47-gf47401c</p></td>
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
<td style="text-align: left;"><p>1 946 924</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — средние</p></td>
<td style="text-align: left;"><p>20</p></td>
<td style="text-align: left;"><p>116 349</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — длинные</p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>1 403 967 (21 422 MB)</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>17 538</p></td>
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
<td style="text-align: left;"><p>28 771 за 30 минут</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0083 (смешанный профиль — Profile 3
доминирует по трафику)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (пик)</p></td>
<td style="text-align: left;"><p>2 263 MB (28 % от 7 924 MB)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (финал)</p></td>
<td style="text-align: left;"><p>261 MB (3 %)</p></td>
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
<td style="text-align: left;"><p>719 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3</p></td>
<td style="text-align: left;"><p>10–15 мин</p></td>
<td style="text-align: left;"><p>338 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>15–20 мин</p></td>
<td style="text-align: left;"><p>160 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>20–25 мин</p></td>
<td style="text-align: left;"><p>326 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>6</p></td>
<td style="text-align: left;"><p>25–30 мин</p></td>
<td style="text-align: left;"><p>261 MB</p></td>
</tr>
</tbody>
</table>

Вердикт: **утечки нет**.

Floor окон 4–6 (160, 326, 261 MB) не показывает монотонного роста. G1 GC
способен сбрасывать heap до 160 MB даже на 15–20 минуте — живые объекты
не накапливаются.

# Сравнение с предыдущим прогоном (2026-06-27)

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Метрика</p></td>
<td style="text-align: left;"><p>2026-06-27</p></td>
<td style="text-align: left;"><p>2026-07-06</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 1</p></td>
<td style="text-align: left;"><p>1 551 082 req</p></td>
<td style="text-align: left;"><p>1 946 924 req (+25,5 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 2</p></td>
<td style="text-align: left;"><p>115 357 req</p></td>
<td style="text-align: left;"><p>116 349 req (+0,9 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 3</p></td>
<td style="text-align: left;"><p>1 199 119 req (18 297 MB)</p></td>
<td style="text-align: left;"><p>1 403 967 req (21 422 MB) (+17,1
%)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Профиль 4</p></td>
<td style="text-align: left;"><p>17 459 req</p></td>
<td style="text-align: left;"><p>17 538 req (+0,5 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего запросов</p></td>
<td style="text-align: left;"><p>2 883 017</p></td>
<td style="text-align: left;"><p>3 484 778 (+20,9 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Всего ошибок</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC (всего)</p></td>
<td style="text-align: left;"><p>32 082</p></td>
<td style="text-align: left;"><p>28 771 (−10,3 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0,0111</p></td>
<td style="text-align: left;"><p>0,0083 (−25,2 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap пик</p></td>
<td style="text-align: left;"><p>1 762 MB (22 %)</p></td>
<td style="text-align: left;"><p>2 263 MB (28 %) (+28,4 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap финал</p></td>
<td style="text-align: left;"><p>638 MB (8 %)</p></td>
<td style="text-align: left;"><p>261 MB (3 %) (−59,1 %)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Утечка памяти</p></td>
<td style="text-align: left;"><p>Нет</p></td>
<td style="text-align: left;"><p>Нет</p></td>
</tr>
</tbody>
</table>

# Анализ

Рост общего числа запросов на **+20,9 %** (+601 761 запрос) при снижении
абсолютного GC на **−10,3 %** и GC/req на **−25,2 %** — положительная
динамика. G1 GC стал эффективнее: меньше циклов сборки на единицу
трафика.

Рост пикового heap (+28,4 %, 1 762 → 2 263 MB) объясняется более высокой
утилизацией за счёт роста throughput по профилю 3 (21 422 vs 18 297 MB
трафика, +17,1 %). При этом финальный heap после завершения теста
**ниже** (261 vs 638 MB, −59,1 %) — GC эффективно возвращает память.

# Итог

1.  Ноль ошибок на всех четырёх профилях нагрузки за 30 минут —
    `TlsSession` + `SocketTlsTransport` стабильны под смешанной
    конкурентной нагрузкой.

2.  Утечки памяти не обнаружено — floor окон 4–6 не растёт.

3.  GC/req снизился на 25,2 % (0,0083 vs 0,0111) — значительное
    улучшение при росте общего числа запросов на 20,9 %.

4.  Throughput (отдельный тест TlsSessionStreamTest) стабилен: 47,6 vs
    48,0 MB/s (−0,8 %).
