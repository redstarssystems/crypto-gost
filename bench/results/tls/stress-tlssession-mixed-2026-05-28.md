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

Перед прогоном применены sysctl:
`net.ipv4.ip_local_port_range="1024 65535"`, `net.ipv4.tcp_tw_reuse=1`,
CPU governor `performance`.

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
<td style="text-align: left;"><p>1 496 227</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>2 — средние</p></td>
<td style="text-align: left;"><p>20</p></td>
<td style="text-align: left;"><p>115 127</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3 — длинные</p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>1 171 138 (17 870 MB)</p></td>
<td style="text-align: left;"><p>0</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4 — обрывы</p></td>
<td style="text-align: left;"><p>10</p></td>
<td style="text-align: left;"><p>17 470</p></td>
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
<td style="text-align: left;"><p>~27 440 за 30 минут</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>GC/req</p></td>
<td style="text-align: left;"><p>0.0098 (смешанный профиль — Profile 3
доминирует по трафику)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (пик)</p></td>
<td style="text-align: left;"><p>~1 735 MB (22 % от 7 924 MB)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Heap (финал)</p></td>
<td style="text-align: left;"><p>903 MB (11 %)</p></td>
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
<td style="text-align: left;"><p>633 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>3</p></td>
<td style="text-align: left;"><p>10–15 мин</p></td>
<td style="text-align: left;"><p>170 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>4</p></td>
<td style="text-align: left;"><p>15–20 мин</p></td>
<td style="text-align: left;"><p>382 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>20–25 мин</p></td>
<td style="text-align: left;"><p>170 MB</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>6</p></td>
<td style="text-align: left;"><p>25–30 мин</p></td>
<td style="text-align: left;"><p>313 MB</p></td>
</tr>
</tbody>
</table>

Вердикт: **утечки нет**.

Окна 4–6 не показывают монотонного роста. G1 GC способен сбрасывать heap
до 170 MB даже на 25-й минуте — это означает, что живые объекты не
накапливаются. Колебания нижней границы (170–382 MB) — нормальная работа
G1 GC, адаптирующего пороги old-gen под смешанную нагрузку.

Тридцать минут исключают быстрое и среднее накопление. Очень медленная
утечка (масштаб часов и суток) этим тестом не выявляется.

# Предел по числу соединений (maxConcurrentSessions)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Максимум одновременных</p></td>
<td style="text-align: left;"><p>~8 150 (остановка при 85 %
heap)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Память на соединение</p></td>
<td style="text-align: left;"><p>~434 KB (черновая оценка, не для
сайзинга)</p></td>
</tr>
</tbody>
</table>

Проверка останавливается при достижении 85 % от `maxMemory()`. Замер
памяти на соединение выполняется с форсированной сборкой мусора
(System.gc() с верификацией стабилизации &lt; 2 %). Результат — верхняя
оценка, включающая служебное хозяйство среды исполнения.

# Итог

1.  Ноль ошибок на всех четырёх профилях нагрузки за 30 минут —
    `TlsSession` + `SocketTlsTransport` стабильны под смешанной
    конкурентной нагрузкой, включая аварийные обрывы.

2.  Утечки памяти не обнаружено — нижняя граница heap во второй половине
    теста не растёт, G1 GC удерживает сборку под контролем.

3.  Предел одновременных соединений: ~8 150 (ограничение heap, не
    протокола).

4.  Отношение GC/req = 0.0098 — нагрузка на сборщик равномерна, без
    аномалий.
