# Метаданные прогона

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 75%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Дата прогона</p></td>
<td style="text-align: left;"><p>2026-11-16</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Код</p></td>
<td style="text-align: left;"><p><code>145c5725</code> (Стрибог на
словах <code>long[8]</code>), рабочее дерево чистое</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JDK</p></td>
<td style="text-align: left;"><p>OpenJDK 25.0.5.3.3</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JMH</p></td>
<td style="text-align: left;"><p>1.37</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Флаги JMH</p></td>
<td
style="text-align: left;"><p><code>-wi 5 -i 5 -f 3 -w 10s -r 10s -jvmArgs -Xmx2g</code>
(5 разогревочных и 5 измерительных итераций по 10 с, 3 запуска
JVM)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Железо</p></td>
<td style="text-align: left;"><p>Intel Core Ultra 9 285H, 16 ядер / 16
потоков, 30 ГиБ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Питание</p></td>
<td style="text-align: left;"><p>от сети; профиль платформы, EPP и
регулятор частоты всех ядер — <code>performance</code>; EPP проверялся
раз в секунду, сбросов не было</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Общее время</p></td>
<td style="text-align: left;"><p>рукопожатия 10 минут, слой записей 30
минут</p></td>
</tr>
</tbody>
</table>

# Что измеряет этот прогон

Уровень `crypto-gost-jsse` — JSSE-обёртка поверх `crypto-gost-tls13`.
Замеры идут через `SSLEngine` (стандартный программный интерфейс JSSE),
проверка сертификата отключена (пустой TrustManager).

Прогон повторяет методику прогона 3 (три запуска JVM) и делается после
двух крупных изменений: арифметики кривой (с 0.7.1) и новой реализации
Стрибога.

# Рукопожатие

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
<td style="text-align: left;"><p>Рукопожатий в секунду</p></td>
<td style="text-align: left;"><p>Погрешность</p></td>
<td style="text-align: left;"><p>Время одной операции</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.fullHandshake</code></p></td>
<td style="text-align: left;"><p>203,4</p></td>
<td style="text-align: left;"><p>± 3,4</p></td>
<td style="text-align: left;"><p>4,92 мс</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseHandshakeBench.mutualAuth</code></p></td>
<td style="text-align: left;"><p>153,0</p></td>
<td style="text-align: left;"><p>± 1,9</p></td>
<td style="text-align: left;"><p>6,54 мс</p></td>
</tr>
</tbody>
</table>

Рукопожатий в секунду (одно ядро)

                      0         50        100        150        200        250
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
      fullHandshake   ████████████████████████████████████████▋               203,4  ±3,4
      mutualAuth      ██████████████████████████████▌                         153,0  ±1,9
                      ├──────────┼──────────┼──────────┼──────────┼──────────┤
                      0         50        100        150        200        250

Рукопожатие с клиентским сертификатом дороже на 33 %: сервер проверяет
подпись клиента в CertificateVerify, клиент подписывает свой.

# Слой записей

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
<td style="text-align: left;"><p>Операций в секунду</p></td>
<td style="text-align: left;"><p>Погрешность</p></td>
<td style="text-align: left;"><p>МБ/с (2²⁰ байт)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>100 Б</p></td>
<td style="text-align: left;"><p>352 924</p></td>
<td style="text-align: left;"><p>± 669</p></td>
<td style="text-align: left;"><p>33,7</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>1 КБ</p></td>
<td style="text-align: left;"><p>47 687</p></td>
<td style="text-align: left;"><p>± 77</p></td>
<td style="text-align: left;"><p>46,6</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.wrap</code></p></td>
<td style="text-align: left;"><p>16 КБ</p></td>
<td style="text-align: left;"><p>3 123</p></td>
<td style="text-align: left;"><p>± 4</p></td>
<td style="text-align: left;"><p><strong>48,8</strong></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>100 Б</p></td>
<td style="text-align: left;"><p>168 309</p></td>
<td style="text-align: left;"><p>± 3 483</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>1 КБ</p></td>
<td style="text-align: left;"><p>23 842</p></td>
<td style="text-align: left;"><p>± 535</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>JsseRecordBench.roundTrip</code></p></td>
<td style="text-align: left;"><p>16 КБ</p></td>
<td style="text-align: left;"><p>1 531</p></td>
<td style="text-align: left;"><p>± 2</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

Шифрование записей (Кузнечик-MGM) хеш не использует, поэтому слой
записей новой реализацией Стрибога не затронут.

# Сравнение с прогоном 4 и с 0.7.1

**Прогон 4** — 2026-07-15, JDK 25.0.3, один запуск JVM. В таблице
рукопожатий прогона 4 единица указана неверно: «95 504 ops/s» и «58 846
ops/s» — это 95,5 и 58,8 рукопожатий в секунду (время операции 10,5 и
17,0 мс в той же таблице).

**0.7.1** — тег `v0.7.1`, измерен 2026-11-08 на этой машине,
`-wi 2 -i 5 -w 3s -r 10s -f 1` для рукопожатий, `-wi 2 -i 3` для
записей. Контроль частоты: `MacBench.hmac256Bc` 16 Б в BouncyCastle —
123 021 (8 ноября) и 123 292 (сейчас), разница 0,2 %.

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
<td style="text-align: left;"><p>Прогон 4</p></td>
<td style="text-align: left;"><p>0.7.1</p></td>
<td style="text-align: left;"><p>Прогон 5</p></td>
<td style="text-align: left;"><p>Изменение к 0.7.1</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>fullHandshake</code></p></td>
<td style="text-align: left;"><p>95,5</p></td>
<td style="text-align: left;"><p>94,0 ± 12,2</p></td>
<td style="text-align: left;"><p><strong>203,4 ± 3,4</strong></p></td>
<td style="text-align: left;"><p><strong>×2,16</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>mutualAuth</code></p></td>
<td style="text-align: left;"><p>58,8</p></td>
<td style="text-align: left;"><p>58,6 ± 2,2</p></td>
<td style="text-align: left;"><p><strong>153,0 ± 1,9</strong></p></td>
<td style="text-align: left;"><p><strong>×2,61</strong></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 100 Б</p></td>
<td style="text-align: left;"><p>360 195</p></td>
<td style="text-align: left;"><p>352 878</p></td>
<td style="text-align: left;"><p>352 924</p></td>
<td style="text-align: left;"><p>0 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 1 КБ</p></td>
<td style="text-align: left;"><p>49 504</p></td>
<td style="text-align: left;"><p>48 604</p></td>
<td style="text-align: left;"><p>47 687</p></td>
<td style="text-align: left;"><p>−1,9 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 16 КБ</p></td>
<td style="text-align: left;"><p>3 258</p></td>
<td style="text-align: left;"><p>3 158</p></td>
<td style="text-align: left;"><p>3 123</p></td>
<td style="text-align: left;"><p>−1,1 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 100 Б</p></td>
<td style="text-align: left;"><p>175 255</p></td>
<td style="text-align: left;"><p>167 330</p></td>
<td style="text-align: left;"><p>168 309</p></td>
<td style="text-align: left;"><p>+0,6 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 1 КБ</p></td>
<td style="text-align: left;"><p>24 068</p></td>
<td style="text-align: left;"><p>24 573</p></td>
<td style="text-align: left;"><p>23 842</p></td>
<td style="text-align: left;"><p>−3,0 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 16 КБ</p></td>
<td style="text-align: left;"><p>1 598</p></td>
<td style="text-align: left;"><p>1 566</p></td>
<td style="text-align: left;"><p>1 531</p></td>
<td style="text-align: left;"><p>−2,2 %</p></td>
</tr>
</tbody>
</table>

## Анализ

1.  **Рукопожатие быстрее 0.7.1 в 2,2 раза, с клиентским сертификатом —
    в 2,6 раза.** Основной вклад — арифметика кривой: генерация ключа
    ECDHE быстрее в 3–4 раза, подпись в 2,3 раза, проверка подписи в 1,5
    раза (см. отчёт
    `bench/results/tls/результаты-jmh-tls-2026-11-16.adoc`).

2.  **Вклад нового Стрибога — около 13 %.** 15 ноября на коде до замены
    хеша (три запуска JVM) было 180,5 ± 7,0 и 135,0 ± 3,7; сейчас 203,4
    и 153,0. Хеш входит в рукопожатие через хеш стенограммы, HKDF и HMAC
    сообщений Finished, а также через хеш подписываемых данных; HKDF и
    вывод ключей теперь быстрее в 2,2 раза.

3.  **Слой записей без изменений.** Все размеры в пределах ±3 % от
    0.7.1. Расхождение с прогоном 4 (до −4 %) — в пределах разницы между
    сборками JDK и одним запуском JVM против трёх.

4.  **Соотношение mutualAuth/fullHandshake** — 1,33 (в прогоне 4 было
    1,62): дешёвая теперь проверка открытого ключа и подписи сильнее
    ускорила путь с двумя проверками.

# Выделения памяти (`-prof gc`, один запуск JVM)

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
<td style="text-align: left;"><p>0.7.1</p></td>
<td style="text-align: left;"><p>Сейчас</p></td>
<td style="text-align: left;"><p>Изменение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>fullHandshake</code>, на
рукопожатие</p></td>
<td style="text-align: left;"><p>21,19 МБ</p></td>
<td style="text-align: left;"><p>10,02 МБ</p></td>
<td style="text-align: left;"><p>−53 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 100 Б / 1 КБ /
16 КБ</p></td>
<td style="text-align: left;"><p>312 / 312 / 316 Б</p></td>
<td style="text-align: left;"><p>216 / 216 / 217 Б</p></td>
<td style="text-align: left;"><p>−31 %</p></td>
</tr>
</tbody>
</table>

Это временные выделения, которые собирают молодые сборки, а не занятая
память. Основной оставшийся источник в рукопожатии — скалярное
умножение: каждая операция поля создаёт новый объект.

# Проверки разумности

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
<td style="text-align: left;"><p><code>roundTrip</code> ≈ половина
<code>wrap</code></p></td>
<td style="text-align: left;"><p>в обмене две операции AEAD вместо
одной</p></td>
<td style="text-align: left;"><p>✅ на 16 КБ 3 123 против 1 531
(соотношение 2,04)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS дороже полного
рукопожатия</p></td>
<td style="text-align: left;"><p>дополнительные подпись и
проверка</p></td>
<td style="text-align: left;"><p>✅ на 33 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Пропускная способность растёт с
размером записи</p></td>
<td style="text-align: left;"><p>постоянные расходы делятся на больший
объём</p></td>
<td style="text-align: left;"><p>✅ 33,7 → 46,6 → 48,8 МБ/с</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Погрешность рукопожатий меньше 5
%</p></td>
<td style="text-align: left;"><p>устойчивый прогон</p></td>
<td style="text-align: left;"><p>✅ 1,7 % и 1,2 %</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Слой записей стабилен</p></td>
<td style="text-align: left;"><p>±5 % от 0.7.1</p></td>
<td style="text-align: left;"><p>✅ все в пределах ±3 %</p></td>
</tr>
</tbody>
</table>

# Ёмкость

Одно ядро, без проверки сертификата:

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Операция</p></td>
<td style="text-align: left;"><p>Операций в секунду</p></td>
<td style="text-align: left;"><p>МБ/с</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Полное рукопожатие TLS 1.3</p></td>
<td style="text-align: left;"><p>203 (4,9 мс)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Рукопожатие с клиентским
сертификатом</p></td>
<td style="text-align: left;"><p>153 (6,5 мс)</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 100 Б</p></td>
<td style="text-align: left;"><p>353 000</p></td>
<td style="text-align: left;"><p>33,7</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 1 КБ</p></td>
<td style="text-align: left;"><p>47 700</p></td>
<td style="text-align: left;"><p>46,6</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>wrap</code> 16 КБ</p></td>
<td style="text-align: left;"><p>3 120</p></td>
<td style="text-align: left;"><p>48,8</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 100 Б</p></td>
<td style="text-align: left;"><p>168 000</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 1 КБ</p></td>
<td style="text-align: left;"><p>23 800</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>roundTrip</code> 16 КБ</p></td>
<td style="text-align: left;"><p>1 530</p></td>
<td style="text-align: left;"><p>—</p></td>
</tr>
</tbody>
</table>

# Открытые вопросы

1.  Выделения при скалярном умножении (около 1,4 МБ на подпись или ключ
    ECDHE) — главный оставшийся источник нагрузки на сборщик мусора.

2.  Стоимость проверки сертификата в `GostX509TrustManager` на уровне
    JSSE не измерялась.

3.  Возобновление по PSK на уровне JSSE отдельным бенчмарком не
    измеряется (на уровне tls13 — `PskResumptionBench`).

4.  Сравнение с SunJSSE на классических алгоритмах и многопоточная
    пропускная способность рукопожатий.

# Воспроизведение прогона

    mvn -o install -DskipTests
    cd bench/jsse && mvn -o package
    java -jar target/benchmarks.jar JsseHandshakeBench -wi 5 -i 5 -f 3 -w 10s -r 10s -jvmArgs -Xmx2g
    java -jar target/benchmarks.jar JsseRecordBench -wi 5 -i 5 -f 3 -w 10s -r 10s -jvmArgs -Xmx2g
    java -jar target/benchmarks.jar '(JsseHandshakeBench.fullHandshake|JsseRecordBench.roundTrip)' -prof gc -wi 2 -i 3 -f 1 -w 5s -r 5s -jvmArgs -Xmx2g

Перед запуском проверить, что EPP всех ядер `performance`:
`cat /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference`.
