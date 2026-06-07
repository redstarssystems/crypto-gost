# Назначение

Измерение скорости передачи данных через защищённое соединение
TlsSession поверх настоящего сетевого сокета. Тест:
`TlsSessionStreamTest` (пакет `org.rssys.gost.tls13.stress`, состав
crypto-gost-tls13).

# Что измеряется

Поток данных в одну сторону: отправитель непрерывно шифрует и передаёт
блоки, получатель принимает и расшифровывает. Считается объём принятых и
расшифрованных данных в единицу времени.

ВАЖНО: это верхняя оценка для одного направления. Двусторонний обмен
(одновременно приём и передача на одном ядре) даст меньшую величину.

- Клиент и сервер работают в одном JVM-процессе — паузы сборщика мусора
  затрагивают обе стороны одновременно, что может временно останавливать
  передачу данных с обеих сторон и занижать результат. В распределённом
  развёртывании (клиент и сервер на разных машинах) этот эффект
  отсутствует.

# Условия

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 66%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Набор шифрования</p></td>
<td style="text-align: left;"><p>Кузнечик-МГМ, Стрибог-256 (профиль
L)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Размер блока</p></td>
<td style="text-align: left;"><p>16383 байта (близко к пределу
записи)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Прогрев</p></td>
<td style="text-align: left;"><p>5 секунд (переопределяется через
<code>stress.warmup</code>), без подсчёта</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Измерение</p></td>
<td style="text-align: left;"><p>15 секунд (переопределяется через
<code>stress.measure</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Число прогонов</p></td>
<td style="text-align: left;"><p>5 (переопределяется через
<code>stress.iters</code>), итог по медиане</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Транспорт</p></td>
<td style="text-align: left;"><p>настоящий сокет TCP через
localhost</p></td>
</tr>
</tbody>
</table>

# Порядок одного прогона

1.  Получатель встаёт на приём; рукопожатие сторон.

2.  Отправитель 5 секунд шлёт блоки без подсчёта (прогрев — чтобы успел
    отработать разогрев виртуальной машины).

3.  Включается признак измерения.

4.  Отправитель 15 секунд непрерывно шлёт блоки.

5.  Отправитель закрывает соединение (сигнал завершения).

6.  Получатель досчитывает остаток и фиксирует время последнего
    принятого блока.

# Правила подсчёта (что делает оценку честной)

1.  Объём считается на стороне **получателя** — по принятым и
    расшифрованным данным, а не по отправленным. Иначе размер буферов
    завысил бы итог.

2.  Время измерения привязано к данным: начало — первый принятый блок,
    конец — последний принятый блок. Выход из цикла приёма (по сигналу
    завершения или по тайм-ауту простоя) на расчёт не влияет.

3.  Время берётся часами с устойчивым ходом (`System.nanoTime`); итог
    делится на действительно прошедшее время, а не на плановое.

4.  Состояние каждого прогона обособлено — переноса значений между
    прогонами нет.

# Отбраковка прогона

Прогон не учитывается, если:

- поток приёма не завершился в отведённое время;

- признак начала или конца измерения не выставлен;

- объём принятых данных равен нулю;

- длительность измерения меньше 5 секунд.

Итог считается только по пригодным прогонам.

# Итоговая величина

Медиана по пригодным прогонам (МБ/с), а также наименьшее и наибольшее
значения. Порог годности в тест не зашит — величина оценивается
отдельно.

# Подготовка системы (prerequisites)

После перезагрузки сбрасываются `sysctl` и CPU governor — без настройки
результат может быть занижен на десятки процентов.

    # CPU governor (должен быть performance)
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

    # TCP port range (должен быть 1024 65535)
    cat /proc/sys/net/ipv4/ip_local_port_range
    sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

    # tcp_tw_reuse (должен быть 1)
    cat /proc/sys/net/ipv4/tcp_tw_reuse
    sudo sysctl -w net.ipv4.tcp_tw_reuse=1

    # Размеры буферов сокета (рекомендуется)
    sudo sysctl -w net.core.rmem_max=134217728
    sudo sysctl -w net.core.wmem_max=134217728

# Запуск теста

По умолчанию `@Tag("stress")`-тесты исключены из прогона через
`surefire.excludedGroups` (корневой `pom.xml`). Переопределить можно
через `-Dsurefire.excludedGroups=`:

## Через make (рекомендуется)

    # Однопоточный throughput (5 прогонов × ~20 с ≈ 100 с)
    make test-stress-tlssession

    # Одиночный быстрый замер (переопределяет test из Makefile)
    make test-stress-tlssession ARGS="-Dtest=org.rssys.gost.tls13.stress.TlsSessionStreamTest#throughput"

    # Управление временем через make
    make test-stress-tlssession ARGS="-Dstress.warmup=2 -Dstress.measure=10 -Dstress.iters=3"

Управление временем теста:

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 40%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Свойство</p></td>
<td style="text-align: left;"><p>По умолч.</p></td>
<td style="text-align: left;"><p>Описание</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>stress.warmup</code></p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>Прогрев, секунд</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>stress.measure</code></p></td>
<td style="text-align: left;"><p>15</p></td>
<td style="text-align: left;"><p>Замер, секунд</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>stress.iters</code></p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>Число прогонов</p></td>
</tr>
</tbody>
</table>

## Через Maven напрямую

    # Однопоточный throughput (5 прогонов × ~20 с ≈ 100 с)
    mvn test -pl crypto-gost-tls13 -am \
      -Dtest="org.rssys.gost.tls13.stress.TlsSessionStreamTest" \
      -Dsurefire.excludedGroups= \
      -Dsurefire.failIfNoSpecifiedTests=false

    # Только измерение (без прочих тестов tls13)
    mvn test -pl crypto-gost-tls13 -am \
      -Dtest="org.rssys.gost.tls13.stress.TlsSessionStreamTest#throughput" \
      -Dsurefire.excludedGroups= \
      -Dsurefire.failIfNoSpecifiedTests=false

    # Короткий прогон (3 прогона, прогрев 2 с, замер 10 с)
    mvn test -pl crypto-gost-tls13 -am \
      -Dtest="org.rssys.gost.tls13.stress.TlsSessionStreamTest#throughput" \
      -Dsurefire.excludedGroups= \
      -Dsurefire.failIfNoSpecifiedTests=false \
      -Dstress.warmup=2 -Dstress.measure=10 -Dstress.iters=3
