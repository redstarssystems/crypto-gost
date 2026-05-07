# Введение

**crypto-gost** — криптографическая библиотека алгоритмов ГОСТ на Java,
а также сопутствующая обвязка вокруг них, позволяющая в полной мере
внедрить ГОСТ в инфраструктуру Java.

**Данная библиотека не является сертифицированной и не предназначена для
работы там, где требуются сертифицированные средства криптографии.**

Библиотека состоит из модулей:

- `crypto-gost-core` - криптографическое ядро.

- `crypto-gost-tls13` - Реализация протокола **TLS 1.3** (RFC 8446) с
  поддержкой российских криптографических алгоритмов согласно **RFC
  9367**.

Поддерживаемые алгоритмы ГОСТ в модуле `crypto-gost-core`:

- **ГОСТ Р 34.11-2012** — хэш-функция «Стрибог» 256 и 512 бит (RFC
  6986).

- **ГОСТ Р 34.12-2015** — блочный шифр «Кузнечик», ключ 256 бит.

- **ГОСТ Р 34.13-2015** — режимы шифрования CBC, CFB, CTR, OFB;
  имитовставка (CMAC).

- **ГОСТ Р 34.10-2012** — электронная подпись 256 и 512 бит (RFC 7091).

- **HMAC-Стрибог** — RFC 7836 (HMAC-Streebog-256 и HMAC-Streebog-512).

- **MGM (Multilinear Galois Mode)** — AEAD-режим для Кузнечика,
  RFC 9058. Совместим с OpenSSL.

**Для модуля `crypto-gost-core` выполнена кросс-валидация на
совместимость с `openssl (ГОСТ)` и `Bouncycastle`.**

Модуль `crypto-gost-tls13` содержит реализацию **TLS 1.3** (RFC 8446 +
RFC 9367) с ГОСТ-криптографией:

1.  **Протоколы:**

    - **Handshake**: полный (client/server), сокращённый (`PSK`),
      взаимный (`mTLS`).

    - **ALPN (RFC 7301)** — согласование протокола прикладного уровня
      (HTTP/2, HTTP/1.1).

    - **SNI (RFC 6066)** — указание имени сервера для multi-tenant
      развёртываний.

    - **KeyUpdate (RFC 8446 §4.6.3)** — обновление ключей шифрования
      трафика.

    - **Cipher suites**: `TLS_KUZNYECHIK_MGM_STREEBOG_256_L/S`.

    - **ECDHE**: CryptoPro-A (256-bit), CryptoPro-B (512-bit)

    - **Per-record TLSTREE re-keying** — смена ключа шифрования на
      каждую TLS-запись.

    - **Фрагментация и сборка** рукопожатий и записей (RFC 8446 §5.1).

    - **Session resumption**: `PSK` через `NewSessionTicket` (`PskStore`
      in-memory, single-use).

    - **OCSP stapling**: сервер прикладывает OCSP-ответ к сертификату.

    - **Post-handshake messages**: `NewSessionTicket` (сохранение для
      `PSK`).

2.  **Криптография**:

    - **Key schedule**: `HKDF-Streebog` (RFC 5869) по схеме TLS 1.3 (RFC
      8446 §7.1).

    - **Защита записей**: `MGM-AEAD` (Kuznyechik) с nonce по RFC 8446
      §5.3.

    - Эфемерные ключи затираются после использования.

3.  **Сертификаты:**

    - Парсинг X.509v3 (GOST R 34.10-2012) — встроенный DER-парсер.

    - Валидация цепочки: подписи, DN (issuer → subject),
      `Basic Constraints`, `Key Usage`, `Extended Key Usage`
      (`serverAuth` / `clientAuth`), pathLen.

    - Проверка hostname: dNSName + iPAddress (RFC 6125).

    - Верификация OCSP-ответов (RFC 6960).

4.  **Транспорт:**

    - `TlsTransport` — интерфейс.

    - `InMemoryTlsTransport` — для тестов и однопроцессных сценариев
      (in-memory очередь).

    - `SocketTlsTransport` — blocking I/O через `java.net.Socket`.

    - `ChannelTlsTransport` — NIO `SocketChannel`-based transport
      (blocking mode, interruptible).

5.  **Пошаговый handshake:**

    - `TlsHandshakeEngine` — state machine для handshake (отвязан от
      I/O). Используется `TlsSession` как оркестратор; пригоден для
      интеграции с JSSE (`SSLEngine`).

6.  **ByteBuffer API:**

    - `TlsRecord.protect/unprotect` — ByteBuffer-перегрузки для
      zero-copy интеграции с NIO.

7.  **Загрузка ключей:**

    - `Pkcs12Loader` — чтение PFX (PKCS#12) с
      `PBKDF2-HMAC-SHA256 + AES-256-CBC`.

8.  **Завершение сессии:**

    - `close_notify` — корректное закрытие по протоколу.

    - Затирание ключевого материала при закрытии или ошибке.

    - Обработка alert: `fatal` — немедленное закрытие + затирание.

9.  **Безопасность реализации:**

    - Constant-time сравнения для verify\_data и PSK binders (защита от
      timing attacks)

    - Затирание ключевого материала при close, fatal alert, exception в
      handshake

    - Защита от DoS: лимиты на длину цепочки сертификатов (10),
      post-handshake messages, размер записей.

10. **Ограничения:**

    - Только resumption PSK (0-RTT и external PSK не поддерживаются).

    - Только `psk_dhe_ke` (pure PSK без ECDHE не поддерживается).

    - `HelloRetryRequest` (RFC 8446 §4.1.4) не поддерживается —
      используется только одна named group (GC256A по умолчанию).

    - Только ГОСТ (non-GOST cipher suites не поддерживаются).

    Все криптографические операции выполняются встроенными средствами
    библиотеки — без внешних зависимостей.

Дополнительные алгоритмы (не ГОСТ):

- **SCrypt** — функция выработки ключа на основе пароля (RFC 7914).

## Цели и задачи

Создавая эту библиотеку я хотел устранить следующие недостатки:

- Иметь криптографическую библиотеку на чистой Java без зависимостей.

- Только ГОСТ-алгоритмы без лишнего кода связанного с западным
  стандартами;

- Готовые методы: потоковое шифрование + имитозащита для шифрования
  файлов или сокетов.

- Реализацию TLS 1.3 для построения безопасных сетевых сервисов с
  российской криптографией.

- Готовые и привычные инструменты для разработчиков и devops-инженеров
  для быстрого развертывания криптографической инфраструктуры в
  экосистема Java.

- Доступную с открытым кодом и нашей лицензией библиотеку для
  разработчиков.

# Установка

- **Способ 1.** Клонируйте репозиторий и выполните сборку и установку в
  локальный .m2:  

  `mvn install`.

  Все модули будут установлены в локальный .m2.

  При необходимости проверить подпись релизного тега можно так:

      gpg --import KEYS
      gpg -v v0.2.0

- **Способ 2.** Скачайте артефакты
  [отсюда](https://gitflic.ru/project/red-stars-systems/crypto-gost/release?sort=TIME&direction=DESC)
  и установите нужные модули. Для модуля `crypto-gost-core` пример
  установки:  

      mvn install:install-file \
        -Dfile=crypto-gost-core-0.2.0.jar \
        -Dsources=crypto-gost-core-0.2.0-sources.jar \
        -Djavadoc=crypto-gost-core-0.2.0-javadoc.jar \
        -DgroupId=org.rssys \
        -DartifactId=crypto-gost-core \
        -Dversion=0.2.0 \
        -Dpackaging=jar

Затем, добавьте зависимость в `pom.xml` вашего проекта нужные модули:

    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost-core</artifactId>
        <version>0.2.0</version>
    </dependency>

    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost-tls13</artifactId>
        <version>0.2.0</version>
    </dependency>

Проверить подпись можно так:

    gpg --import KEYS
    gpg --verify crypto-gost-core-0.2.0.jar.asc crypto-gost-core-0.2.0.jar

# CRYPTO-GOST-CORE

Подробная документация модуля `crypto-gost-core` вынесена в отдельный
файл: [crypto-gost-core/README.adoc](crypto-gost-core/README.adoc) или
[crypto-gost-core/README.md](crypto-gost-core/README.md) (обновляется
автоматически на основе asciidoc-файла).

# CRYPTO-GOST-TLS13

Подробная документация модуля `crypto-gost-tls13` вынесена в отдельный
файл: [crypto-gost-tls13/README.adoc](crypto-gost-tls13/README.adoc) или
[crypto-gost-tls13/README.md](crypto-gost-tls13/README.md) (обновляется
автоматически на основе asciidoc-файла).

# Бенчмарки

[Методики бенчмарков и кросс-валидации](#bench/README.adoc)

# Раздел для разработчиков

Для доработки библиотеки необходимо установить OpenJDK 11+, maven.

- `mvn test` — запуск тестов.

- `mvn package` — получение дистрибутива библиотеки.

- `mvn install` — установка дистрибутива библиотеки в локальный .m2.

В папке *bench* созданы примеры кросс-верификации **crypto-gost**,
**BouncyCastle 1.83** и **OpenSSL**.

# Проблематика

Представленная ниже информация является моим частным мнением и оно может
являться ошибочным.  
Криптобиблиотека может содержать ошибки, которые мне неизвестны (я
прилагаю все усилия, чтобы такие найти и закрыть), все риски по её
использованию вы берете на себя.

**Если вам нужна сильная криптография и гарантии её правильной работы -
найдите профессионалов и доверьтесь им.**

Разработчикам иногда требуется российская криптография для защиты
данных. Для личных проектов или для целей локальной разработки в
тестовой среде не всегда возможно использовать сертифицированные
средства. Если у вас есть личный проект на нескольких серверах, то для
установки в них российской криптографии и развертывания
PKI-инфраструктуры придется сделать значительные усилия. Де-факто
"стандартом" в области криптографии для Java для разработчиков стала
библиотека Bouncycastle. Этой библиотеке много лет, есть обширная
документация и книги, которые я считаю полезно изучить.

При использовании Bouncycastle имменно с российской криптографией я
столкнулся со следующими трудностями:

- Очень медленное шифрование/расшифрование по ГОСТ "Кузнечик".

- Есть проблемы с безопасностью реализации, некоторые из которых могут
  носить критический характер (об этом далее);

- Если мне нужны только ГОСТ-алгоритмы, то 95% остального кода
  библиотеки мне не нужно.

- Нужен контроль изменений в новых версиях, как в плане безопасности,
  так и производительности.

- Отсутствие современной реализации TLS для ГОСТ.

- Безопасность даже для личных проектов очень важна. Авторы развивают
  прежде всего западные алгоритмы и устраняют недостатки в них.

Классический алгоритм электронной подписи на эллиптических кривых
(ECDSA) при каждой подписи требует некое число `k`, которое нужно
использовать при подписи совместно с закрытым ключом. Некоторые авторы
реализуют ECDSA со случайным `k`, что требует криптографически
качественного генератора случайных чисел (ГСЧ/RNG) при каждой подписи. А
если ваш сайт или приложение работают в облачной среде, то неизвестно
как настроена виртуализация и проброс энтропии в виртуальную машину для
выработки случайных чисел `k`, нужных для **каждой** подписи.

Хочу отметить некоторые недавние взломы на этой почве:

- Sony PlayStation 3 (2010) — использовали константный `k` при подписи
  прошивок. *Два уравнения с одним `k` → система из двух уравнений →
  закрытый ключ восстанавливается элементарно*.

- Android Bitcoin-кошельки (2013) — java.security.SecureRandom на
  Android имел дефект инициализации. Повторяющиеся `k` у разных
  пользователей привели к массовой краже биткоинов.

Отсюда можно сделать вывод, что если вы взяли Bouncycastle или любую
другую библиотеку, то нужно иметь в виду, что:

- повтор числа `k` → полная компроментация закрытого ключа;

- предсказуемый `k` → тоже компроментация закрытого ключа;

- слабый ГСЧ(RNG) в облаке или специфических условиях → катастрофа.

- утечки ключа через атаки по таймингу (timing) или по сторонним каналам
  (side channels). Да, для криптографии нельзя в лоб писать
  умножение/деление больших чисел, т.к. это создаёт риск утечки
  закрытого ключа при наличии доступа к времени выполнения операций
  (особенно если ваш сервис можно дергать по API). Нужна специальная
  математика, защитные техники, строгий контроль, чего рядовой
  разработчик просто не знает, отсюда и обоснование сертификации средсв
  СКЗИ для серьезных проектов и корректности их встраивания.

SecureRandom в Java сегодня — криптографически надёжный. Основная угроза
— не алгоритм, а окружение (энтропия в VM), которую использует
BouncyCastle.

Изначально, часть кода этой библиотеки основана на BouncyCastle 1.83. Но
сейчас код полностью переработан: исправлены недочёты оригинала,
арифметика эллиптических кривых приведена в сторону безопасности, число
`k` выполнено детерминированным (не путать с константным) по RFC 6979
вместо `SecureRandom`, ускорены алгоритмы шифрования. Реализация
приведена в полное соответствие стандартам ГОСТ и RFC. В данной
реализации библиотеке упала скорость электронной подписи в угоду
безопасности.

## Улучшения в безопасности электронной подписи

В таблице приведена сравнительная оценка безопасности электронной
подписи между двумя библиотеками. Там где указано *constant time*(CT)
это положительное свойство. Злоумышленник может посылать разные данные и
запросы. Если криптографические операции выполняются за одно и то же
время, то такое свойство реализации не дает злоумышленнику никаких
данных. Отсутствие *constant time* свойства у операций, это серьезный
риск утечки закрытого ключа.

<table>
<caption>Сравнение реализации ГОСТ Р 34.10-2012
<strong>crypto-gost</strong> с BouncyCastle 1.83</caption>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Свойство</th>
<th style="text-align: center;">crypto-gost<br />
(текущая версия)</th>
<th style="text-align: center;">BouncyCastle 1.83</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Арифметика поля (ГОСТ-кривые)</p></td>
<td style="text-align: center;"><p>Защищено<br />
Montgomery CIOS, <code>long[]</code>,<br />
constant-time</p></td>
<td style="text-align: center;"><p><code>BigInteger</code> через
<code>ECFieldElement.Fp.modMult()</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Координаты точки</p></td>
<td style="text-align: center;"><p>Проективные Якоби,<br />
только long[]</p></td>
<td style="text-align: center;"><p>ECFieldElement.Fp на BigInteger,
координатная система Якоби`.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Timing side-channel арифметики
поля</p></td>
<td style="text-align: center;"><p>Защищено<br />
(constant time без ветвлений по данным)</p></td>
<td style="text-align: center;"><p>Уязвимо<br />
(переменное время <code>BigInteger</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Скалярное умножение секретного
<em>k</em></p></td>
<td style="text-align: center;"><p>Защищено<br />
Montgomery ladder<br />
(constant-time)</p></td>
<td style="text-align: center;"><p>Уязвимо<br />
wNAF / <code>FixedPointCombMultiplier</code><br />
(не constant time)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Timing side-channel скалярного
умножения</p></td>
<td style="text-align: center;"><p>Защищено</p></td>
<td style="text-align: center;"><p>Уязвимо</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Инверсия в поле при
<code>normalize()</code></p></td>
<td style="text-align: center;"><p>z<sup>(p−2)</sup> mod p, CT ladder
(теорема Ферма)</p></td>
<td style="text-align: center;"><p><code>BigInteger.modInverse()</code>
(алгоритм Евклида, не constant time)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Timing side-channel инверсии z →
k</p></td>
<td style="text-align: center;"><p>Защищено</p></td>
<td style="text-align: center;"><p>Уязвимо</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Генерация эфемерного ключа
<em>k</em></p></td>
<td style="text-align: center;"><p>Защищено<br />
RFC 6979 (детерминированный HMAC-DRBG)</p></td>
<td style="text-align: center;"><p><code>SecureRandom</code><br />
(зависит от ГСЧ и окружения)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Устойчивость к атакам на RNG</p></td>
<td style="text-align: center;"><p>Защищено<br />
(<em>k</em> не зависит от ГСЧ/RNG)</p></td>
<td style="text-align: center;"><p>Зависит от качества источника
энтропии в окружении.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Интерпретация хэша (RFC 7091
§5.3)</p></td>
<td style="text-align: center;"><p>LSB-first
(<code>reverseBytes</code>), точно по стандарту ГОСТ</p></td>
<td style="text-align: center;"><p>Требует отдельной проверки для каждой
версии библиотеки</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Зачистка ключевого материала</p></td>
<td style="text-align: center;"><p>Выполняется<br />
<code>Destroyable</code><br />
<code>Arrays.fill(dBytes, 0)</code></p></td>
<td style="text-align: center;"><p>Частично<br />
(нет явного <code>Destroyable</code> для ГОСТ-ключей)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Условная редукция
(constant-time)</p></td>
<td style="text-align: center;"><p>constant-time-маска без ветвления в
<code>conditionalSubtract</code></p></td>
<td style="text-align: center;"><p>Не применимо (<code>BigInteger</code>
непрозрачен)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Вычисление маски бесконечности</p></td>
<td
style="text-align: center;"><p><code>(acc | -acc) &gt;&gt;&gt; 63</code>
(CT, без тернарного оператора)</p></td>
<td style="text-align: center;"><p>Не применимо</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Shamir’s trick при верификации
подписи</p></td>
<td style="text-align: center;"><p><code>shamirMultiply</code> -
интерливинговый wNAF,<br />
z1·G + z2·Q за один проход</p></td>
<td
style="text-align: center;"><p><code>ECAlgorithms.implShamirsTrickWNaf</code>,<br />
аналогичный алгоритм</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Совместимость JVM</p></td>
<td style="text-align: center;"><p>JDK 11+<br />
</p></td>
<td style="text-align: center;"><p>JDK 8+</p></td>
</tr>
</tbody>
</table>

Данная реализация **crypto-gost** претендует на более защищенный уровень
по нескольким параметрам, который к тому же не зависит от качества ДСЧ
(RNG) в облаке/окружении при подписи сообщений.  
**Данное утверждение требует подтверждения с помощью независимого
аудита**.

Нужно отметить существенное падение скорости подписи и проверки в
`crypto-gost`, связанные с реализацией. Что лучше: безопасность vs
скорость? Данная библиотека поставила целью преследовать безопасность,
как наивысший критерий. Какой смысл в быстрой подписи, если любая
операция ведет к компроментации закрытого ключа.

# Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
