# Введение

**crypto-gost** — криптографическая библиотека алгоритмов ГОСТ на Java.

Данная библиотека не является сертифицированной и не предназначена для
работы там, где требуются сертифицированные средства криптографии.

Поддерживаемые алгоритмы ГОСТ:

- **ГОСТ Р 34.11-2012** — хэш-функция «Стрибог» 256 и 512 бит (RFC
  6986).

- **ГОСТ Р 34.12-2015** — блочный шифр «Кузнечик», ключ 256 бит.

- **ГОСТ Р 34.13-2015** — режимы шифрования CBC, CFB, CTR, OFB;
  имитовставка (CMAC).

- **ГОСТ Р 34.10-2012** — электронная подпись 256 и 512 бит (RFC 7091).

- **HMAC-Стрибог** — RFC 7836 (HMAC-Streebog-256 и HMAC-Streebog-512).

- **MGM (Multilinear Galois Mode)** — AEAD-режим для Кузнечика,
  RFC 9058. Совместим с OpenSSL.

Дополнительные алгоритмы (не ГОСТ):

- **SCrypt** — функция выработки ключа на основе пароля (RFC 7914).

**Создавая эту библиотеку я хотел устранить следующие недостатки
Bouncycastle:**

- Иметь криптографическую библиотеку на чистой Java без зависимостей.

- Только ГОСТ-алгоритмы без лишнего кода, который относится к западным
  стандартам и не будет требовать аудита;

- Более высокую скорость шифрования алгоритмом "Кузнечик".

- Готовые методы: потоковое шифрование + имитозащита для шифрования
  файлов или сокетов.

- Удобные обертки, не требующие глубоких знаний в криптографии.

- По возможности, устранить недостатки реализации электронной подписи
  ГОСТ или уязвимости в Bouncycastle.

- Доступную с открытым кодом и нашей лицензией библиотеку для
  разработчиков.

**Выполнена кросс-валидация на совместимость с `openssl (ГОСТ)` и
`Bouncycastle`.**

## Зачем эта библиотека?

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
установки в них российской криптографии придется приобрести лицензии.
Де-факто "стандартом" в области криптографии для Java для разработчиков
стала библиотека Bouncycastle. Этой библиотеке много лет, есть обширная
документация и книги, которые я считаю очень полезно почитать.

Однако при использовании Bouncycastle имменно с российской криптографией
я столкнулся со следующими трудностями:

- Очень медленное шифрование/расшифрование по ГОСТ "Кузнечик".

- Есть проблемы с безопасностью реализации, некоторые из которых могут
  носить критический характер (об этом далее);

- Если мне нужны только ГОСТ-алгоритмы, то 95% остального кода
  библиотеки мне не нужно.

- Нужен контроль изменений в новых версиях, как в плане безопасности,
  так и производительности.

- Безопасность даже для личных проектов очень важна. Авторы развивают
  прежде всего западные алгоритмы и устраняют недостатки в них.

Классический алгоритм электронной подписи на эллиптических кривых
(ECDSA) при каждой подписи требует некое число `k`, которое нужно
использовать при подписи совместно с закрытым ключом. Некоторрые авторы
реализуют ECDSA со случайным `k`, что требует криптографически
качественного генератора случайных чисел (ГСЧ) при каждой подписи. А
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

### Улучшения в безопасности электронной подписи

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

Нужно отметить существенное падение скорости подписи и проверки. Что
лучше: безопасность vs скорость? Данная библиотека поставила целью
преследовать безопасность, как наивысший критерий. Какой смысл в быстрой
подписи, если любая операция ведет к компроментации закрытого ключа?

Методика бенчмарков описана ниже.

Результаты бенчмарков:

- [Результаты сравнения для 256
  бит](https://gitflic.ru/project/red-stars-systems/crypto-gost/blob?file=doc/bench/results/signature/ecgost256-throughput.png)

- [Результаты сравнения для 512
  бит](https://gitflic.ru/project/red-stars-systems/crypto-gost/blob?file=doc/bench/results/signature/ecgost512-throughput.png)

### Улучшения в шифровании

Методика бенчмарков описана ниже. Результаты сравнения **crypto-gost** и
**BouncyCastle 1.83**

Результаты:

- [Результаты сравнения режима
  CTR](https://gitflic.ru/project/red-stars-systems/crypto-gost/blob?file=doc/bench/results/kuznyechik/kuznyechik-ctr-throughput.png)

- [Результаты сравнения режима
  CFB](https://gitflic.ru/project/red-stars-systems/crypto-gost/blob?file=doc/bench/results/kuznyechik/kuznyechik-cfb-throughput.png)

# Установка

Способы установи:

- **Способ 1.** Клонируйте репозиторий и выполните сборку и установку в
  локальный .m2:  

  `mvn install`.

  При необходимости проверить подпись релизного тега можно так:

      gpg --import KEYS
      gpg -v v0.1.1

- **Способ 2.** Скачайте артефакты
  [отсюда](https://gitflic.ru/project/red-stars-systems/crypto-gost/release?sort=TIME&direction=DESC)
  и установите:  

      mvn install:install-file \
        -Dfile=crypto-gost-0.1.1.jar \
        -Dsources=crypto-gost-0.1.1-sources.jar \
        -Djavadoc=crypto-gost-0.1.1-javadoc.jar \
        -DgroupId=org.rssys \
        -DartifactId=crypto-gost \
        -Dversion=0.1.1 \
        -Dpackaging=jar

Затем, добавьте зависимость в `pom.xml` вашего проекта:

    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost</artifactId>
        <version>0.1.1</version>
    </dependency>

Проверить подпись можно так:

    gpg --import KEYS
    gpg --verify crypto-gost-0.1.1.jar.asc crypto-gost-0.1.1.jar

Публичный gpg-ключ в конце документа.

# Высокоуровневый API

Библиотека предоставляет два независимых API для работы:

- `org.rssys.gost.api` — высокоуровневый API, не требует регистрации
  провайдера. Код лаконичнее, ориентирован на пользователя.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API, интегрируется со
  стандартной инфраструктурой Java.

Все статические методы потокобезопасны.  

## Генерация ключей

### Управление симметричными ключами

#### Настройка провайдера (только для JCA API)

Перед использованием JCA-методов необходимо зарегистрировать провайдер
один раз:

    import java.security.Security;
    import org.rssys.gost.jca.RssysGostProvider;
    Security.addProvider(new RssysGostProvider());

#### Генерация симметричного ключа

Генерация случайного 256-битного ключа для шифра "Кузнечик" (ГОСТ Р
34.12-2015). По умолчанию, как источник энтропии используется класс
`java.security.SecureRandom`, который в JVM имеет хорошие
криптографические свойства.

Через `org.rssys.gost.api`

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = KeyGenerator.generateSymmetricKey();
    try {
        // использование ключа
    } finally {
        key.destroy(); // обнуляет ключевой материал в памяти
    }

Через JCA (`org.rssys.gost.jca`)

    import javax.crypto.KeyGenerator;
    import javax.crypto.SecretKey;

    KeyGenerator kg = KeyGenerator.getInstance("Kuznyechik", "RssysGostProvider");
    SecretKey key = kg.generateKey();
    try {
        // использование ключа
    } finally {
        key.destroy(); // обнуляет ключевой материал в памяти
    }

#### Импорт и экспорт симметричного ключа

Симметричный ключ хранится как сырые байты `byte[]`.

Никогда не храните симметричный ключ в открытом виде. Для хранения
используйте шифрование ключа другим ключом (KEK) или вывод из пароля
через scrypt (см. ниже).

#### org.rssys.gost.api

Экспорт ключа в byte\[\]

    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан или загружен ранее
    // getKey() возвращает defensive copy — мутация результата не влияет на ключ внутри объекта
    byte[] rawKey = key.getKey(); // 32 байта
    try {
        // сохранить rawKey в зашифрованном хранилище ...
    } finally {
        java.util.Arrays.fill(rawKey, (byte) 0); // обнулить после использования
    }

Импорт ключа из byte\[\]

    import org.rssys.gost.cipher.SymmetricKey;

    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    // Конструктор делает defensive copy — мутация rawKey после не влияет на ключ
    SymmetricKey key = new SymmetricKey(rawKey);
    try {
        // использование ключа ...
    } finally {
        key.destroy();                             // обнуляет ключ внутри объекта
        java.util.Arrays.fill(rawKey, (byte) 0);  // обнулить исходный массив
    }

Вывод ключа из пароля (scrypt, RFC 7914)

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.cipher.SymmetricKey;

    // Соль должна быть случайной и уникальной для каждого пользователя/объекта
    // Минимальная рекомендуемая длина соли: 16 байт
    byte[] password = "секретный пароль".getBytes(StandardCharsets.UTF_8);
    byte[] salt     = new byte[16];
    new java.security.SecureRandom().nextBytes(salt); // 
    SymmetricKey key = KeyGenerator.deriveKey(password, salt); // 
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(password, (byte) 0); // 
    }

- Соль не является секретом — её можно хранить рядом с зашифрованными
  данными. Главное требование: соль уникальна для каждого объекта
  шифрования.

- Параметры по умолчанию: N=524288, r=8, p=1. Операция ресурсоёмкая — не
  вызывайте в цикле и не блокируйте UI-поток.

- `deriveKey` не обнуляет массив пароля — это ответственность
  вызывающего кода.

#### JCA (org.rssys.gost.jca)

Экспорт ключа в byte\[\]

    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан или загружен ранее

    // getEncoded() возвращает defensive copy
    byte[] rawKey = key.getEncoded(); // 32 байта, null если ключ уничтожен
    try {
        // сохранить rawKey в зашифрованном хранилище ...
    } finally {
        if (rawKey != null) java.util.Arrays.fill(rawKey, (byte) 0);
    }

Импорт ключа из byte\[\] через `SecretKeyFactory` (рекомендуется)

    import javax.crypto.SecretKey;
    import javax.crypto.SecretKeyFactory;
    import javax.crypto.spec.SecretKeySpec;

    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    SecretKeySpec spec = new SecretKeySpec(rawKey, "Kuznyechik");
    SecretKeyFactory skf = SecretKeyFactory.getInstance("Kuznyechik", "RssysGostProvider");
    SecretKey key = skf.generateSecret(spec);
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(rawKey, (byte) 0);
    }

Импорт ключа через прямой конструктор `GostSecretKey`

    import org.rssys.gost.jca.key.GostSecretKey;
    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    // algorithm: "Kuznyechik", "HmacGOST3411-2012-256", "HmacGOST3411-2012-512", "CMAC-Kuznyechik"
    GostSecretKey key = new GostSecretKey("Kuznyechik", rawKey);
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(rawKey, (byte) 0);
    }

Конвертация между `SymmetricKey` и `GostSecretKey`

    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.jca.key.GostSecretKey;

    // api/ → JCA: SymmetricKey → GostSecretKey
    SymmetricKey symKey = ...; // из api/
    GostSecretKey jcaKey = new GostSecretKey("Kuznyechik", symKey); // 

    // JCA → api/: GostSecretKey → SymmetricKey
    GostSecretKey jcaKey2 = ...; // из JCA
    SymmetricKey symKey2 = jcaKey2.toSymmetricKey(); // 

- Конвертация создаёт копию ключевых байт. Уничтожение одного объекта не
  влияет на другой — вызывайте `destroy()` на обоих.

## Шифрование данных

Все алгоритмы используют шифр Кузнечик (ГОСТ Р 34.12-2015) с ключом 256
бит. Ключи считаются выработанными на предыдущем шаге (см. раздел
«Управление симметричными ключами»).

### Выбор алгоритма

В таблице приведены только некоторые режимы, рекомендуемые для начала,
обеспечивающие безопасную работу. Под API в таблице понимается или
`org.rssys.gost.api` или `org.rssys.gost.jca`

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 16%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Сценарий</th>
<th style="text-align: left;">Доступность в API</th>
<th style="text-align: left;">Алгоритм в API / JCA</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Шифрование блока данных аутентификацией
и контролем целостности,<br />
ГОСТ Р 34.13-2015 CTR+CMAC</p></td>
<td style="text-align: left;"><p><code>api</code></p></td>
<td style="text-align: left;"><p><code>AuthenticatedCipher</code><br />
</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Шифрование блока данных<br />
(без аутентификации и без контроля целостности)<br />
ГОСТ Р 34.13-2015 CTR</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>Cipher(CTR)</code> /
<code>Kuznyechik/CTR/NoPadding</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Потоковое шифрование (файл или сокет) с
аутентификацией и контролем целостности<br />
ГОСТ Р 34.13-2015 CTR+CMAC</p></td>
<td style="text-align: left;"><p><code>api</code></p></td>
<td
style="text-align: left;"><p><code>AuthenticatedStream</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Файл или сокет без
аутентификации</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>Cipher.encryptingStream</code> /
<code>CipherOutputStream</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Шифрование буфера с аутентификацией
целостности<br />
(не ГОСТ, но носит рекомендательный характер)</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>MgmCipher</code> /
<code>Kuznyechik/MGM/NoPadding</code></p></td>
</tr>
</tbody>
</table>

### Шифрование буфера

#### org.rssys.gost.api

AuthenticatedCipher — CTR + CMAC (ГОСТ Р 34.13-2015) с аутентификацией и
контролем целостности данных - рекомендуется для большинства задач.

    import org.rssys.gost.api.AuthenticatedCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV генерируется автоматически
    // Формат пакета: [IV (8 байт)] [CMAC от открытого текста (8 байт)] [шифртекст]
    byte[] packet = AuthenticatedCipher.seal(plaintext, key);

    // Расшифрование
    try {
        byte[] decrypted = AuthenticatedCipher.open(packet, key);
    } catch (AuthenticationException e) {
        // CMAC не совпал: данные повреждены или подменены
    } finally {
        key.destroy();
    }

MgmCipher — AEAD без AAD (Как альтернатива AuthenticatedCipher, там тоже
Кузнечик, но режим не строго ГОСТ)

    import org.rssys.gost.api.MgmCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование — ICN генерируется автоматически, шифр "Кузнечик"
    // Формат пакета: [ICN (16 байт)] [шифртекст] [тег (16 байт)]
    byte[] packet = MgmCipher.seal(plaintext, key);

    // Расшифрование
    try {
        byte[] decrypted = MgmCipher.open(packet, key);
    } catch (AuthenticationException e) {
        // Тег не совпал: данные повреждены или подменены
    }

MgmCipher — AEAD с AAD (ассоциированные данные), режим для специфических
задач.

    import org.rssys.gost.api.MgmCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);
    byte[] aad        = "заголовок сообщения".getBytes(StandardCharsets.UTF_8);

    // см. ниже про AAD
    // Шифрование: AAD аутентифицируется, но не шифруется и не включается в пакет
    byte[] packet = MgmCipher.seal(plaintext, key, aad);

    // Расшифрование: AAD должен совпадать с переданным при шифровании
    try {
        byte[] decrypted = MgmCipher.open(packet, key, aad);
    } catch (AuthenticationException e) {
        // Тег не совпал: данные или AAD повреждены / подменены
    } finally {
        key.destroy();
    }

AAD — любые данные (заголовок, метаданные, идентификатор сессии),
которые нужно аутентифицировать вместе с шифртекстом, но не шифровать.

Cipher — CTR без аутентификации

    import org.rssys.gost.api.Cipher;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV (8 байт) генерируется автоматически и включается в начало результата
    // Формат результата: [IV (8 байт)] [шифртекст]
    byte[] encrypted = Cipher.encrypt(plaintext, key, Cipher.Mode.CTR);

    // Расшифрование: IV извлекается автоматически из начала массива
    byte[] decrypted = Cipher.decrypt(encrypted, key, Cipher.Mode.CTR);
    key.destroy();

Режим CTR без аутентификации не защищает от подмены данных. Если
целостность важна — используйте `AuthenticatedCipher` (ГОСТ Р
34.13-2015) или `MgmCipher` (Р 1323565.1.026-2019, рекомендация).

#### JCA (org.rssys.gost.jca)

Kuznyechik/CTR/NoPadding — без аутентификации и контроля целостности
данных

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;
    GostSecretKey key = ...; // выработан ранее

    byte[] plaintext = "данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV (8 байт) генерируется автоматически
    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertext = cipher.doFinal(plaintext);
    byte[] iv         = cipher.getIV(); // 

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] decrypted = cipher.doFinal(ciphertext);
    key.destroy();

- IV необходимо передать получателю вместе с `ciphertext`.

Режим CTR без аутентификации не защищает от подмены данных. Если
целостность важна — используйте `AuthenticatedCipher` /
`AuthenticatedStream` из `org.rssys.gost.api` (ГОСТ Р 34.13-2015) или
`Kuznyechik/MGM/NoPadding` (Р 1323565.1.026-2019).

Kuznyechik/MGM/NoPadding — AEAD без AAD

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] plaintext = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: ICN генерируется автоматически
    Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertext = cipher.doFinal(plaintext); // [шифртекст][тег (16 байт)]
    byte[] icn        = cipher.getIV();            // 

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
    try {
        byte[] decrypted = cipher.doFinal(ciphertext);
    } catch (javax.crypto.AEADBadTagException e) {
        // Тег не совпал: данные повреждены или подменены
    } finally {
        key.destroy();
    }

- ICN необходимо передать получателю вместе с `ciphertext`. В отличие от
  `MgmCipher.seal`, JCA не включает ICN в выходной буфер автоматически.

Kuznyechik/MGM/NoPadding — AEAD с AAD

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] plaintext = "открытые данные".getBytes(StandardCharsets.UTF_8);
    byte[] aad       = "заголовок".getBytes(StandardCharsets.UTF_8);

    // Шифрование
    Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipher.updateAAD(aad);                          // 
    byte[] ciphertext = cipher.doFinal(plaintext);
    byte[] icn        = cipher.getIV();

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
    cipher.updateAAD(aad);                          // 
    try {
        byte[] decrypted = cipher.doFinal(ciphertext);
    } catch (javax.crypto.AEADBadTagException e) {
        // Тег не совпал
    } finally {
        key.destroy();
    }

- `updateAAD` должен вызываться до `doFinal`. AAD при шифровании и
  расшифровании должен совпадать.

### Потоковое шифрование (файл / сокет)

#### org.rssys.gost.api

AuthenticatedStream — предназначен для потокового шифрования
сокета/файла с аутентификацией и контролем целостности данных
(рекомендуется для большинства задач).

    import org.rssys.gost.api.AuthenticatedStream;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;
    import java.io.*;
    import java.nio.file.*;

    SymmetricKey key = ...; // выработан ранее

    // Шифрование файла
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    try (InputStream  in  = Files.newInputStream(src);
         OutputStream raw = Files.newOutputStream(encrypted);
         OutputStream out = AuthenticatedStream.sealing(raw, key)) { // 
        in.transferTo(out);
    }

    // Расшифрование файла
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted);
         InputStream  in  = AuthenticatedStream.opening(raw, key);  // 
         OutputStream out = Files.newOutputStream(decrypted)) {
        in.transferTo(out);
    } catch (IOException e) {
        if (e.getCause() instanceof AuthenticationException) {
            // CMAC чанка не совпал: файл повреждён или подменён
        }
        throw e;
    } finally {
        key.destroy();
    }

- `sealing` записывает заголовок потока и шифрует данные чанками по 64
  КБ. Каждый чанк содержит собственный IV и CMAC — усечение потока
  обнаруживается автоматически.

- `opening` проверяет CMAC каждого чанка до возврата данных вызывающему.

Cipher.encryptingStream / decryptingStream — CTR без аутентификации.

    import org.rssys.gost.api.Cipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.*;
    import java.nio.file.*;

    SymmetricKey key = ...; // выработан ранее

    // Шифрование: IV (8 байт) записывается в поток автоматически первым
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    try (InputStream  in  = Files.newInputStream(src);
         OutputStream raw = Files.newOutputStream(encrypted);
         OutputStream out = Cipher.encryptingStream(raw, key, Cipher.Mode.CTR)) {
        in.transferTo(out);
    }

    // Расшифрование: IV читается из потока автоматически
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted);
         InputStream  in  = Cipher.decryptingStream(raw, key, Cipher.Mode.CTR);
         OutputStream out = Files.newOutputStream(decrypted)) {
        in.transferTo(out);
    } finally {
        key.destroy();
    }

CTR без аутентификации не обнаруживает повреждение или подмену данных.
Для потоков с требованием целостности используйте `AuthenticatedStream`.

#### JCA (org.rssys.gost.jca)

CipherOutputStream / CipherInputStream — CTR без аутентификации и
контроля целостности данных.

    import javax.crypto.Cipher;
    import javax.crypto.CipherInputStream;
    import javax.crypto.CipherOutputStream;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.*;
    import java.nio.file.*;

    GostSecretKey key = ...; // выработан ранее
    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", "RssysGostProvider");

    // Шифрование: IV генерируется автоматически, записываем его явно перед шифртекстом
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] iv = cipher.getIV(); // 
    try (InputStream        in  = Files.newInputStream(src);
         OutputStream       raw = Files.newOutputStream(encrypted)) {
        raw.write(iv);                               // 
        try (OutputStream out = new CipherOutputStream(raw, cipher)) {
            in.transferTo(out);
        }
    }

    // Расшифрование: читаем IV явно из начала потока
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted)) {
        byte[] ivRead = raw.readNBytes(iv.length);   // 
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivRead));
        try (InputStream  in  = new CipherInputStream(raw, cipher);
             OutputStream out = Files.newOutputStream(decrypted)) {
            in.transferTo(out);
        }
    } finally {
        key.destroy();
    }

- JCA не управляет IV автоматически в потоковом API — приложение
  отвечает за запись и чтение IV из потока.

Для потоков с аутентификацией целостности используйте
`AuthenticatedStream` из `org.rssys.gost.api`.

#### JCA MGM (потоковый режим)

**JCA MGM (`Kuznyechik/MGM/NoPadding`) не подходит для больших потоков —
он буферизует весь plaintext в памяти до вызова `doFinal`.**  

Данные не возвращаются до проверки тега — это фундаментальное требование
безопасности, а не ограничение реализации.

Почему так сделан JCA MGM? Если бы мы возвращали plaintext до проверки
тега, то:

1.  Приложение получило бы потенциально поддельные данные до проверки
    целостности.

2.  Это называется "release of unauthenticated plaintext" — классическая
    уязвимость AEAD-реализаций.

3.  Атакующий мог бы манипулировать тем, что приложение обрабатывает,
    даже если тег в итоге не пройдёт.

RFC 9058 явно требует: данные не должны использоваться до успешной
верификации тега.

Используйте `AuthenticatedStream` для больших потоков.

## Хэш-функция Стрибог (ГОСТ Р 34.11-2012)

Стрибог — криптографическая хэш-функция в двух вариантах: 256 бит и 512
бит.

Библиотека предоставляет два независимы API по вызову хеш-функций:

- `org.rssys.gost.api` — прямой API, не требует регистрации провайдера.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API.

Результат хеширования - big-endian (MSB first) массив байт, совместимый
с OpenSSL. RFC 6986 приводит тест-векторы в ГОСТ-нотации (right-to-left)
— байты будут в обратном порядке при прямом сравнении.

### org.rssys.gost.api

Блочный режим хеширования данных. Хешируемые данные целиком в памяти.

    import org.rssys.gost.api.Digest;

    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // Стрибог-256 (ГОСТ Р 34.11-2012), вывод 32 байта
    byte[] hash256 = Digest.digest256(data);

    // Стрибог-512 (ГОСТ Р 34.11-2012), вывод 64 байта
    byte[] hash512 = Digest.digest512(data);

Инкрементальный режим хеширования. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.Digest;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    // Стрибог-256
    Digest h256 = new Digest(Digest.Algorithm.STREEBOG_256);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            h256.update(buf, 0, n);
        }
    }
    byte[] hash256 = h256.digest();

    // Стрибог-512
    Digest h512 = new Digest(Digest.Algorithm.STREEBOG_512);
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            h512.update(buf, 0, n);
        }
    }
    byte[] hash512 = h512.digest();

Экземпляр `Digest` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим хеширования данных. Хешируемые данные целиком в памяти.

    import java.security.MessageDigest;

    // Стрибог-256
    MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256", "RssysGostProvider"); // 
    byte[] hash256 = md256.digest(data);

    // Стрибог-512
    MessageDigest md512 = MessageDigest.getInstance("GOST3411-2012-512", "RssysGostProvider");
    byte[] hash512 = md512.digest(data);

- Алиасы: `"Streebog-256"`, `"1.2.643.7.1.1.2.2"` для 256-бит;
  `"Streebog-512"`, `"1.2.643.7.1.1.2.3"` для 512-бит.

Инкрементальный режим хеширования. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import java.security.MessageDigest;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256", "RssysGostProvider");
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            md256.update(buf, 0, n);
        }
    }
    byte[] hash256 = md256.digest();

## HMAC-Streebog (RFC 7836)

HMAC — код аутентификации сообщений на основе хэш-функции "Стрибог".  
Данная функция требует симметричный ключ.  
В библиотеке представлено два варианта функции: HMAC-Streebog-256 (32
байта) и HMAC-Streebog-512 (64 байта).

### org.rssys.gost.api

Блочный режим вычисления HMAC. Защищаемые данные целиком в памяти.

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // HMAC-Streebog-256
    byte[] mac256 = Digest.hmac256(data, key);

    // HMAC-Streebog-256
    byte[] mac512 = Digest.hmac512(data, key);

    // Проверка целостности — constant-time сравнение (защита от timing-атак)
    boolean ok = CmacApi.verifyMac(expected, mac256);

Инкрементальный режим вычисления HMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    SymmetricKey key = ...; // выработан ранее

    // HMAC-Streebog-256
    Digest m256 = new Digest(Digest.Algorithm.HMAC_256, key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            m256.update(buf, 0, n);
        }
    }
    byte[] mac256 = m256.digest();

    // HMAC-Streebog-512
    Digest m512 = new Digest(Digest.Algorithm.HMAC_512, key);
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            m512.update(buf, 0, n);
        }
    }
    byte[] mac512 = m512.digest();

    // Проверка целостности
    boolean ok = CmacApi.verifyMac(expected, mac256);

    key.destroy();

Экземпляр `Digest` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим вычисления HMAC. Защищаемые данные целиком в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // HMAC-Streebog-256
    Mac mac256 = Mac.getInstance("HmacGOST3411-2012-256", "RssysGostProvider"); // 
    mac256.init(key);
    byte[] result256 = mac256.doFinal(data);

    // HMAC-Streebog-512
    Mac mac512 = Mac.getInstance("HmacGOST3411-2012-512", "RssysGostProvider");
    mac512.init(key);
    byte[] result512 = mac512.doFinal(data);

    key.destroy();

- Алиасы: `"HMAC-Streebog-256"`, `"1.2.643.7.1.1.4.1"` для 256-бит;
  `"HMAC-Streebog-512"`, `"1.2.643.7.1.1.4.2"` для 512-бит.

Инкрементальный режим вычисления HMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    GostSecretKey key = ...; // выработан ранее

    Mac mac256 = Mac.getInstance("HmacGOST3411-2012-256", "RssysGostProvider");
    mac256.init(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            mac256.update(buf, 0, n);
        }
    }
    byte[] result256 = mac256.doFinal();

    key.destroy();

## CMAC-Кузнечик (ГОСТ Р 34.13-2015)

CMAC — имитовставка на основе блочного шифра Кузнечик. Для вычисления
необходим симметричный ключ.  

Полный тег: 16 байт (128 бит = размер блока). Допускается усечение тега.

CMAC строится на блочном шифре (Кузнечик). HMAC строится на хэш-функции
(Стрибог). **Это разные алгоритмы с разной областью применения.**

### org.rssys.gost.api

Блочный режим вычисления CMAC. Защищаемые данные целиком в памяти.

    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // Полный тег CMAC, 16 байт
    byte[] tag = CmacApi.cmac(data, key);

    // Усечённый тег, 8 байт (первые 8 байт полного тега)
    byte[] tag8 = CmacApi.cmac(data, key, 8);

    // Проверка целостности — constant-time сравнение (защита от timing-атак)
    boolean ok = CmacApi.verifyMac(expected, tag);

    key.destroy();

Инкрементальный режим режим вычисления CMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    SymmetricKey key = ...; // выработан ранее

    CmacApi cmac = new CmacApi(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            cmac.update(buf, 0, n);
        }
    }
    byte[] tag = cmac.digest(); // 16 байт

    // Проверка целостности
    boolean ok = CmacApi.verifyMac(expected, tag);

    key.destroy();

Экземпляр `CmacApi` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим вычисления CMAC. Данные целиком находятся в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    Mac mac = Mac.getInstance("CMAC-Kuznyechik", "RssysGostProvider");
    mac.init(key);
    byte[] tag = mac.doFinal(data);

    key.destroy();

Инкрементальный режим вычисления CMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    GostSecretKey key = ...; // выработан ранее

    Mac mac = Mac.getInstance("CMAC-Kuznyechik", "RssysGostProvider");
    mac.init(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            mac.update(buf, 0, n);
        }
    }
    byte[] tag = mac.doFinal();

    key.destroy();

## Выбор алгоритма хеширования и кодов аутентификации

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Сценарий</th>
<th style="text-align: left;">Алгоритм</th>
<th style="text-align: left;">Доступность в API</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Контрольная сумма данных (без
ключа)</p></td>
<td
style="text-align: left;"><p><code>Digest.digest256 / digest512</code></p></td>
<td style="text-align: left;"><p><code>api</code> / JCA
<code>MessageDigest</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Аутентификация данных на основе
хэш-функции Стрибог + симметричный ключ</p></td>
<td style="text-align: left;"><p><code>Digest.hmac256 / hmac512</code>
(RFC 7836)</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA
<code>Mac</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Аутентификация данных, на основе шифра
Кузнечика + симметричный ключ</p></td>
<td style="text-align: left;"><p><code>CmacApi.cmac</code></p></td>
<td style="text-align: left;"><p><code>api</code> / JCA
<code>Mac</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Проверка целостности
(constant-time)</p></td>
<td style="text-align: left;"><p><code>CmacApi.verifyMac</code></p></td>
<td style="text-align: left;"><p><code>api</code></p></td>
</tr>
</tbody>
</table>

## Электронная подпись ГОСТ Р 34.10-2012

Электронная подпись — алгоритм ГОСТ Р 34.10-2012 (RFC 7091).

- в методах **sign/veify** хэш для переданных данных выбирается и
  вычисляется автоматически по параметрам кривой: Streebog-256 для
  256-битных кривых, Streebog-512 для 512-битных.

- Нонс k генерируется детерминированно по RFC 6979 §3.2 (HMAC-Стрибог) —
  одно сообщение + один ключ всегда дают одну подпись.

- Формат подписи: `r ∥ s` big-endian, без DER/ASN.1. Длина: 64 байта
  (256-бит кривые) или 128 байт (512-бит кривые).

Библиотека предоставляет два независимых API для вычисления электронной
подписи:

- `org.rssys.gost.api` — прямой API, не требует регистрации провайдера.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API.

### org.rssys.gost.api

Подпись и проверка подписи для "сырых" данных. В данном режиме, хеш
вычисляется автоматически, внутри методов sign/verify.

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;

    byte[] data = "сообщение для подписи".getBytes(StandardCharsets.UTF_8);

    // Генерация ключевой пары — кривая CryptoPro-A (256 бит)
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());

    try {
        // Подпись: хеш Стрибог-256 вычисляется автоматически для данных data, базируясь на параметрах кривой. То есть отдельно хэш вычислять не нужно.
        // Формат: r ∥ s big-endian, длина 64 байта
        byte[] signature = Signature.sign(data, pair.getPrivate());
        // Проверка подписи. Хэш для data вычисляется внути автоматически.
        boolean valid = Signature.verify(data, signature, pair.getPublic());
        // valid => true
        // Подмена данных обнаруживается
        byte[] tampered = data.clone();
        tampered[0] ^= 0x01;
        boolean invalid = Signature.verify(tampered, signature, pair.getPublic());
        // invalid => false
    } finally {
        pair.getPrivate().destroy(); // обнуляет d в памяти
    }

Импорт закрытого ключа из byte\[\] и подпись

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import java.math.BigInteger;

    byte[] dBytes = ...; // 32 байта закрытого ключа, big-endian
    ECParameters params = ECParameters.cryptoProA();
    PrivateKeyParameters priv = new PrivateKeyParameters(new BigInteger(1, dBytes), params);

    try {
        byte[] signature = Signature.sign(data, priv); // хеш нужной битности вычисляется автоматически
        // ...
    } finally {
        priv.destroy();
        java.util.Arrays.fill(dBytes, (byte) 0); // очистить исходный массив
    }

Импорт открытого ключа из координат и верификация

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.signature.ECPoint;
    import org.rssys.gost.signature.PublicKeyParameters;
    import java.math.BigInteger;

    byte[] qxBytes = ...; // 32 байта координаты Qx, big-endian
    byte[] qyBytes = ...; // 32 байта координаты Qy, big-endian
    ECParameters params = ECParameters.cryptoProA();
    ECPoint q = ECPoint.affine(new BigInteger(1, qxBytes), new BigInteger(1, qyBytes), params);
    PublicKeyParameters pub = new PublicKeyParameters(q, params);

    boolean valid = Signature.verify(data, signature, pub);

Получение открытого ключа из закрытого: Q = d·G

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;

    PrivateKeyParameters priv = ...; // загружен ранее

    try {
        // Вычисляет Q = d·G — скалярное умножение базовой точки
        PublicKeyParameters pub = Signature.derivePublicKey(priv);
        // Полученный ключ можно использовать для верификации
        boolean valid = Signature.verify(data, signature, pub);
    } finally {
        priv.destroy();
    }

### Подпись готового хэша (signHash / verifyHash)

Данные методы используются, когда хэш должен быть вычислен отдельно
(возможно внешней системой: HSM, TSP, CMS), или когда повторное
хэширование нежелательно (большой файл уже хэширован ранее).

Хэш должен соответствовать кривой: Стрибог-256 (32 байта) для 256-битных
кривых, Стрибог-512 (64 байта) для 512-битных. Передача хэша другого
алгоритма (SHA-256, MD5 и т.п.) нарушает требования ГОСТ Р 34.10-2012.

Нонс k генерируется детерминированно по RFC 6979 — идентично
`Signature.sign`.

#### org.rssys.gost.api

Подпись готового хэша

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    byte[] data = "сообщение".getBytes(StandardCharsets.UTF_8);
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
    try {
        // Хэш вычислен заранее
        byte[] hash = Digest.digest256(data); // 32 байта для 256-битной кривой
        // Подпись готового хэша
        byte[] signature = Signature.signHash(hash, pair.getPrivate()); // 64 байта
        // Проверка подписи для хэша
        boolean valid = Signature.verifyHash(hash, signature, pair.getPublic());
        // valid => true
    } finally {
        pair.getPrivate().destroy();
    }

Кросс-совместимость sign ↔ signHash

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.Signature;
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
    try {
        byte[] hash = Digest.digest256(data);
        // sign и signHash дают одинаковый результат для тех же данных
        byte[] sig1 = Signature.sign(data, pair.getPrivate());     // хэш внутри
        byte[] sig2 = Signature.signHash(hash, pair.getPrivate()); // хэш снаружи
        // sig1 и sig2 идентичны побайтово — детерминированность RFC 6979
        Arrays.equals(sig1, sig2) // => true
        // verify и verifyHash взаимозаменяемы
        boolean ok1 = Signature.verify(data, sig2, pair.getPublic());      // 
        boolean ok2 = Signature.verifyHash(hash, sig1, pair.getPublic()); // 
        // ok1 == ok2 == true
    } finally {
        pair.getPrivate().destroy();
    }

- `verify(data, sig)` и `verifyHash(hash, sig)` принимают подписи,
  созданные как через `sign`, так и через `signHash`.

### JCA (org.rssys.gost.jca)

Генерация ключевой пары, подпись и верификация

    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.Signature;
    import java.security.spec.ECGenParameterSpec;

    byte[] data = "сообщение для подписи".getBytes(StandardCharsets.UTF_8);

    // Генерация ключевой пары — кривая tc26-gost-A-256 (256 бит)
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "RssysGostProvider");
    kpg.initialize(new ECGenParameterSpec("tc26-gost-A-256")); // 

    KeyPair pair = kpg.generateKeyPair();

    try {
        // Подпись — хеш Стрибог-256 вычисляется автоматически базируясь на параметрах кривой
        Signature signer = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider"); // 
        signer.initSign(pair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign(); // 64 байта

        // Верификация
        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
        verifier.initVerify(pair.getPublic());
        verifier.update(data);
        boolean valid = verifier.verify(signature);
        // valid => true
    } finally {
        pair.getPrivate().destroy();
    }

- Поддерживаемые имена кривых: `"cryptopro-A"`, `"cryptopro-B"`,
  `"cryptopro-C"`, `"tc26-gost-A-256"` (256 бит); `"tc26-gost-A-512"`,
  `"tc26-gost-B-512"`, `"tc26-gost-C-512"` (512 бит).  
  Инициализация по размеру: `kpg.initialize(256)` → `cryptopro-A`,
  `kpg.initialize(512)` → `tc26-gost-A-512`.

- Для 512-битных кривых используйте `"ECGOST3410-2012-512"`.

Алиасы: OID `"1.2.643.7.1.1.3.2"` (256 бит), `"1.2.643.7.1.1.3.3"` (512
бит).

Импорт закрытого ключа из PKCS#8 DER и подпись

    import java.security.KeyFactory;
    import java.security.PrivateKey;
    import java.security.Signature;
    import java.security.spec.PKCS8EncodedKeySpec;

    byte[] pkcs8Der = ...; // DER-кодирование в формате PKCS#8 PrivateKeyInfo
    KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", "RssysGostProvider");

    PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));

    try {
        Signature signer = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
        signer.initSign(priv);
        signer.update(data);
        byte[] signature = signer.sign();
        // ...
    } finally {
        priv.destroy();
    }

Импорт открытого ключа из X.509 DER и верификация

    import java.security.KeyFactory;
    import java.security.PublicKey;
    import java.security.Signature;
    import java.security.spec.X509EncodedKeySpec;

    byte[] x509Der = ...; // DER-кодирование в формате X.509 SubjectPublicKeyInfo
    KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", "RssysGostProvider");
    PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(x509Der));
    Signature verifier = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
    verifier.initVerify(pub);
    verifier.update(data);

    boolean valid = verifier.verify(signature);

Экспорт ключей в DER для хранения или передачи

    import org.rssys.gost.jca.key.GostECPrivateKey;
    import org.rssys.gost.jca.key.GostECPublicKey;

    // Экспорт открытого ключа — X.509 SubjectPublicKeyInfo DER
    byte[] pubDer = pair.getPublic().getEncoded(); // 

    // Экспорт закрытого ключа — PKCS#8 PrivateKeyInfo DER
    // ВНИМАНИЕ: хранить только в зашифрованном виде
    byte[] privDer = pair.getPrivate().getEncoded(); // 
    try {
        // сохранить privDer ...
    } finally {
        java.util.Arrays.fill(privDer, (byte) 0); // очистить после использования
        pair.getPrivate().destroy();
    }

- `getEncoded()` возвращает `null` если ключ уничтожен (`destroy()` был
  вызван).

### Поддерживаемые кривые

<table style="width:100%;">
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 16%" />
<col style="width: 16%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Имя кривой</th>
<th style="text-align: left;">Стандарт</th>
<th style="text-align: left;">Бит</th>
<th style="text-align: left;">Хэш подписи</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>cryptopro-A</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.2</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>cryptopro-B</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.3</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>cryptopro-C</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.4</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-A-256</code></p></td>
<td style="text-align: left;"><p>RFC 7836, Appendix A.2</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-A-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836, Appendix A.1</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-B-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-C-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
</tbody>
</table>

### Что даёт RFC 6979

Детерминированный k через HMAC-DRBG (HMAC-Стрибог) решает проблему
плохого ГСЧ радикально: k = HMAC-DRBG(закрытый ключ, хеш сообщения).

Свойства:

- Два разных сообщения → два разных k (хеши разные → DRBG даёт разный
  вывод).

- Одно сообщение подписывается всегда одним k → никакой вариативности
  нет.

- `k` не предсказуем без знания закрытого ключа (HMAC — псевдослучайная
  функция).

- Не зависит от качества системного ГСЧ.

## Замечания по безопасности API

- **Очистка ключей** — `SymmetricKey`, `PrivateKeyParameters`,
  `ECDSASigner` реализуют `javax.security.auth.Destroyable`. Вызывайте
  `destroy()` в блоке `finally`.

- **Сравнение MAC** — используйте `verifyMac()` вместо
  `Arrays.equals()`. `verifyMac` использует `MessageDigest.isEqual()` —
  constant-time.

- **IV** — каждый вызов `encrypt()` без явного IV генерирует новый
  случайный IV. Повторное использование IV с одним ключом в CTR/OFB
  нарушает конфиденциальность.

- **Thread-safety** — статические методы всех классов API
  потокобезопасны.

## Замечания по безопасности JCA

- **Закрытые ключи** — `PrivateKeyParameters` реализует `Destroyable`.
  После использования вызывайте `((Destroyable) privateKey).destroy()`.

- **ICN в MGM** — повтор ICN с тем же ключом полностью компрометирует
  защиту. Используйте `ENCRYPT_MODE` без явного ICN: он генерируется
  через `SecureRandom` автоматически.

- **AAD** — `updateAAD` должен вызываться до `update`/`doFinal`. Порядок
  важен.

- **AEADBadTagException** — не кэшируйте данные из потока расшифрования
  до получения этого исключения или успешного завершения.

# Раздел для разработчиков

Для доработки библиотеки необходимо установить OpenJDK 11+, maven.

- `mvn test` — запуск тестов.

- `mvn package` — получение дистрибутива библиотеки.

- `mvn install` — установка дистрибутива библиотеки в локальный .m2.

В папке *bench* созданы примеры кросс-верификации **crypto-gost**,
**BouncyCastle 1.83** и **OpenSSL**.

## Методики бенчмарков

**Все тесты производились на ОС AltLinux p11 x86\_64 с установленным
OpenSSL+ГОСТ.**

### Бенчмарк электронной подписи ГОСТ Р 34.10-2012

Расположение: папка `bench/signature`.

#### Что измеряется

Пропускная способность (ops/s) операций подписания и верификации по ГОСТ
Р 34.10-2012 на двух группах кривых:

- **256-бит** — кривая CryptoPro-A (RFC 4357)

- **512-бит** — кривая TC26-A-512 (RFC 7836)

#### Что сравнивается

**crypto-gost** (низкоуровневый API: `ECDSASigner` + `Streebog256/512`)
против **BouncyCastle** (`ECGOST3410_2012Signer`). Обе библиотеки
используют одну и ту же ключевую пару.

**crypto-gost** использует детерминированный нонс k (RFC 6979 +
HMAC-Стрибог), BouncyCastle — случайный `SecureRandom`. Это влияет на
скорость подписания, но не верификации.

#### Что не входит в измерение

Объекты подписи (`ECDSASigner`, `ECGOST3410_2012Signer`) создаются в
`@Setup` и переиспользуются через `init()`.  

Измеряется только hash-then-sign / hash-then-verify без накладных
расходов на аллокации объектов.

#### Параметры JMH

- 5 итераций прогрева × 2 с.

- 5 итераций замера × 2 с.

- 3 форка JVM.

Итого ~60 с на один режим (256/512) × операцию (sign/verify). Три форка
устраняют JIT-зависимости между запусками.

#### Как воспроизвести

    make build              # сборка uber-jar
    make bench-256 plot     # 256-бит бенчмарк + график
    make bench-512 plot-512 # 512-бит бенчмарк + график
    make bench-all          # оба бенчмарка

#### Как читать графики

Гистограммы показывают среднее значение ops/s, планки погрешностей —
99.9% доверительный интервал JMH.  
Если планки двух столбцов перекрываются — разница статистически
незначима.

### Кузнечик

**Расположение**: Каталог *bench/kuznyechik*

**Запуск:** `make bench`

**Что измеряется:** Пропускная способность симметричного шифрования
Кузнечик (ГОСТ Р 34.12-2015) в режимах CTR и CFB при разных размерах
буфера: 1 КБ, 10 КБ, 100 КБ, 1 МБ. Результат — МБ/с обработанных данных.

**Что сравнивается:** crypto-gost (низкоуровневый API: Ctr/Cfb +
processBytes) против **BouncyCastle** (SICBlockCipher/CFBBlockCipher +
processBytes). Обе библиотеки используют один и тот же ключ и IV,
созданные через KeyGenerator.generateSymmetricKey().

**Что не входит в измерение:** Создание объектов шифра и ключевое
расписание вынесены в @Setup — они выполняются один раз до замера.
Бенчмарк измеряет только время обработки данных, без накладных расходов
на аллокации.

**Как обеспечивается честность:**

- IV инкрементируется на каждой итерации — JIT не может кешировать
  одинаковый результат.

- Входные данные читаются из бинарного файла со случайным содержимым
  (генерируется dd if=/dev/urandom).

- Оба соперника переинициализируют шифр перед каждым вызовом одинаково.

**Параметры JMH:**

5 итераций прогрева × 2 с + 5 итераций замера × 2 с + 3 форка JVM. Итого
~60 секунд на один режим. Три форка устраняют JIT-зависимости между
запусками, 5 итераций дают надёжный доверительный интервал (99.9% CI
выводится автоматически JMH).

**Как воспроизвести:** make data \# генерация тестовых файлов make build
\# сборка uber-jar make bench \# запуск обоих бенчмарков make plot \#
построение графиков (требует gnuplot)

**Как читать графики:** Гистограммы показывают среднее значение MB/s,
планки погрешностей — 99.9% доверительный интервал JMH. Если планки двух
столбцов перекрываются — разница статистически незначима.

## Методики кросс-валидации

Каталог *bench/signature*.

### Кросс-валидация электронной подписи ГОСТ Р 34.10-2012 с BouncyCastle

#### Цель

Подтвердить **совместимость** реализации **crypto-gost** с BouncyCastle
1.83: подписи, выработанные одной библиотекой, должны успешно
верифицироваться другой.

#### Структура

Каждый тест **двунаправленный**:

- `crypto-gost → bc` — crypto-gost подписывает, BC верифицирует.

- `bc → crypto-gost` — BC подписывает, crypto-gost верифицирует.

Покрытие: все 7 стандартных кривых ГОСТ Р 34.10-2012:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Кривая</p></td>
<td style="text-align: left;"><p>Размер</p></td>
<td style="text-align: left;"><p>Стандарт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-256</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-A-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-B-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TC26-C-512</p></td>
<td style="text-align: left;"><p>512-бит</p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
</tr>
</tbody>
</table>

По 100 случайных сообщений на кривую (итого 1400 проверок).

#### Как воспроизвести

    make cross-validate-256  # все 256-бит кривые
    make cross-validate-512  # все 512-бит кривые
    make cross-validate-all  # все 7 кривых

#### Ожидаемый результат

    All 1400 cross-validation checks PASSED. ✓

### Кросс-валидация электронной подписи ГОСТ Р 34.10-2012 с OpenSSL (ГОСТ)

#### Цель

Подтвердить **совместимость** реализации **crypto-gost** с **OpenSSL
3.3.х (ГОСТ)**: подписи, выработанные библиотекой, должны успешно
верифицироваться независимой реализацией OpenSSL..

#### Структура

**Направление:** crypto-gost подписывает → OpenSSL верифицирует.

Покрытие: 3 стандартных кривых ГОСТ Р 34.10-2012:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Кривая</p></td>
<td style="text-align: left;"><p>Размер</p></td>
<td style="text-align: left;"><p>Стандарт</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-A</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-B</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CryptoPro-C</p></td>
<td style="text-align: left;"><p>256-бит</p></td>
<td style="text-align: left;"><p>RFC 4357</p></td>
</tr>
</tbody>
</table>

**Ограничение:** TC26-A-256 и 512-бит кривые не поддерживаются engine
gost на данной системе.

**Алгоритм одного теста:**

1.  Генерируется случайный закрытый ключ (openssl rand -hex 32) и
    случайное сообщение (1 КБ из /dev/urandom).

2.  SignatureTool (crypto-gost) вычисляет публичный ключ Q=d·G и
    экспортирует его в DER SubjectPublicKeyInfo.

3.  SignatureTool подписывает сообщение — формат r||s (big-endian).

4.  Подпись конвертируется в формат OpenSSL engine gost: s||r.

5.  OpenSSL dgst -streebog256 -engine gost -verify верифицирует.

6.  Tamper-тест: XOR первого байта подписи — OpenSSL должен отклонить.

**Формат подписи (важно для совместимости):** crypto-gost : r\_BE ||
s\_BE OpenSSL gost: s\_BE || r\_BE

Скрипт выполняет перестановку автоматически.

#### Как воспроизвести

    make cross-validate-openssl  # 3 кривых 256 бит, требует OpenSSL engine gost

#### Ожидаемый результат

      Сводка:
        Всего проверок:  60
        Пройдено:        60
        Ошибок:          0
        Статус:          УСПЕХ

### Кузнечик

**Расположение**: Каталог *bench/kuznyechik*

**Запуск:**

- `make cross-validate` \# **crypto-gost ↔ BouncyCastle.**

- `make cross-validate-openssl` \# **crypto-gost ↔ OpenSSL** (требует
  OpenSSL 3.x с ГОСТ).

**Цель:** Подтвердить совместимость реализации Кузнечика в
**crypto-gost** с независимыми реализациями (BouncyCastle 1.83 и OpenSSL
3.x), а также дополнительно подтвердить корректность алгоритма через три
независимых источника.

**Структура:** Две независимые кросс-валидации:

1.  **crypto-gost** ↔ **BouncyCastle 1.83**
    (KuznyechikCrossValidation.java)

    Каждый тест двунаправленный:

    - gost→bc: crypto-gost шифрует → BC расшифровывает → сравниваем с
      исходником.

    - bc→gost: BC шифрует → crypto-gost расшифровывает → сравниваем с
      исходником.

      **Режимы**: CTR, CBC/PKCS7, CBC/NoPad, CFB, OFB, MGM (только
      roundtrip, BC не поддерживает MGM).

      **Размеры данных:** 0, 1, 16, 255, 10000 байт — покрывают пустые
      данные, 1 байт, ровно один блок, некратный блоку, большой буфер.

      **Дополнительно:** тест со случайными данными и случайными IV
      через SecureRandom для CTR и CFB — исключает зависимость от
      предсказуемых паттернов.

2.  **crypto-gost** ↔ **OpenSSL 3.x** (cross-validate-openssl.sh)

    Использует KuznyechikTool — CLI-обёртку над crypto-gost API — как
    мост между Java и OpenSSL.

    Каждый тест двунаправленный:

    - openssl → crypto-gost: OpenSSL шифрует файл → KuznyechikTool
      расшифровывает → сравнение.

    - crypto-gost → openssl: KuznyechikTool шифрует файл → OpenSSL
      расшифровывает → сравнение.

      Ключ и IV генерируются случайно через openssl rand на каждый тест.

      **Режимы:** CTR, CBC/PKCS7, CBC/NoPad, CFB, OFB.

      **Совместимость CTR IV:** ГОСТ Р 34.13-2015 определяет CTR IV как
      8 байт, счётчик = IV || 0x00\*8. OpenSSL kuznyechik-ctr принимает
      16-байтный IV и интерпретирует его как начальное значение
      счётчика. Совместимость обеспечена: crypto-gost использует IV8 ||
      0x00\*8, OpenSSL получает тот же 16-байтный вектор — результаты
      шифрования совпадают.

### Методика кросс-валидации: хэш-функции и кода аутентификации (имитовставки)

Кросс-валидация подтверждает корректность реализации путём сравнения
результатов **crypto-gost** с двумя независимыми реализациями:
**BouncyCastle 1.83** и **OpenSSL 3.3.x** с ГОСТ-провайдером.

#### Покрытие

<table>
<colgroup>
<col style="width: 60%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Алгоритм</th>
<th style="text-align: left;">BouncyCastle 1.83</th>
<th style="text-align: left;">OpenSSL 3.x</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Streebog-256 (ГОСТ Р
34.11-2012)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Streebog-512 (ГОСТ Р
34.11-2012)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HMAC-Streebog-256 (RFC 7836)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>HMAC-Streebog-512 (RFC 7836)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CMAC-Кузнечик (ГОСТ Р
34.13-2015)</p></td>
<td style="text-align: left;"><p>18 проверок</p></td>
<td style="text-align: left;"><p>5 проверок</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Итого</strong></p></td>
<td style="text-align: left;"><p><strong>90 проверок</strong></p></td>
<td style="text-align: left;"><p><strong>25 проверок</strong></p></td>
</tr>
</tbody>
</table>

#### Кросс-валидация с BouncyCastle

Для каждого алгоритма и каждого размера сообщения
`{0, 1, 8, 16, 32, 64, 256, 1024, 65535}` байт проверяются два
направления:

- `crypto-gost → BC` — crypto-gost вычисляет тег/хэш, BouncyCastle
  проверяет совпадение.

- `BC → crypto-gost` — BouncyCastle вычисляет тег/хэш, crypto-gost
  проверяет совпадение.

Используется высокоуровневый API: `api/Digest` и `api/CmacApi`.

#### Кросс-валидация с OpenSSL

Для каждого алгоритма и каждого размера сообщения
`{0, 1, 16, 255, 1024}` байт с уникальным случайным ключом (32 байта,
`openssl rand -hex 32`) проверяется направление:

- `crypto-gost → openssl` — crypto-gost вычисляет результат через
  `MacTool`, OpenSSL вычисляет тот же результат независимо, значения
  сравниваются побайтово.

  Команды OpenSSL:

<!-- -->

    # Streebog-256 / Streebog-512
    openssl dgst -streebog256 -r <file>
    openssl dgst -streebog512 -r <file>
    # HMAC-Streebog-256 / HMAC-Streebog-512
    openssl mac -digest streebog256 -macopt hexkey:<KEY> HMAC < <file>
    openssl mac -digest streebog512 -macopt hexkey:<KEY> HMAC < <file>
    # CMAC-Kuznyechik
    openssl mac -cipher kuznyechik-cbc -macopt hexkey:<KEY> CMAC < <file>

#### Требования

- Java 21+

- BouncyCastle 1.83 (`bcprov-jdk18on`)

- OpenSSL 3.x с GOST-провайдером (поддержка `streebog256`,
  `kuznyechik-cbc`)

#### Как воспроизвести

    # Сборка
    cd bench/mac
    make build

    # Кросс-валидация с BouncyCastle (лог: results/cross-validate-bc.log)
    make cross-validate

    # Кросс-валидация с OpenSSL (лог: results/cross-validate-openssl.log)
    make cross-validate-openssl

#### Ожидаемый результат

Все 115 проверок прошли успешно на следующем окружении:

# Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
