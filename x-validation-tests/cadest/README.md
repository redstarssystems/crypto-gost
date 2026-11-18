Семантическая кросс-валидация CMS/CAdES-подписей crypto-gost боевым
инструментом КриптоПро CSP (`cryptcp`). Тест
`CryptoproCAdESCrossValidationTest` строит подписи через crypto-gost и
проверяет их код возврата `cryptcp` (0 — принято, ≠0 — отклонено).

# Уровни проверки

**Ядро** (выполняется всегда, если доступен `cryptcp`) —
`cryptcp -verify -nochain`: семантическая проверка самой CMS-подписи
(алгоритм, дайджест, signedAttrs). Требует лишь установки сертификата
подписанта в личное хранилище `uMy` (тест делает это сам). Доверенный
корень не нужен.

**CAdES opt-in** (только с `-Dcrossval.cryptopro.trustRoot=true`) —
`cryptcp -verify -cadesbes|-cadest|-xlongtype1`: полная проверка
CAdES-атрибутов (signingCertificateV2, метка времени). Эти флаги
игнорируют `-nochain` и всегда строят цепочку до доверенного корня, а
также проверяют статус отзыва. Поэтому тестовый корень ставится в
доверенное хранилище `uRoot` на время прогона и после него снимается
(ниже).

# Предусловия

- КриптоПро CSP (`cryptcp`, `certmgr`) — путь по умолчанию
  `/opt/cprocsp/bin/amd64/`.

- КриптоПро ЭЦП SDK (`libcades`, пакет `cprocsp-pki-cades-64`) — для
  флагов `-cadesbes/-cadest`.

- OpenSSL с ГОСТ — для генерации вспомогательных данных (не обязателен
  для этих тестов).

Переопределение путей: `-Dcryptcp.binary=...`, `-Dcertmgr.binary=...`,
`-Dtsputil.binary=...`.

# Тестовый корень на время прогона

Ключ тестового корня `Crossval Test Root CA` лежит в репозитории
(константа `CA_D` в `CryptoproFixtureGenerator`), поэтому доверять ему
постоянно нельзя: любой, у кого есть репозиторий, выпустит сертификат,
которому ваш КриптоПро поверит. Корень стоит в `uRoot` только на время
прогона.

**Как запускать.** `make crossval-cades` (или `make crossval-full`,
который вызывает его первым):

    make crossval-cades

Эквивалент без make:

    mvn -Pcrossval -pl x-validation-tests/cadest -am -Dexec.skip=true \
        -Dcrossval.cryptopro.trustRoot=true -Dtest='CryptoproCAdES*' test

Ключ `-am` обязателен: без него модуль возьмёт `gost-crossval-utils` из
локального репозитория Maven, и новая сессия установки корня в прогон не
попадёт.

**Флаг `crossval.cryptopro.trustRoot` - единственный барьер.** Окно
подтверждения, которое показывает КриптоПро при установке корня, не
блокирует: `certmgr` его не ждёт и закрывает само. Поэтому защитой
служит только явный флаг. Без него корень не ставится ни тестами, ни
make-целями (кроме `crossval-cades` и `crossval-full`, которые задают
флаг сами). `make crossval` корень не ставит. Запускать только на машине
разработчика, не на боевых машинах.

**Что нужно.** Доступ к графической сессии: переменные `DISPLAY` и
`XAUTHORITY`. Без них установка в `uRoot` невозможна (`certmgr` отвечает
`0x80090020`); тесты отказывают сразу, до вызова `certmgr`, с сообщением
«нет доступа к X-сессии». Из обычного ssh без проброса X это не
работает. Ответ оператора не нужен: тест подаёт `Y` на stdin, но решает
доступ к X-серверу и флаг, а не stdin (установка проходит и при закрытом
stdin). Ключ `-silent` не годится, он даёт `0x80090022`.

**Как это устроено.** `TrustedRootSession` (модуль `crossval-utils`)
ставит корень при первом открытии и убирает при последнем закрытии,
число открытий общее для JVM.

- Корень опознаётся по идентификатору ключа (`keyid`) и точному DER: у
  старого и нового корня с одним ключом `keyid` одинаков, а DER
  различается.

- Корня с этим `keyid` нет - ставим и проверяем, что в хранилище лёг
  ровно наш DER.

- Стоит наш корень, а метки нет (поставлен вручную) - не ставим и не
  удаляем, тесты идут.

- Стоит другой DER под тем же `keyid` или таких сертификатов несколько -
  прогон падает с подсказкой, автоматически ничего не удаляется.

- После снятия корня тест проверяет, что доверие снято: подпись,
  принятая с корнем, больше не принимается (`cryptcp -verify -cadesbes`
  отвечает `0x800B010A`, `-xlongtype1` - `0x200001F9`, так как этот
  режим первым проверяет цепочку метки времени).

- Сбой после начала установки откатывается сразу: корень убирается,
  метка снимается. Метка той же JVM без открытой сессии считается
  собственным сбоем, а не «идёт другой прогон».

- Ошибка установки корня не роняет класс целиком: ядровые CMS-проверки
  идут, а тесты, которым корень нужен, падают с исходной причиной.

**Файл-метка**
`x-validation-tests/.crossval-root-mark.<пользователь>.<keyid>` (вне
`target/`, в `.gitignore`; своя у каждого пользователя, потому что
`uRoot` у каждого свой, и у каждого корня, чтобы два корня одной JVM,
например корень фикстур и корень одноразового УЦ, не принимали метки
друг друга за собственный сбой) пишется до установки и хранит состояние,
DER, PID и время старта процесса. Метка мёртвого процесса - остаток
аварии: следующий прогон убирает корень сам. Метка живого процесса -
другой прогон идёт, отказ. `git clean -xdf` метку удалит: тогда корень,
оставшийся от убитого прогона, будет выглядеть как «поставленный
вручную» - уберите его командой ниже.

**Аварийная очистка и ручные сценарии:**

    make cryptopro-root-status                     # все метки пользователя и состояние корня, ничего не меняет
    make cryptopro-root-remove                     # удалить корень с нашим DER
    make cryptopro-root-remove ROOT_ARGS=--force   # при нескольких сертификатах с этим keyid
    make cryptopro-root-remove ROOT_ARGS=--force-live  # снять корень и под ЖИВЫМ прогоном (сломает его тесты)
    make cryptopro-root-install ROOT_ARGS=--yes    # поставить и оставить (для ручных сценариев)

Если эти команды не нужны, достаточно штатного
`certmgr -delete -store uRoot -keyid <keyid>`; при нескольких
сертификатах с одним `keyid` удаляйте по отпечатку (`-thumbprint`).

Сертификат подписанта, сертификат TSA и CRL тест ставит в `uMy`
автоматически. После прогона он убирает их по идентификатору ключа (не
по имени) и проверяет, что своих сертификатов и CRL не осталось; ошибки
удаления не глотаются. Кроме того, хранилища `uMy` и `uRoot`
сравниваются со снимком до прогона (множество строк вывода
`certmgr -list` в памяти): лишнее значит остаток, пропавшее значит задет
чужой сертификат; в сообщениях только числа. Сертификаты пользователя не
трогаются и не выводятся.

## Отзыв подписанта в `-xlongtype1`

В режиме `-xlongtype1` КриптоПро проверяет отзыв сертификата подписанта
только по OCSP-ответу, встроенному в сообщение (CRL для конечного
сертификата не используется, загрузка запрещена). Поэтому фикстура
выпускает делегированного OCSP-ответчика
(`CryptoproFixtureGenerator.buildOcspResponder`) с EKU `OCSPSigning` и
расширением `id-pkix-ocsp-nocheck`, а `buildOcsp` подписывает им ответ о
листе. Сертификат ответчика лежит в самом ответе и дополнительно указан
в `CompleteCertificateRefs` и `certificate-values` (иначе КриптоПро
сообщает, что сертификат проверки подписи не найден среди упомянутых
значений). Корень должен стоять в `uRoot` на время проверки: без него
шлюз падает ошибкой построения цепочки. В тестах его ставит сессия (см.
«Тестовый корень на время прогона»).

## Файлы КриптоПро и политика свежести

Файл, созданный КриптоПро (`-sign` или `-enhance` с `-xlongtype1`),
хранит цепочку TSA только во вложенном `certificate-values` сигнатурного
штампа, а сертификат делегированного OCSP-ответчика - только во внешнем
`certificate-values`. Проверка `crypto-gost` использует их как
недоверенные кандидаты. Если для промежуточного УЦ в файле лежит CRL,
выпущенный до подписи, политика `STRICT` его отвергает; для такой
проверки задайте `ETSI_DEFAULT`.

## Готовый вектор X Long, созданный КриптоПро

Файлы `crypto-gost-pkix/src/test/resources/cryptopro_xlong/`
(`xlong.p7s`, `data.txt`, `root.cer`) - detached CAdES-X Long Type 1,
созданный `cryptcp -sign -xlongtype1 -cadestsa` ключом из контейнера
КриптоПро. Сертификат подписанта выпущен тестовым УЦ фикстур (срок до
2045 года), закрытого ключа и персональных данных в файлах нет.
`CryptoproCreatedXLongVectorTest` проверяет его в `STRICT` и
`ETSI_DEFAULT` без КриптоПро, поэтому обычный `mvn test` не требует
человека.

Как вектор получен (повторять нужно только при смене фикстур):

1.  `cryptcp -createrqst -rdn "CN=Crossval CryptoPro Signer,O=crypto-gost,C=RU" -provtype 80 -hashalg 1.2.643.7.1.1.2.2 -sg -ku -exprt -cont '\\.\HDIMAGE\xlong_signer' signer.req`
    (интерактивно: датчик случайных чисел).

2.  Сертификат по запросу выпускает тестовый УЦ (`GostCsrParser`,
    `GostCertificateBuilder`) с `ocspResponder` и
    `crlDistributionPoints` на локальный HTTP-сервер.

3.  Локальный сервер отдаёт TSA, OCSP и CRL на тестовом УЦ. Условия, без
    которых КриптоПро не создаёт подпись:

    - без `-nochain` - с `-nochain` КриптоПро вообще не обращается к
      OCSP (`0x800B010E`);

    - в OCSP-ответе `CertID` обязан повторять хеш запроса: первый запрос
      идёт с SHA-1, дальше со Стрибогом; при несовпадении `cryptcp`
      падает с SIGSEGV в `CResponse::Import`;

    - у сертификата TSA должны быть `crlDistributionPoints` и OCSP в
      AIA;

    - кешированный ответ (`cache.sto`) нужно удалять между попытками.

4.  `cryptcp -sign -f signer.cer -autocont -xlongtype1 -cadestsa http://127.0.0.1:18080/tsp -pin ... -detached -silent data.txt data.p7s`.

Вектор содержит один удостоверяющий центр (подписант выпущен корнем).
Форму с промежуточными УЦ и CRL описывает следующий раздел.

## Готовый вектор X Long с промежуточными УЦ

Файлы
`crypto-gost-pkix/src/test/resources/cryptopro_xlong_intermediate/`
(`xlong.p7s`, `root.cer`, `signer-ca.cer`, `tsa-ca.cer`) - CAdES-X Long
Type 1, созданный `cryptcp -enhance -xlongtype1 -enhall -cadestsa`
поверх CAdES-BES, подписанного crypto-gost. Контейнер КриптоПро и
закрытый ключ не нужны: `-enhance` добавляет штампы, ссылки и значения
отзыва, подпись подписанта остаётся нашей. Сообщение attached, потому
что `-enhance` не принимает detached.

Иерархия: корень `Crossval Test Root CA` выпускает два промежуточных
УЦ - `Crossval Signer CA` (для подписанта и его OCSP-ответчика) и
`Crossval TSA CA` (для службы штампов и её OCSP-ответчика). Источники
отзыва разведены по звеньям, иначе форма вектора теряется:

<table>
<colgroup>
<col style="width: 40%" />
<col style="width: 20%" />
<col style="width: 40%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Сертификат</p></td>
<td style="text-align: left;"><p>OCSP</p></td>
<td style="text-align: left;"><p>CRL</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>подписант</p></td>
<td style="text-align: left;"><p>да</p></td>
<td style="text-align: left;"><p>нет</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>промежуточные УЦ</p></td>
<td style="text-align: left;"><p>нет</p></td>
<td style="text-align: left;"><p>CRL корня
<code>/crl/root.crl</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>служба штампов</p></td>
<td style="text-align: left;"><p>да</p></td>
<td style="text-align: left;"><p>CRL
<code>Crossval TSA CA</code></p></td>
</tr>
</tbody>
</table>

CRL корня выпущен за сутки до запуска сервера, то есть раньше штампа
подписи. Поэтому `ETSI_DEFAULT` файл принимает, а `STRICT` отвергает с
причиной `REVOCATION_EVIDENCE_OUT_OF_WINDOW` для промежуточного УЦ
подписанта. Свежесть проверяется на `escTimeStamp`, который записан в
файл, поэтому тест не зависит от текущей даты.
`CryptoproCreatedXLongIntermediateVectorTest` проверяет это без
КриптоПро.

Ограничение вектора: сервер кладёт промежуточный УЦ службы штампов в
каждый токен, поэтому он есть и в `escTimeStamp`, и во вложенных
значениях `signature-time-stamp`. Размещение «только во вложенных
значениях соседнего токена», как у файлов реальных служб штампов, этот
вектор не воспроизводит; такую форму покрывает
`CAdESXLongTsaIntermediateFromOtherTokenTest`.

Как вектор получен (повторять нужно только при смене фикстур). Контейнер
КриптоПро не создаётся, а сертификаты ставятся командой
`certmgr -silent`. Корню фикстур нужно стоять в `uRoot` на время
генерации: поставьте его перед шагами
(`make cryptopro-root-install ROOT_ARGS=--yes`, нужна X-сессия) и
снимите после (`make cryptopro-root-remove`).

1.  Сервер и фикстуры лежат в `CryptoproIntermediateFixtures`,
    `CryptoproVectorServer` и `CryptoproIntermediateVectorTool`. Классы
    собирать вместе с зависимостями из реактора:
    `mvn -Pcrossval -pl x-validation-tests/cadest -am test-compile -Dexec.skip=true`.
    Ключ `-am` обязателен: без него модуль возьмёт `crypto-gost-pkix` из
    локального репозитория Maven, а устаревший jar даёт другое
    кодирование (лишний `NULL` в `AlgorithmIdentifier`, `countryName`
    как UTF8String), и КриптоПро отвечает ошибкой ASN1. Инструмент
    запускать с `crypto-gost-pkix/target/classes` и
    `crypto-gost-core/target/classes` в classpath.

2.  `CryptoproIntermediateVectorTool prepare <каталог>` выпускает
    сертификаты (корень берётся из `cryptopro-fixtures/ca.cer`, корень
    поставлен на время генерации) и пишет `attached.p7s`. Сообщение
    содержит `signingTime` и не содержит `NULL` в трёх служебных
    `AlgorithmIdentifier` (`digestAlgorithms`, `digestAlgorithm` и
    `signatureAlgorithm` подписанта): без этого `cryptcp -enhance`
    отвечает `0x80093101`.

3.  Поставить сертификаты (неинтерактивно): промежуточные УЦ и
    сертификаты OCSP-ответчиков в `uCA`, сертификат службы штампов в
    `uMy`: `certmgr -install -store uCA -file signer-ca.cer -silent`
    (так же `tsa-ca.cer`, `signer-ocsp.cer`, `tsa-ocsp.cer`) и
    `certmgr -install -store uMy -file tsa.cer -silent`.

4.  `CryptoproIntermediateVectorTool serve <тот же каталог>` поднимает
    TSP, OCSP и CRL на `127.0.0.1:18080`.

5.  Удалить `cache.sto`
    (`/var/opt/cprocsp/users/<пользователь>/stores/cache.sto`) и
    выполнить
    `cryptcp -enhance -xlongtype1 -enhall -cadestsa http://127.0.0.1:18080/tsp attached.p7s`.

6.  Удалить временные сертификаты из `uCA` и `uMy`.

Условия, без которых КриптоПро не создаёт подпись:

- OCSP-ответ несёт сертификат ответчика: иначе `ResponderID` строится по
  имени УЦ, а подписывает ключ ответчика, и проверка подписи падает
  (`0x80090006`). КриптоПро сам убирает сертификат при сохранении в
  `revocation-values`;

- имена кодируются по RFC 5280: `countryName` - PrintableString, иначе
  разбор OCSP-ответа падает с `0x80093101`;

- nonce из запроса возвращается в ответе, `CertID` повторяет хеш
  запроса;

- промежуточный УЦ службы штампов кладётся в токен (`addChainCert`),
  промежуточные УЦ и ответчики дополнительно стоят в `uCA`.

# Эталонная подпись КриптоПро для диагностики (не нужна для тестов)

Тесты репозитория не используют ключи КриптоПро: X Long подписывает
crypto-gost, а КриптоПро только проверяет. Сертификат с ключом в
хранилище КриптоПро нужен лишь для разбора расхождений, когда
`cryptcp -sign -xlongtype1` сам создаёт эталонную подпись (например,
через локальный TSA). Создание интерактивное: датчик случайных чисел
показывает окно, поэтому `-silent` даёт `0x80090022`.

Самоподписанный сертификат создаётся в графическом терминале и
копируется из контейнера в личное хранилище (`-du` = `uMy`); команды
проверены только по справке `--help` инструментов, само создание
выполняется вручную:

    /opt/cprocsp/bin/amd64/csptest -keyset -newkeyset -makecert \
        -container '\\.\HDIMAGE\xlong_ref' -keytype exchange -exportable
    /opt/cprocsp/bin/amd64/cryptcp -cspcert -ku -ex -du -cont '\\.\HDIMAGE\xlong_ref'

Затем сертификат ставится в доверенные корни
(`certmgr -install -store uRoot`; это отдельный сертификат, не корень
фикстур) и используется в
`cryptcp -sign -thumbprint <отпечаток> -xlongtype1 -cadestsa <URL> -detached`.
После работы удалить сертификат из `uRoot` и `uMy`
(`certmgr -delete -store ... -thumbprint ...`) и контейнер
(`csptest -keyset -deletekeyset -container xlong_ref -silent`).

Подробный журнал проверки CAdES (причина отказа `0x800B010E` и подобных)
включается командой `cpconfig -loglevel cades -mask 0xffffffff` (записи
идут в journald); после диагностики вернуть `cades` на `0x1`, а
`libcapi20`/`libcapi10` на `0x1` (нулевую маску `cpconfig` не
принимает).

## Готовые векторы BES, T, 512 бит и несколько подписантов

Каталоги `crypto-gost-pkix/src/test/resources/`: `cryptopro_bes/` (BES
attached и detached), `cryptopro_t/` (CAdES-T attached и detached),
`cryptopro_bes512/` (BES на 512 бит), `cryptopro_multisigner/` (BES с
двумя подписантами, attached и detached). Подписи создал `cryptcp`,
сертификаты подписантов выпустил тестовый УЦ по запросам контейнеров
КриптоПро (срок до 2045 года), закрытых ключей и персональных данных в
файлах нет. Тесты `CryptoproCreated*VectorTest` проверяют их без
КриптоПро.

Что не покрыто: T и X Long на 512 бит (нужны 512-битная TSA и
Стрибог-512 в запросах и ответах OCSP), CAdES-T с несколькими
подписантами, CAdES-A.

Как получить векторы (достаточно при смене фикстур). Всё неинтерактивно,
если пароль контейнера задан явно: без `-pin` КриптоПро открывает
графическое окно запроса.

1.  Запрос и контейнер (для 512 бит `-provtype 81` и
    `-hashalg 1.2.643.7.1.1.2.3`):

        cryptcp -createrqst -rdn "CN=Crossval CryptoPro BES Signer,O=crypto-gost,C=RU" \
            -provtype 80 -hashalg 1.2.643.7.1.1.2.2 -sg -ku -exprt \
            -cont '\\.\HDIMAGE\crossval_a1' -pin <пин> signer.req

2.  Сертификат по запросу выпускает `CryptoproCsrIssuer` (выпускает
    корень; кривая УЦ не обязана совпадать с кривой ключа, поэтому
    512-битный подписант допустим под 256-битным корнем). Серийные
    номера задавать разными:

        java -cp <classpath> org.rssys.gost.crossval.cadest.CryptoproCsrIssuer \
            signer.req signer.cer 100 <каталог-состояния>

3.  Привязка к контейнеру и подпись (поиск подписанта по `-thumbprint`:
    `-dn` ищет подстроку и находит несколько сертификатов). Все векторы
    получены без `-nochain`: цепочка подписанта к корню из `uRoot`
    строится и проверяется, а `-norev -nonet` только отключают обращение
    к сети:

        certmgr -inst -file signer.cer -store uMy -container '\\.\HDIMAGE\crossval_a1' \
            -pin <пин> -at_signature
        cryptcp -sign -cadesbes -norev -nonet -thumbprint <SHA-1> -pin <пин> \
            -hashalg 1.2.643.7.1.1.2.2 data.txt bes-attached.p7s
        cryptcp -sign -detached -cadesbes ... data.txt bes-detached.p7s
        cryptcp -addsign -attached -cadesbes ... -thumbprint <SHA-1 второго> multi.p7s
        cryptcp -addsign -detached -cadesbes ... -thumbprint <SHA-1 второго> data.txt multi-detached.p7s

4.  CAdES-T: поднять
    `CryptoproIntermediateVectorTool serve <каталог-состояния>`,
    поставить `tsa-ca.cer` в `uCA`, `tsa.cer` в `uMy`, затем
    `cryptcp -sign [-detached] -cadest -cadestsa http://127.0.0.1:18080/tsp -norev -nonet ...`.
    Сертификат промежуточного УЦ TSA едет внутри токена.

5.  Убрать за собой: `csptest -keyset -deletekeyset`,
    `certmgr -delete -store uMy|uCA -dn ...`.

# Запуск

Только ядро (доверенный корень не нужен):

    mvn -Pcrossval -pl x-validation-tests/cadest test -Dexec.skip=true \
        -Dtest=CryptoproCAdESCrossValidationTest

Полный набор, включая opt-in CAdES (корень ставится на время прогона):

    make crossval-cades

# Ограничения

- CAdES-C (complete-refs) семантически не проверяется: у КриптоПро нет
  отдельного типа `CADES_C` (только BES/T/X-Long/A). Проверяется
  структурно (asn1parse) и собственным верификатором crypto-gost.

- EnvelopedData несовместим на уровне RecipientInfo: КриптоПро
  использует `KeyTransRecipientInfo` (RFC 4490), crypto-gost —
  `KeyAgreeRecipientInfo` (VKO + KExp15). Зашифрованные CMS
  невзаимозаменяемы.
