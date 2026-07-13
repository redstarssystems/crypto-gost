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

**CAdES opt-in** (только с `-Dcryptcp.trustRoot=true`) —
`cryptcp -verify -cadesbes|-cadest`: полная проверка CAdES-атрибутов
(signingCertificateV2, метка времени). Эти флаги игнорируют `-nochain` и
всегда строят цепочку до доверенного корня, а также проверяют статус
отзыва. Поэтому требуется однократная ручная подготовка окружения
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

# Одноразовая настройка доверенного корня (для opt-in)

Тест-CA имеет фиксированный ключ (стабильный отпечаток), поэтому корень
устанавливается один раз.

**Шаг 1. Сгенерировать файл тест-CA** (если ещё нет):

    java -cp <classpath> org.rssys.gost.crossval.cadest.CryptoproFixtureGenerator \
        x-validation-tests/cadest/src/test/resources/cryptopro-fixtures

Создаёт `ca.cer`, `leaf.cer`, `ca.crl`. Для установки корня нужен только
`ca.cer`.

**Шаг 2. Установить `ca.cer` в доверенный корень `uRoot`.** Установка
корня требует интерактивного подтверждения отпечатка, поэтому
выполняется в терминале графической консоли (через ssh с закрытым stdin
не проходит):

    /opt/cprocsp/bin/amd64/certmgr -install -store uRoot -file ca.cer

На вопрос о неподтверждённом отпечатке ответить `y`.

**Шаг 3. Проверить установку** (ожидаемый отпечаток
`d863d977de87e6b5c85e99cb4ec87e714caf27dd`):

    /opt/cprocsp/bin/amd64/certmgr -list -store uRoot | grep -A1 "Crossval Test Root"

CRL и сертификат TSA тест ставит в `uMy` автоматически (и убирает после
прогона).

# Запуск

Только ядро (доверенный корень не нужен):

    mvn -Pcrossval -pl x-validation-tests/cadest test -Dexec.skip=true \
        -Dtest=CryptoproCAdESCrossValidationTest

Полный набор, включая opt-in CAdES (после установки корня):

    mvn -Pcrossval -pl x-validation-tests/cadest test -Dexec.skip=true \
        -Dcryptcp.trustRoot=true -Dtest=CryptoproCAdESCrossValidationTest

# Ограничения

- CAdES-C (complete-refs) семантически не проверяется: у КриптоПро нет
  отдельного типа `CADES_C` (только BES/T/X-Long/A). Проверяется
  структурно (asn1parse) и собственным верификатором crypto-gost.

- EnvelopedData несовместим на уровне RecipientInfo: КриптоПро
  использует `KeyTransRecipientInfo` (RFC 4490), crypto-gost —
  `KeyAgreeRecipientInfo` (VKO + KExp15). Зашифрованные CMS
  невзаимозаменяемы.
