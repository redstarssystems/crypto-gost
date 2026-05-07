# \[0.2.0\] - 08-05-2026

## Изменено

- Рефакторинг проекта. Теперь он мультимодульный:

  - Модуль `crypto-gost` переместился в `crypto-gost-core`. Теперь это
    криптографическое ядро.

- Добавлен новый модуль `crypto-gost-tls`

- Реализован TLS 1.3 (RFC 8446 + RFC 9367): полный handshake
  клиент/сервер, защищённая передача данных, mTLS, PSK session
  resumption, TLSTREE per-record re-keying, OCSP stapling, X.509 chain
  validation. Добавлена поддержка PKCS12.

## Добавлено

### Модуль cryto-gost-core

- Новый метод в Mgm режиме `reinitICN` для реализации TLS 1.3.

- Документация для разработчика теперь crypto-gost-core/README.adoc
  (crypto-gost-core/README.md создается автоматически из asciidoc
  файла).

### Модуль crypto-gost-tls

Новый модуль `crypto-gost-tls13` реализует защищённый протокол TLS 1.3 с
ГОСТ-профилем (RFC 9367). Все криптографические операции выполняются
встроенными средствами библиотеки — без внешних зависимостей.

Поддерживаются:

- Односторонняя аутентификация сервера (основной режим).

- Взаимная аутентификация (mTLS): сервер запрашивает сертификат клиента.

- PSK session resumption (RFC 8446 §2.2): сокращённый handshake по
  сохранённому билету.

- ALPN (RFC 7301): согласование протокола прикладного уровня (HTTP/2,
  HTTP/1.1).

- SNI (RFC 6066): виртуальные хосты на одном IP.

- KeyUpdate (RFC 8446 §4.6.3): обновление ключей трафика без
  перерукопожатия.

Проверка сертификата сервера включает:

- Проверка цепочки сертификатов (BasicConstraints, KeyUsage keyCertSign,
  pathLen) по RFC 5280.

- Distinguished Name: issuer == subject предыдущего сертификата (RFC
  5280 §6.1).

- ExtendedKeyUsage: serverAuth (1.3.6.1.5.5.7.3.1) для сервера,
  clientAuth (1.3.6.1.5.5.7.3.2) для клиента.

- Проверка hostname по SubjectAltName/dNSName с wildcard и IP-адресу
  (RFC 6125).

- OCSP Stapling (RFC 6960): проверка статуса отзыва, подпись
  tbsResponseData.

- Проверка алгоритмической консистентности (RFC 5280 §4.1.1.2).

Оба cipher suite используют per-record рекейинг через TLSTREE (RFC 9367
§4.2).  

Суффикс `_L` (Light): SNMAX = 2^64 − 1 (максимальное число записей до
смены ключа).  

Суффикс `_S` (Strong): SNMAX = 2^42 − 1 (более частая смена ключа).

### Детали реализации (crypto-gost-tls 0.2.0)

#### Безопасность

- Constant-time поиск inner content type (сканирование всего padding
  безусловно) — защита от timing side-channel.

- MGM nonce: MSB первого байта очищается для ICN (RFC 9058 §3, RFC 9367
  §3.3).

- Затирание ключевого материала: destroy() на всех объектах с ключами
  (TlsKeySchedule, TlsTrafficKeys, TlsRecord, HandshakeContext).

- ECDHE-приватный ключ и транскрипт handshake уничтожаются после
  завершения handshake.

- HMAC-ключевой материал затирается после использования (HkdfStreebog,
  KdfGostR3411\_2012\_256).

- Защита от DoS/OOM: записи &gt; 16640 байт (MAX\_CIPHERTEXT\_LENGTH)
  отклоняются до аллокации.

- Защита от flood: не более 8 post-handshake сообщений за один вызов
  read() (MAX\_POST\_HANDSHAKE).

- Максимальный размер сертификата: 256 КБ (MAX\_CERT\_SIZE)

- Constant-time сравнение verify\_data и PSK binders
  (MessageDigest.isEqual).

#### Тестирование

- Known Answer Tests из RFC 9367 Appendix A.1 (L и S варианты) — полный
  key schedule, TLSTREE, AEAD, ECDHE.

- 4 интеграционных теста (self-interop) через реальные TCP-сокеты.

- Фаззинг-тесты для парсеров: TlsMessageParser (8 методов), TlsDerParser
  (3 метода), TlsOcspVerifier (1 метод).

#### Архитектурные решения

- TlsHandshakeEngine — state machine, отвязанная от I/O (для будущего
  модуля JSSE).

- ByteBuffer-перегрузки TlsRecord.protect/unprotect для NIO/JSSE.

- TLSTREE кэш (TlsTreeCache) — пересчёт только изменившихся уровней (RFC
  9367).

- InMemoryTlsTransport.Pair — двунаправленная пара для тестов и
  однопроцессного взаимодействия.

#### Текущие ограничения

- HelloRetryRequest не поддерживается

- 0-RTT, external PSK, pure PSK (без ECDHE) не поддерживаются.

- Delegated OCSP не поддерживается

- DN сравнение: byte-exact DER (не семантическое)

- CertificateRequest.certificate\_authorities не отправляется.

# \[0.1.2\] - 2026-05-01

- Исправлена ошибка в DER-кодировщике. Размер координат точки EC
  определяется модулем поля p, а не порядком группы n. Из-за этого был
  неверный вывод при кодировании. Устранена двойная OCTET STRING обёртка
  закрытого ключа.

- Обновлена версия crypto-gost в тестах и бенчмарках. Теперь выводится и
  используется актуальная.

# \[0.1.1\] - 2026-04-30

- В JCA провайдер добавлен алиас `Kuznyechik/MGM/NoPadding` для режима
  `Kuznyechik-MGM`. Это название более идиоматично для JCA. Добавлен
  соответствующий тест `Kuznyechik/MGM/NoPadding`.

- В документацию README внесены мелкие исправления и уточнения
  формулировок.

- Внесены дополнительные сведения в pom.xml о разработчике, лицензии и
  репозитории.

- Добавлено подписывание jar-файлов моим публичным ключом. В файл `KEYS`
  добавлен мой публичный ключ.

- Добавлены новые методы + тесты к ним + документация:

  - **signHash(byte\[\] hash,PrivateKeyParameters priv)** — подписывает
    готовый хэш. Внутри использует ECDSASigner.generateSignature()
    напрямую, минуя DigestSigner. RFC 6979 детерминизм сохраняется.

  - **verifyHash(byte\[\] hash, byte\[\] signature, PublicKeyParameters
    pub)** — проверяет подпись готового хэша через
    ECDSASigner.verifySignature().

- добавлено обнуление данных dBytes в ECDSASigner.

- добавлен вспомогательный класс **SignatureCodec** для вызова из разных
  мест, чтобы избежать дублирования.

- проведены тесты на кросс-валидацию повторно.

# \[0.1.0\] - 2026-04-28

Начальный выпуск.
