# \[0.6.4\] - 14-07-2026

Данный релиз завершает работу над модулем pkix. Выравнивает и
стабилизирует API, устраняет последние найденные проблемы совместимости
и безопасности, предоставляет набор функций для построения полноценной
PKI инфраструктуры на базе ГОСТ-криптографии. Это первый релиз, где CMS
и CAdES совместимы с Крипто-Про 5. До этого их реализация в crypto-gost
была не рабочей, с нарушениями стандарта. Теперь работосопособность
точно подтверждена тестами кросс-валидации Крипто-ПРО 5 и openssl 3.3.3.

## Модуль crypto-gost-core

### Добавлено

- **Абстракция подписанта `GostSigner` — подпись X.509-объектов без
  извлечения закрытого ключа в память JVM (HSM/PKCS#11/внешний CSP).**

  Ранее единственной точкой подписи был
  `Signature.signHash(hash, PrivateKeyParameters)`, жёстко привязанный к
  сырому ключу в куче приложения. Теперь интерфейс `GostSigner` (пакет
  `org.rssys.gost.api`) отделяет операцию подписи от материала ключа:
  методы `signHash(byte[])`, `getParams()` и `getPublicKey()`.
  Реализация может подписывать внутри аппаратного модуля, а наружу
  возвращать только готовую подпись. Для сценариев без HSM —
  `GostSigner.of(PrivateKeyParameters)`: тонкая реализация поверх ключа
  в памяти, выводящая открытый ключ немедленно (Q = d·G), что сохраняет
  `getPublicKey()` корректным даже после `destroy()`.

- **512-битный VKO ГОСТ Р 34.10-2012 —
  `KeyAgreement.vkoGostR3410_2012_512` (RFC 7836 §4.3.2).**

  Ранее существовал только `vkoGostR3410_2012_256` (KEK на Стрибог-256),
  из-за чего согласование ключа для 512-битных ключей вычислялось
  неверно. Теперь добавлен 512-битный вариант (KEK на Стрибог-512, 64
  байта); общая математика точки вынесена в приватный `computeVko`.
  Нужен для CMS EnvelopedData с 512-битными ключами
  (`id-tc26-agreement-gost-3410-2012-512`, `1.2.643.7.1.1.6.2`).

## Модуль crypto-gost-pkix

### Добавлено

- **X.509-строители принимают `GostSigner` — `GostCertificateBuilder`,
  `GostCrlBuilder`, `GostCsrBuilder`.**

  Ранее билдеры принимали только `PrivateKeyParameters` и
  материализовали ключ издателя в памяти в момент подписи. Теперь
  терминальный `sign(GostSigner)` (и удобная обёртка
  `sign(PrivateKeyParameters)` через `GostSigner.of(priv)`) позволяет
  подписывать внутри HSM/PKCS#11 без извлечения ключа в память JVM.
  Момент связывания подписанта унифицирован (см. раздел «Изменено»).

- **Расширение абстракции `GostSigner` на
  CMS/OCSP/countersignature-строители — `CmsSignedDataBuilder`,
  `GostOcspResponseBuilder`, `CountersignatureBuilder`,
  `GostOcspRequestBuilder`.**

  Ранее эти строители принимали только `PrivateKeyParameters` и вызывали
  `Signature.signHash()` напрямую, без fail-closed self-verify защиты.
  Теперь все они поддерживают `GostSigner` (с сохранением обратной
  совместимости через `GostSigner.of(priv)`), используют
  `signHashChecked()` для мгновенной проверки подписи после сборки, а
  транзитивные строители (`TspResponseBuilder`,
  `CmsSignedAndEnvelopedData`, `CAdESExtender`, `OcspRequestBuilder` из
  jsse) пробрасывают `GostSigner` прозрачно. Теперь вся цепочка
  PKIX-строителей готова к работе с HSM/PKCS#11 без извлечения ключа в
  память JVM.

- **`GostCsrBuilder` — поддержка атрибута `extensionRequest` (PKCS#9
  §5.4.1) и fluent API для запроса расширений X.509v3 в CSR.**

  Ранее `GostCsrBuilder` был чисто статической утилитой, жёстко
  формировавшей пустой атрибутный блок `[0] IMPLICIT SET`. Подписчик не
  мог указать желаемые расширения (SAN, KeyUsage, EKU, BasicConstraints,
  SKI) в генерируемом CSR — эта информация передавалась вне протокола.
  Теперь `GostCsrBuilder` переведён на builder-паттерн с фабричным
  методом `create(String|byte[], PublicKeyParameters)`, консистентно с
  `GostCertificateBuilder` и `GostCrlBuilder`. Fluent-сеттеры
  `.sanDns()`, `.sanIp()`, `.keyUsage()`, `.extendedKeyUsage()`,
  `.basicConstraints()`, `.ski()` и `.additionalExtensions()` позволяют
  подписчику запросить конкретные расширения; при сборке они кодируются
  в атрибут `extensionRequest` (OID 1.2.840.113549.1.9.14) с корректным
  IMPLICIT-тегированием `[0]` (X.690 §8.14). Статические методы
  `buildCsr(priv, pub, dn)` сохранены для обратной совместимости —
  формируют CSR без расширений, побайтово идентично предыдущим версиям.
  `GostOids` пополнен константой `ATTR_EXTENSION_REQUEST`.

  В `GostCsrParser.getExtensions()` добавлен NOTE о границе доверия:
  `extensionRequest` — просьба подписчика, не полномочие; CA обязан
  валидировать запрошенные расширения перед копированием в сертификат
  (проверка владения доменом, контроль `isCA`, полномочия на EKU).

- **Человекочитаемый вывод сертификата и `.p7b` —
  `CertificateTextFormatter.format()` и `GostPkcs7.formatText()`.**

  Ранее для сертификата был только компактный log-safe `toString()` (DN
  усечён до 256 символов, OCSP исключён), а подробного дампа расширений
  не было вовсе. Теперь
  `CertificateTextFormatter.format(GostCertificate)` даёт многострочный
  отчёт с полным DN, сроками, алгоритмом ключа и расшифровкой расширений
  (KeyUsage, EKU, SAN, IAN, AIA, CDP, SKI/AKI, BasicConstraints,
  CertificatePolicies, NameConstraints) на русском языке.
  `GostPkcs7.formatText(byte[])` печатает дамп контейнера `.p7b`
  целиком: сертификаты и метаданные встроенных CRL. Вывод — только
  структурный разбор без криптографической проверки, о чём предупреждает
  первая строка; список отозванных сертификатов CRL показывается лишь
  после `verify()` (fail-closed инвариант `GostCrl`).

  В `GostOids` добавлен метод `displayName(String oid)` — расшифровка
  OID в человекочитаемое имя (неизвестные OID возвращаются в точечной
  нотации). Метод `CmsSignedDataVerifier.parseEmbeddedCrls()` стал
  package-private для переиспользования из `GostPkcs7` без дублирования
  логики разбора `crls [1]`.

- **Поддержка rfc822Name, URI, directoryName, otherName (UPN) в SAN/IAN
  — `GeneralNameCodec`, `GostCertificateBuilder`, `GostCsrBuilder`.**

  Ранее `GostCertificateBuilder` и `GostCsrBuilder` поддерживали только
  dNSName и iPAddress в SubjectAlternativeName и IssuerAlternativeName.
  Парсер `GostExtensionParser` игнорировал остальные типы GeneralName
  (RFC 5280 §4.2.1.6). Теперь добавлены fluent-методы
  `.sanRfc822Name()`, `.sanUri()`, `.sanDirectoryName()`,
  `.sanOtherName()`, `.sanUpn()` (и зеркальные `ian*`) в оба строителя.
  `GeneralNameCodec` дополнен методами `encodeRfc822Name()`,
  `encodeUri()`, `encodeOtherName()` (с корректным
  IMPLICIT-тегированием) и `encodeOtherNameUpn()`. `GostOids` пополнен
  константой `ID_MS_UPN`. Единый record
  `OtherNameEntry(String oid, byte[] valueDer)` используется в write- и
  read-путях.

  Парсер `GostExtensionParser.parseSanGeneralNames()` извлекает все
  шесть типов GeneralName; `parseNameConstraints()` и
  `parseGeneralSubtrees()` обрабатывают rfc822Name, URI и directoryName
  (ограничения otherName по-прежнему дают флаг
  `hasUnsupportedNameType`). `GostCertificate` экспонирует getter’ы для
  всех новых типов: `getSanRfc822Names()`, `getSanUris()`,
  `getSanDirectoryNames()`, `getSanOtherNames()` и зеркальные
  IAN-геттеры. `CertificateTextFormatter` отображает новые типы (EMAIL:,
  URI:, DIRNAME:, OTHERNAME:{oid}).

  `ChainValidator` пересмотрен: для rfc822Name/URI/directoryName
  добавлен полноценный enforcement в `checkCertAgainstConstraints()`;
  для otherName — fail-closed: если NameConstraints содержат
  неподдерживаемый тип (otherName), а лист сертификата имеет otherName в
  SAN, цепочка reject-ится; если лист не имеет otherName — только
  WARNING (ограничения не применимы).

- **Расширение `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1) при выпуске
  сертификатов — `GostCertificateBuilder.ocspNoCheck()`.**

  Ранее пометить сертификат делегированного OCSP-респондера расширением
  `id-pkix-ocsp-nocheck` можно было только вручную через
  `additionalExtensions(byte[])`, самостоятельно кодируя DER. Теперь
  доступен типизированный fluent-метод `.ocspNoCheck()` (extnValue —
  `OCTET STRING` с вложенным `NULL`, non-critical), чтение через
  `GostCertificate.hasOcspNoCheck()` и отображение строки «OCSP No
  Check» в `CertificateTextFormatter`. Метод `buildTbs()` выполняет
  fail-closed-проверку: без EKU `id-kp-OCSPSigning` вызов отвергается
  (`IllegalStateException`) — защита от постановки расширения на
  сертификат, не являющийся OCSP-респондером. `OcspVerifier` при
  принятии делегированного responder-сертификата пишет WARNING, если у
  делегата есть точка проверки отзыва (CDP или AIA-OCSP), но отсутствует
  `id-pkix-ocsp-nocheck` (аномалия RFC 6960 §4.2.2.2.1); решение
  доверять при этом не меняется. `GostOids` пополнен константой
  `EXT_OCSP_NOCHECK`.

- **`GostCertificateBuilder.generateSerial()` и `.randomSerial()` —
  хелперы генерации случайного серийного номера сертификата.**

  Ранее умолчание `serial = BigInteger.ONE` порождало сертификаты с
  постоянным serial=1, если разработчик забывал вызвать явный
  `.serial(...)` — нарушение уникальности пары (issuer, serial) и
  требование CA/Browser Forum BR §7.1 (≥64 бит энтропии). Статический
  `generateSerial()` возвращает положительный `BigInteger` со 128 битами
  CSPRNG-вывода (127 бит эффективной энтропии, bitLength == 128
  детерминированно), пригодный для прямой передачи в `.serial()`.
  Fluent-метод `.randomSerial()` — тонкий делегат, сокращающий типовой
  вызов до одного звена цепочки. Явная установка серийного номера
  обязательна (см. раздел «Изменено»).

- **CertificatePolicies — fluent-сеттеры и поддержка CPS-квалификатора в
  `GostCertificateBuilder` и `GostCsrBuilder`.**

  Ранее расширение CertificatePolicies (RFC 5280 §4.2.1.4) можно было
  задать только через статический метод
  `buildCertificatePoliciesExtension(String[])` с последующей передачей
  сырых DER-байтов в `additionalExtensions()` — единственное расширение
  в билдере, не имевшее типизированного fluent-сеттера. CPS-квалификатор
  `id-qt-cps` (1.3.6.1.5.5.7.2.1) не кодировался и не читался — парсер
  `GostExtensionParser` извлекал только `policyIdentifier` OID,
  игнорируя `policyQualifiers`. Теперь доступны fluent-методы
  `.certificatePolicies(String... policyOids)` (только OID) и
  `.certificatePolicyInfos(CertificatePolicy... policies)` (OID +
  опциональный CPS-URI) в `GostCertificateBuilder` и `GostCsrBuilder`.
  Новый record `CertificatePolicy(String policyOid, String cpsUri)` —
  единообразный write/read тип по образцу `OtherNameEntry`. Парсер
  `GostExtensionParser` извлекает CPS-квалификатор из `policyQualifiers`
  и заполняет новое поле `certPolicies` в `ExtensionsResult`;
  `GostCertificate` экспонирует getter `getCertificatePolicyInfos()`.
  `CertificateTextFormatter` отображает CPS-URI. Старый API
  `buildCertificatePoliciesExtension(String[])` и
  `additionalExtensions()` сохранены для обратной совместимости.
  `ChainValidator` не затронут — CPS-квалификатор чисто информационный
  (RFC 5280 §4.2.1.4).

- **`GostCertificateBuilder.fromCsrIdentity(GostCsrParser, ECParameters)`
  — безопасный выпуск сертификата из CSR: копирование DN и ключа с
  обязательной проверкой proof-of-possession.**

  Ранее мост между разбором CSR (`GostCsrParser`) и построением
  сертификата (`GostCertificateBuilder`) отсутствовал. Разработчик УЦ
  был вынужден вручную (~30 строк) перекладывать subject DN и открытый
  ключ из CSR в билдер, рискуя потерять байтовую точность DN при
  перекодировке через строку (смена типа ASN.1-строки с
  PrintableString/BMPString на UTF8String, потеря multi-valued RDN) или
  пропустить proof-of-possession (`verifySelf()`). Теперь статическая
  фабрика `fromCsrIdentity` принимает распарсенный CSR и возвращает
  предзаполненный `GostCertificateBuilder`: байтово-точно копирует
  subject DN (через новый `GostCsrParser.getSubjectDnDer()`) и открытый
  ключ заявителя, fail-closed проверяет `verifySelf()` с типизированной
  ошибкой `PkixException.Reason.SIGNATURE_INVALID`. Расширения CSR не
  копируются — решение об их переносе остаётся за УЦ.

- **`GostCsrParser.getSubjectDnDer()` — доступ к сырым DER-байтам
  subject DN из CSR для байтово-точного переноса в сертификат.**

  Ранее `GostCsrParser` сохранял только строковое представление DN после
  парсинга (`getSubjectDn()`), а сырые DER-байты терялись в
  конструкторе. Пересборка DN через
  `GostDnParser.encodeDn(getSubjectDn())` меняла тип ASN.1-строки
  (PrintableString/BMPString → всегда UTF8String), теряла multi-valued
  RDN и падала на неизвестных OID. Теперь геттер `getSubjectDnDer()`
  возвращает
  `Arrays.copyOfRange(certData, subjectDnOff, subjectDnOff + subjectDnLen)`
  — байтово-идентичный исходному DER.

- **Удобные методы срока действия в `GostCertificateBuilder` и
  `GostCrlBuilder` — `notBeforeNow()`, `validForDays/Months/Years(int)`,
  `thisUpdateNow()`, `nextUpdateDays/Months/Years(int)`.**

  Ранее для задания срока действия сертификата требовалось вручную
  форматировать строку в формате GeneralizedTime (`"YYYYMMDDHHMMSSZ"`)
  или использовать `Instant`-арифметику:
  `.notBefore(Instant.now()).notAfter(Instant.now().plusSeconds(3600L * 24 * 365))`.
  Теперь доступны удобные fluent-методы:
  `.notBeforeNow().validForDays(365)` — строитель сам вычисляет
  `notBefore` с буфером clock skew 5 мин (`GostOids.CLOCK_SKEW_MS`) и
  `notAfter` через указанный срок. `validForMonths`/`validForYears`
  используют календарную арифметику UTC (31 января + 1 месяц → 28/29
  февраля). Симметрично для CRL: `.thisUpdateNow().nextUpdateDays(30)`.
  Вспомогательный парсер `parseAsn1Time()` и форматтер
  `UTC_TIME_FORMATTER` вынесены из `GostCertificateBuilder` в
  `GostSignatureHelper` для переиспользования между сертификатным и
  CRL-строителями, устранения дублирующего форматтера
  `GENERALIZED_TIME_FORMATTER` и унификации форматирования
  `notBefore(Instant)`/`notAfter(Instant)` с
  `thisUpdate(Instant)`/`nextUpdate(Instant)`.

- **`GostOcspRequest` и `GostOcspResponse` — `fromPemOrDer()`,
  `toPem()`, `getEncoded()` для симметрии PEM-API с сертификатами, CRL и
  CSR.**

  Ранее оба класса поддерживали только DER: `fromDer(byte[])`, а
  конструкторы не сохраняли исходный массив — не было ни `getEncoded()`,
  ни PEM-методов. Прикладной код был вынужден обходить это через прямые
  вызовы `GostPemUtils.pemToDer()` / `GostPemUtils.toPem()`. Стало:
  `fromPemOrDer(byte[])` (автоопределение PEM/DER по первому байту) и
  `toPem()` с заголовками `OCSP REQUEST` / `OCSP RESPONSE` (конвенция
  OpenSSL), а также `getEncoded()` для получения исходного DER.
  Defensive copy на входе и выходе — единообразно с `GostCertificate`,
  `GostCrl`, `GostCsrParser`.

- **CMS EnvelopedData: поддержка KeyTransRecipientInfo (ktri) —
  расшифровка и сборка.**

  Реализован обязательный по ТК26 §8.2.1 формат KeyTransRecipientInfo
  (тег `0x30`, первый элемент CHOICE без номера). keyEncryptionAlgorithm
  = kuznyechik-kexp15 с параметром VKO-256. Вложенный
  GostR3410-KeyTransport содержит sessionEncryptedKey (KExp15 output, 48
  байт), ephemeralPublicKey (SubjectPublicKeyInfo) и ukm (32 байта).
  Алгоритмический стек — VKO + KExp15 + Кузнечик CTR-ACPKM. Двусторонний
  интероп с КриптоПРО 5.0 и gost-engine подтверждён кросс-валидацией.

- **CMS EnvelopedData: ktri — основной формат, kari — через
  `createKari()`.**

  `CmsEnvelopedDataBuilder.create()` теперь создаёт ktri-сообщения. Для
  KeyAgreeRecipientInfo (RFC 5652 §6.2.2, тег `0xA1`) — явный фабричный
  метод `createKari()`. Расшифровщик автоматически определяет тип по
  тегу.

- **CMS EnvelopedData: имитовставка (OMAC) —
  `CmsEnvelopedDataBuilder.withOmac()`.**

  Включает CMS-профильный режим `kuznyechik-ctr-acpkm-omac` (OID
  `1.2.643.7.1.1.5.2.2`, Mac-and-Encrypt по Р 1323565.1.025-2019
  §8.3.2). CEK разделяется через KDF\_TREE (label="kdf tree",
  seed=ukm\[8..15\]) на ключ шифрования K(1) и ключ имитовставки K(2).
  CMAC(K(2)) вычисляется по открытому тексту; зашифрованная имитовставка
  — 16 байт на продолжении CTR-потока после контента — выносится в
  `unprotectedAttrs [1]` как атрибут `content-mac` (`id-cms-mac-attr` =
  `1.2.643.7.1.0.6.1.1`). UKM контентного шифра — 16 байт (IV\[0..8) |
  kdf\_seed\[8..16). `EnvelopedData.version = 2` (присутствуют
  unprotectedAttrs, RFC 5652 §6.1). При размере данных &gt; 256 КБ —
  `IllegalArgumentException` (ACPKM-рекейинг в данной версии не
  реализован, fail-closed). Расшифровка — `CmsOmacHelper.decrypt()`:
  парсинг `content-mac` из `unprotectedAttrs`, constant-time сравнение
  имитовставки, `AuthenticationException` при несовпадении. Двусторонний
  интероп с КриптоПро 5.0 и gost-engine подтверждён кросс-валидацией.

- **Новый `CmsOmacHelper` — CMS-профильный OMAC (Mac-and-Encrypt, Р
  1323565.1.025-2019 §8.3.2).**

  Реализует сквозной процесс шифрования и проверки: KDF\_TREE-выработка
  ключей, CMAC по открытому тексту, единый CTR-поток для контента и
  имитовставки (continuation, как `gost2015_final_call` в gost-engine),
  constant-time сравнение, wipe ключей. Атрибут `content-mac` кодируется
  через `CmsAttribute.encode()`.

### Изменено

- **BREAKING: OID-константы `GostOids` приведены к RFC 9215 — имена
  теперь соответствуют значениям.**

  Ранее имена вводили в заблуждение: `SIG_WITH_DIGEST_256/512` хранили
  OID открытого ключа (`1.2.643.7.1.1.1.1/.2`), а `SIGN_ALG_256/512` —
  комбинированный signWithDigest (`1.2.643.7.1.1.3.2/.3`), то есть метки
  были перепутаны; значение открытого ключа дублировалось ещё и в
  `CMS_SIGNER_INFO_ALG_256/512`. Теперь единый набор:
  `PUBLIC_KEY_256/512` (OID открытого ключа: SPKI и CMS
  `SignerInfo.signatureAlgorithm`) и `SIGN_WITH_DIGEST_256/512` (X.509
  `signatureAlgorithm`). Значения OID на проводе не изменились;
  исправлены Javadoc и человекочитаемые метки. Требуется правка кода
  потребителей, ссылавшихся на старые имена.

- **`CmsSignedDataVerifier` валидирует `SignerInfo.signatureAlgorithm`
  (fail-closed, защита от algorithm-confusion).**

  Ранее поле `signatureAlgorithm` подписанта не читалось вообще —
  подпись проверялась ключом сертификата независимо от заявленного
  алгоритма. Теперь OID проверяется: допускаются оба легитимных
  семейства (OID открытого ключа `1.2.643.7.1.1.1.1/.2`, как у
  КриптоПро/openssl/данной библиотеки, и signWithDigest
  `1.2.643.7.1.1.3.2/.3`, как у BouncyCastle), а объявленная битность
  (256/512) обязана совпадать с кривой ключа сертификата — иначе отказ.
  Форма параметров (NULL или отсутствие) не проверяется строго, чтобы не
  ломать совместимость.

\+ Ранее `CtrAcpkmMode` выполнял чистый CTR без переразвёртывания ключа,
что приводило к расхождению гаммы с gost-engine и КриптоПро для данных
больше размера секции. Теперь ключ переразвёртывается каждые N байт:
4096 по умолчанию (ГОСТ-дефолт, PBES2/PKCS12/JCA) и 256×1024 для CMS
EnvelopedData (как в gost-engine). Для PBES2-сценария (данные &lt; 4 КБ)
поведение идентично предыдущим версиям — рекейинг не срабатывает.

\+ Добавлен реестр констант `AcpkmSectionSize` (`DEFAULT = 4096`,
`CMS = 256 * 1024`) с Javadoc-обоснованием каждого значения. Статические
методы `encryptOnly`/`decryptOnly`/`encryptWithMac`/`decryptWithMac`
получили перегрузки с параметром `sectionSize`; существующие сигнатуры
делегируют с дефолтом 4096 и сохраняют обратную совместимость. Валидация
`sectionSize` — обязан быть кратен 16 (размер блока Кузнечика, RFC 8645
§6.2.1). В
`CmsOmacHelper`/`CmsEnvelopedDataBuilder`/`CmsEnvelopedDataDecryptor`
CMS-путь использует `AcpkmSectionSize.CMS`. `GostCtrAcpkmCipherSpi`
включает рекейинг с дефолтным размером секции 4096 (ранее был warning
без рекейинга).

- **Добавлены публичные статические `deriveContentKeys` и `computeCmac`
  в `CtrAcpkmMode`.**

  KDF\_TREE-деривация ключей K(1)/K(2) из CEK (label="kdf tree",
  seed=ukm\[8..15\]) и чистый CMAC Кузнечика (ГОСТ Р 34.13-2015 §5.1)
  вынесены для переиспользования в CMS-OMAC хелпере (`CmsOmacHelper`) и
  других подсистемах. Методы `encryptWithMac`/`decryptWithMac` (inline
  Encrypt-then-MAC для PKCS12) не затронуты.

- **`CmsKeyWrap` — интерфейс принимает явный IV параметр.**

  Методы `wrap(cek, kek, ukm, iv)` и `unwrap(wrappedCek, kek, ukm, iv)`
  теперь принимают IV отдельно от UKM. IV вычисляется по формуле ТК26:
  `UKM[25..24+n/2]` (последние 8 байт 32-байтного UKM). Ранее IV был
  первыми 8 байтами UKM — ошибка для 32-байтного UKM. KDF\_TREE (KEG)
  seed = `UKM[16..24]`, label = "kdf tree" (R 1323565.1.020-2018);
  VKO-множитель = `BE(UKM[0..16])`.

- **`CmsEnvelopedDataBuilder` — UKM = 32 байта в kari (было 8).**

  Приведение KeyAgreeRecipientInfo к ТК26: ukm — 32 байта, IV —
  последние 8. Байтовое представление kari-сообщений меняется (breaking
  change).

- **`GostCertificateBuilder` требует явный серийный номер — устранён
  insecure-by-default.**

  Ранее забытый `.serial(...)` молча давал сертификат с серийным номером
  1 (умолчание `BigInteger.ONE`), что нарушало уникальность пары
  (issuer, serial) и делало отзыв через CRL/OCSP неоднозначным. Стало:
  серийный номер — обязательное поле наравне с `publicKey`, `notBefore`,
  `notAfter`; `buildTbs()` бросает `IllegalStateException`, если не
  вызван `.serial(...)` или `.randomSerial()` (RFC 5280 §4.1.2.2 —
  уникальность, CA/Browser Forum BR §7.1 — ≥64 бит энтропии для
  случайных значений). Попутно примеры цепочки сертификатов в README
  модулей переведены с устаревшего `.assembleCert(...)` на актуальный
  `.sign(...)`.

- **X.509-строители выполняют fail-closed-проверку подписи после
  сборки.**

  Ранее возвращённая подпись помещалась в DER без проверки — неисправный
  внешний подписант мог молча выпустить объект с невалидной подписью.
  Теперь после подписи проверяются длина подписи и её соответствие
  открытому ключу подписанта (self-verify); несоответствие приводит к
  немедленному исключению. Поскольку старые перегрузки с
  `PrivateKeyParameters` делегируют через `GostSigner.of(priv)`,
  проверка распространяется и на них — это усиление гарантий, не
  нарушающее совместимость.

- **Дедупликация расширений X.509v3 — `ExtensionsAccumulator`, обрезка
  избыточных overload’ов.**

  Ранее `GostCertificateBuilder` и `GostCsrBuilder` независимо хранили
  13+ одинаковых полей расширений (SAN, KeyUsage, EKU, BasicConstraints,
  CertificatePolicies, SubjectKeyIdentifier, дополнительные расширения)
  и 12 идентичных fluent-сеттеров. Статические строители расширений
  (`buildKeyUsageExtension`, `buildSanExtension` и др.) жили
  исключительно в `GostCertificateBuilder`, и `GostCsrBuilder` вызывал
  их через полное имя класса.

  Теперь общие поля и fluent-сеттеры вынесены в новый публичный класс
  `ExtensionsAccumulator` (пакет `org.rssys.gost.pkix.cert`), который
  используется как делегат в обоих строителях. Все статические строители
  расширений перенесены в `ExtensionsAccumulator`; в
  `GostCertificateBuilder` оставлены прямые делегаты (не дубли, а
  перевызов через ExtensionsAccumulator). SKI вычисляется немедленно в
  обоих строителях через `Digest.digest256` (ранее `GostCsrBuilder`
  использовал boolean-флаг). Добавлена статическая фабрика
  `CertificatePolicy.fromOids(String...)` — устраняет дублирующийся цикл
  создания политик из строковых OID.

  Порядок расширений в DER сертификата изменился: accumulator-расширения
  (SAN, KU, EKU, BC, CP, SKI) теперь идут единым блоком перед
  сертификат-специфичными (IAN, AIA, CDP, FreshestCRL, AKI,
  NameConstraints, ocspNoCheck), а не вперемежку.

  **BREAKING:** четыре избыточные перегрузки статических строителей
  удалены: `buildKeyUsageExtension(byte[])`,
  `buildEkuExtension(String[])`,
  `buildSanExtension(String[], String[])`,
  `buildIssuerAltNameExtension(String[], String[])`. Вызывающий код
  должен добавить явный параметр critical (`false`) или расширить список
  аргументов до полной сигнатуры.
  `buildCertificatePoliciesExtension(String[])` сохранён как удобная
  обёртка над `CertificatePolicy.fromOids(...)`. Обновите код, если
  использовали удалённые перегрузки (затрагивает около 15 точек вызова в
  примерах и тестах).

- **Унифицирован момент связывания подписанта в X.509-строителях —
  единый терминальный `sign(...)` у `GostCertificateBuilder`,
  `GostCrlBuilder`, `GostCsrBuilder`, `GostOcspResponseBuilder`.**

  Ранее подписант связывался по-разному:
  `GostCrlBuilder.create(signer, dn)` требовал его в конструкторе,
  `GostOcspResponseBuilder` — через сеттер `.signer(priv, pub)` перед
  `build()`, а сертификат и CSR — в терминальных `assembleCert(signer)`
  / `buildCsr(signer)`. Стало: у всех четырёх строителей подписант
  передаётся в единый терминальный метод `sign(GostSigner)` /
  `sign(PrivateKeyParameters)`, а `create(...)` несёт только структурные
  данные. Конкретно: `GostCrlBuilder.create(issuerDn)....sign(signer)`;
  `GostOcspResponseBuilder.create(serial)....sign(signer)` (открытый
  ключ подписанта выводится из `signer.getPublicKey()` — отдельный
  аргумент `pub` больше не нужен, что исключает несогласованную пару
  priv/pub); `GostCertificateBuilder....sign(signer)` (двухшаговый путь
  — `buildTbs()` + статический `sign(tbs, signer)` — сохранён);
  `GostCsrBuilder....sign(signer)`.

  **BREAKING:** удалены старые сигнатуры без делегатов —
  `GostCrlBuilder.create(GostSigner|PrivateKeyParameters, dn)`,
  `GostCertificateBuilder.assembleCert(...)` (все перегрузки, включая
  статический `assembleCert(tbs, priv, params)` с задокументированным
  риском рассинхрона `params`/ключа), `GostCsrBuilder.buildCsr(...)`
  (инстансные и статические), `GostOcspResponseBuilder.signer(...)`. Это
  **разовый рефакторинг** , а не смена общей политики проекта.

  Добавлены fail-closed hardening-проверки в момент `sign(...)`:
  `GostCertificateBuilder` сверяет AlgorithmIdentifier из `params`
  (create-time) с `signer.getParams()` — ловит рассинхрон размера
  подписи (256↔512) между TBS и фактическим алгоритмом; `GostCsrBuilder`
  проверяет proof-of-possession — `signer.getPublicKey()` обязан
  совпадать с открытым ключом из `create(...)`, иначе CSR не является
  доказательством владения ключом. Оба несоответствия приводят к
  немедленному `IllegalStateException`.

- **`GostCrlBuilder`: `thisUpdate` по умолчанию фиксируется в момент
  `sign()`, а не создания строителя.**

  Ранее при `create(...)` дефолтный `thisUpdate` вычислялся в
  конструкторе. Стало: при отсутствии явного `.thisUpdate(...)` время
  берётся в момент вызова `sign()`. Между `create()` и `sign()` может
  пройти время (отложенная подпись через HSM-воркер, очередь), и
  `thisUpdate` теперь корректно отражает момент выпуска CRL. Явный
  `.thisUpdate(...)` по-прежнему имеет приоритет.

- **Дайджест messageImprint метки времени выбирается по заявленному
  алгоритму подписанта.**

  Ранее `CAdESExtender` выбирал алгоритм хэширования для messageImprint
  TSP-запроса по длине подписи. Стало: по объявленному `digestAlgorithm`
  из `SignerInfo` (при сборке метки) и по размеру ключа сертификата
  подписанта (при проверке) — критичный параметр берётся из объявленного
  значения, а не выводится из косвенного признака. Неизвестный алгоритм
  в чужом `SignerInfo` даёт `PkixException`.

- **Диспетчеризация Streebog-256/512 сведена к единым fail-closed
  хелперам `GostSignatureHelper`.**

  Ранее выбор дайджеста по OID, размеру ключа или длине хэша был
  продублирован более чем в 15 местах модуля с молчаливым дефолтом на
  Streebog-256 при неизвестном значении. Стало: единые
  `keySizeToDigestOid`, `digestByOid`, `digestAlgByHlen` (и обновлённый
  `doHash`) с явной ошибкой на неподдерживаемый дискриминатор; там, где
  развилка была тавтологичной (`OcspVerifier`), она упрощена до прямого
  значения. Поведение на валидном входе не изменилось (подтверждено
  кросс-валидацией).

### Исправлено

- **KARI (`KeyAgreeRecipientInfo`) в CMS EnvelopedData приведён к RFC
  5652 / ТК26 — kari теперь совместим с эталонными реализациями.**

  Ранее kari не был interoperable и не поддерживал 512-битные ключи
  (проверялся только самосогласованными тестами, маскировавшими баги).
  Исправлено сразу несколько дефектов кодирования: `kari [1]` и
  `originatorKey [1]` кодировались как EXPLICIT вместо IMPLICIT (RFC
  5652 §6.2 объявлен `DEFINITIONS IMPLICIT TAGS`);
  `keyEncryptionAlgorithm` имел обратную вложенность (правильно: внешний
  OID — алгоритм key wrap `kexp15`, параметры —
  `SEQUENCE { agreement-OID }`); поддерживался только 256-битный VKO;
  KEG применял KDF\_TREE безусловно, тогда как для 512-бит VKO-выход (64
  байта) используется напрямую как K\_MAC‖K\_ENC, а KDF\_TREE
  применяется только для 256-бит. Выбор варианта 256/512 — по кривой
  ключа получателя. Расшифровка официального эталонного вектора
  TC26/gost-engine (kari + Кузнечик CTR-ACPKM-OMAC, 512-бит)
  подтверждена побайтово.

  Направление «наш encrypt → наш/OpenSSL decrypt» для `ktri` на
  256-битных ключах подтверждено (self-roundtrip + OpenSSL
  3.3.3/gost-engine). Обратное направление — расшифровка нами внешних
  `ktri` 256-битных контейнеров — также подтверждено: исправлен кофактор
  TC26\_A\_256 с 1 на 4 (ECParameters.cofactor), что устранило
  расхождение VKO с gost-engine/CryptoPro в `computeVko`. Эталонный
  вектор TC26 a231 (ktri-256 Kuznyechik CTR-ACPKM) расшифровывается
  побайтово, тест убран из `@Disabled`. Внешние контейнеры КриптоПро CSP
  5 расшифровываются корректно.

  Обратное направление — шифрование crypto-gost → расшифрование
  КриптоПро CSP 5 — подтверждено на реальном токене для матрицы: ktri и
  kari, с OMAC и без, на данных 1 КБ и 18 МБ (ACPKM-рекейинг, 72 секции
  Kuznyechik CTR-ACPKM). Открытый текст побайтово совпадает с исходным
  во всех 8 комбинациях.

\+ Ранее AlgorithmIdentifier эфемерного ключа в
`GostR3410-KeyTransport`/originator кодировался с каноничным OID кривой
(`GostCurves`), из-за чего `publicKeyParamSet` получателя XchA
(`1.2.643.2.2.36.0`) подменялся на CryptoPro-A (`1.2.643.2.2.35.1`). Это
нарушало Р 1323565.1.025-2019 §8.4.2.2 (представление эфемерного ключа
обязано в точности совпадать с сертификатом) и приводило к отказу
расшифрования в КриптоПро CSP (`0x80090019`). Стало: AlgorithmIdentifier
берётся из сертификата получателя дословно (новый
`GostCertificate.getSpkiAlgorithmId()`), меняется только точка ключа.
Проверено на реальном токене КриптоПро и двусторонней кросс-валидацией с
gost-engine.

- **`CmsEnvelopedDataBuilder` — корректная `EnvelopedData.version` по
  RFC 5652 §6.1 (совместимость с КриптоПро CSP).**

  Ранее `version` жёстко кодировалась как 3 для обоих форматов (ktri и
  kari), что нарушает RFC 5652 §6.1 (значение 3 зарезервировано под
  `pwri`/`ori`) и приводило к отклонению контейнера КриптоПро CSP.
  Стало: `version = 0` для ktri (все RecipientInfo version 0,
  issuerAndSerialNumber), `version = 2` для kari (KeyAgreeRecipientInfo
  не version 0, без `pwri`/`ori`) и для ktri+OMAC (присутствуют
  `unprotectedAttrs`).

- **`CmsEnvelopedDataDecryptor` — приём BER indefinite-length в
  `encryptedContent` (совместимость с КриптоПРО CMS 5.0).**

  Ранее `decryptContent` требовал строго primitive `[0]` с
  definite-length (`0x80`) и не расшифровывал контейнеры КриптоПРО, где
  `encryptedContent` закодирован как constructed `[0]` с
  indefinite-length (`A0 80 ... 00 00`), в том числе с сегментированным
  OCTET STRING. Стало: ветвь `0x80` (DER crypto-gost) сохранена без
  изменений, добавлена ветвь `0xA0` со сбором и склейкой октетов через
  новый `DerCodec.collectImplicitOctets` (принимает
  `0x04`/`0x24`/`0xA0`, definite и indefinite, с рекурсией по вложенным
  сегментам); прочие теги — fail-closed `PARSE_ERROR`. Кодирование не
  менялось — crypto-gost по-прежнему выпускает DER definite-length.

- **`Kexp15CmsKeyWrap` — IV для KExp15/KImp15: последние 8 байт UKM
  (было первые 8).**

  Ранее метод `Arrays.copyOf(ukm, 8)` использовал первые 8 байт UKM как
  IV, что несовместимо с ТК26 (формула UKM\[25..24+n/2\]) для
  32-байтного UKM. При 8-байтном UKM разницы не было (bug was masked).

- **`TspRequestBuilder` больше не переиспользует nonce между вызовами
  `build()`.**

  Ранее `getNonce()` лениво генерировал nonce и кэшировал его в поле —
  повторный `build()` на том же строителе выпускал два TSP-запроса с
  одинаковым nonce, ослабляя защиту от replay (RFC 3161). Стало: в
  авто-режиме nonce генерируется заново на каждый `build()`;
  `getNonce()` до `build()` бросает `IllegalStateException` —
  симметрично `GostOcspRequestBuilder`. Явно заданный через `nonce(...)`
  (и opt-out `nonce(null)`) сохраняется между сборками намеренно.

- **`CertChainBuilder` — корректное построение цепочки при ротации
  ключей CA.**

  Ранее issuer искался только по Subject DN и брался первый попавшийся:
  при наличии двух CA с одинаковым DN, но разными ключами (перевыпуск с
  новым ключом) выбор мог пасть на неверный сертификат, и легитимная
  цепочка не строилась (`SIGNATURE_INVALID`). Стало: среди всех
  кандидатов одного Subject DN приоритет отдаётся тому, чей SKI
  совпадает с AKI подписываемого сертификата (RFC 5280 §4.2.1.1), затем
  перебираются остальные — до первого с верной подписью. Обнаружение
  петель вынесено на уровень глубины, чтобы перебор кандидатов не
  подменял `SIGNATURE_INVALID` ложным `CHAIN_LOOP`. Полный backtracking
  по нескольким путям в область изменения не входит.

- **`ChainValidator.validateChainWithRevocation` — правдивый лог
  проверки отзыва.**

  Ранее финальная запись «validation with revocation passed» выводилась
  безусловно, даже когда все элементы `revocationData` были `null` и ни
  одна проверка отзыва фактически не выполнялась, — это вводило в
  заблуждение при аудите логов. Стало: лог отражает число реально
  выполненных и пропущенных проверок (`checked`/`skipped`). Поведение
  (fail-closed при обнаружении отзыва) не изменилось.

- **`GostPkcs12Builder` — согласованный учёт длины `friendlyName`.**

  Ранее длина проверялась в байтах UTF-8 (лимит 64), тогда как атрибут
  кодируется в BMPString (UTF-16BE), вдвое длиннее для ASCII, — проверка
  не соответствовала фактическому размеру. Стало: лимит меряется в
  байтах UTF-16BE (128 байт = 64 символа), совпадая с реальным
  кодированием; прежний бюджет для ASCII-имён сохранён.

- **CMS `SignerInfo.signatureAlgorithm` — корректный OID алгоритма
  подписи с NULL-параметрами (совместимость с КриптоПро/OpenSSL).**

  Ранее `CmsSignedDataBuilder` и `CountersignatureBuilder` записывали в
  `SignerInfo.signatureAlgorithm` комбинированный signWithDigest-OID
  (`1.2.643.7.1.1.3.2/.3.3`) без параметров — как в X.509-сертификате.
  Собственный верификатор и BouncyCastle/OpenSSL это поле не проверяют
  строго, поэтому дефект не проявлялся, но КриптоПро отвергал подпись с
  `0x80090008` «Invalid algorithm specified». Стало: в CMS
  `SignerInfo.signatureAlgorithm` пишется OID открытого ключа
  (`1.2.643.7.1.1.1.1` для 256, `1.2.643.7.1.1.1.2` для 512) с
  параметрами `NULL` — согласно RFC 4490 §3.2 и де-факто эталонным
  реализациям. Подписи CMS/CAdES-BES/CAdES-T теперь семантически
  принимаются КриптоПро (проверено кросс-валидацией
  `cryptcp -verify`/`-cadesbes`/`-cadest`). X.509-путь
  (`GostSignatureHelper`) не затронут — там signWithDigest-OID без
  параметров корректен по RFC 9215.

- **CMS `digestAlgorithm` — обязательные NULL-параметры у алгоритма
  хэширования.**  
  Ранее `CmsSignedDataBuilder`, `CountersignatureBuilder`,
  `CAdESAttributes` (signingCertificateV2) и `CAdESCompleteData`
  (complete-refs) кодировали `AlgorithmIdentifier` дайджеста как
  `SEQUENCE { OID }` без поля параметров. Стало:
  `SEQUENCE { OID, NULL }` — поле параметров присутствует и содержит
  `NULL`, как требует Р 1323565.1.025 §4.1/4.2 для OID
  `id-tc26-gost3411-2012-256/512` и как формирует эталонный openssl
  gost-engine. Затрагивает `SignedData.digestAlgorithms`,
  `SignerInfo.digestAlgorithm`, `ESSCertIDv2.hashAlgorithm` и
  `OtherHashAlgAndValue`. Форма закреплена структурным регресс-тестом.

- **Исправлен кофактор кривой TC26\_A\_256 с 1 на 4 — расшифровка
  внешних ktri-256 контейнеров.**  
  Ранее `ECParameters.TC26_A_256.cofactor` был равен 1, из-за чего
  `computeVko` вычислял `scalar = d * 1 * ukm mod n`.
  `gost_ec_point_mul` в gost-engine/CryptoPro применяет кофактор 4 для
  этой кривой, поэтому shared-точка и, как следствие, KEK расходились с
  эталоном. Расшифровка внешних `ktri`-256 контейнеров от КриптоПро и
  OpenSSL завершалась ошибкой `Invalid MAC during CEK unwrap`. Стало:
  cofactor = 4, VKO выдаёт KEK, совпадающий с gost-engine побайтово.
  Двусторонний интероп `ktri`-256 подтверждён на контейнерах КриптоПро
  CSP 5 и OpenSSL 3.3.3.

# \[0.6.3\] - 08-07-2026

Данный релиз заполняет пробелы в API и делает доработки необходимые для
создания разработчиками собственного УЦ. То есть библиотека теперь даёт
строительные блоки для реализации "CA-as-Code"/УЦ-как-код".

## Модуль crypto-gost-core

## Модуль crypto-gost-pkix

### Добавлено

- **Метод `addCrl(GostCrl)` в `CmsSignedDataBuilder` — встраивание CRL в
  SignedData (поле `crls [1]`, RFC 5652 §5.1).**

  Ранее билдер поддерживал только встраивание дополнительных
  сертификатов (`addCertificate()`). Теперь поддерживается выбор `crl`
  из `RevocationInfoChoice` (RFC 5652 §10.2.1); OCSP-ответы (`other`) не
  поддерживаются. CRL сортируются в DER-порядке (X.690 §11.6),
  аналогично сертификатам.

- **Верификатор `CmsSignedDataVerifier` возвращает встроенные CRL в
  результатах проверки.**

  Поле `crls [1]` разбирается с DoS-защитой (лимиты `MAX_EMBEDDED_CRLS`
  и `MAX_EMBEDDED_CRLS_TOTAL_SIZE` в `CmsConstants`).
  `GostCrl.fromDer()` вызывается без `verify()` — revoked-список не
  извлекается на этом этапе. CRL доступны через `embeddedCrls()` в
  `VerifiedSignedData` и `MultiSignerVerifiedData`. В `CAdESExtender`
  поле `crls [1]` сохраняется как opaque при перекодировании.

- **Перегрузка
  `GostPkcs7.buildCertsOnly(List<GostCrl>, GostCertificate...)` для
  встраивания CRL в certs-only .p7b-контейнеры.**

  Старый метод `buildCertsOnly(GostCertificate...)` — обёртка над новым
  с пустым списком CRL. `extractCertificates()` корректно работает при
  наличии `crls [1]` в контейнере (поле сертификатов на фиксированном
  индексе, CRL не мешает разбору).

- **Автоматическая проверка отзыва в `CmsSignedDataVerifier` —
  `verifyAnyWithRevocationCheck` и `verifyAllWithRevocationCheck`.**

  Методы проверяют статус отзыва каждого сертификата цепочки по embedded
  CRL из SignedData и опционально по внешним CRL через `CrlVerifier`
  (проверка подписи CRL, срока, issuer DN и статуса отзыва). Приоритет
  поиска: embedded, затем внешние. Delta CRL и partial/indirect CRL
  пропускаются при подборе. При отсутствии подходящего CRL проверка
  пропускается (best-effort, warn). Если CRL есть, но невалиден или
  сертификат отозван — `PkixException` (fail-closed). `trustedCerts`
  обязан быть непустым. Базовые `verifyAny`/`verifyAll` сохраняют
  обратную совместимость — без проверки отзыва.

- **Поддержка `byKey` responder ID в OCSP —
  `GostOcspResponseBuilder.withResponderByKey()`,
  `GostOcspResponse.getResponderIdType()` и `getResponderKeyHash()`,
  проверка byKey в `OcspVerifier`.**

  Ранее билдер формировал только `byName [1]` (subject DN подписанта), а
  парсер отклонял ответы с `byKey [2]` (хэш публичного ключа), выдавая
  `PkixException`. Теперь поддерживается CHOICE ResponderID согласно RFC
  6960 §4.1.1: по умолчанию byName (обратная совместимость), опционально
  byKey через Streebog-256/512. RFC 5019bis рекомендует byKey для
  высоконагруженных сред. Хэш Streebog — ГОСТ-конвенция, распознаётся
  только ГОСТ-клиентами; для универсальной совместимости используйте
  byName.

  Константа `TAG_CTX_CONSTRUCTED_2 = 0xA2` добавлена в `DerCodec`
  (core), метод `GostDerCodec.encodeSpkiKeyValue(PublicKeyParameters)` —
  в core.

- **Делегированный CRL-подписант — `CrlVerifier.verifyDelegated()`.**

  Ранее CRL верифицировался только ключом CA. Теперь поддерживается
  делегированный CRL-подписант (RFC 5280 §6.3.3): CRL подписывается
  отдельным ключом с битом `cRLSign` в KeyUsage. `verifyDelegated()`
  сначала пробует ключ CA (fast path), при неудаче перебирает
  сертификаты подписантов, проверяя срок, `isCrlSigner()` и цепочку
  подписи к CA (симметрично делегированному OCSP-responder в
  `OcspVerifier`). Три перегрузки: с `minCrlNumber` (защита от CRL
  rollback), с настраиваемыми лимитами размера и числа записей. cRLSign
  у CA в прямом пути — defence-in-depth (LOG warning, не reject).

- **`GostCertificate.isCrlSigner()` — проверка `cRLSign` KeyUsage.**

  Метод возвращает `true`, если KeyUsage отсутствует (без ограничений)
  или содержит бит `cRLSign` (0x02). Парсинг бита добавлен в
  `GostExtensionParser` и `ExtensionsResult`. Используется в
  `verifyDelegated()` для валидации сертификатов подписантов.

- **Парсинг IssuingDistributionPoint в `GostCrl` — `isIdp()`,
  `isIndirectCrl()`, `isOnlyContainsUserCerts()`,
  `isOnlyContainsCACerts()`.**

  Ранее любое присутствие IDP-расширения (2.5.29.28) вызывало
  `PkixException(IDP_NOT_SUPPORTED)`. Теперь IDP парсится: извлекаются
  флаги `onlyContainsUserCerts`, `onlyContainsCACerts`, `indirectCRL`.
  Добавлены четыре публичных метода. Реджектится только
  `indirectCRL=true` — indirect CRL не поддерживается.

- **`GostCrlBuilder.withIdpExtension(boolean, boolean)` — IDP с
  флагами.**

  Перегруженный метод принимает `onlyContainsUserCerts` и
  `onlyContainsCACerts`. Старый `withIdpExtension()` без аргументов
  сохраняет поведение — пустой IDP (все флаги false). Добавлен
  статический метод `buildIdpExtension()` для прямого кодирования IDP
  SEQUENCE согласно RFC 5280 §5.2.5.

- **Fluent-построитель NameConstraints в `GostCertificateBuilder`.**

  Ранее NameConstraints можно было только читать из сертификатов (парсер
  в `GostExtensionParser` и enforcement в `ChainValidator`), но не
  создавать программно. Добавлены: instance-метод
  `.nameConstraints(permittedDns, permittedIps, excludedDns, excludedIps)`
  для fluent-цепочки, static-метод `buildNameConstraintsExtension(...)`
  для самостоятельной DER-сборки и
  `GeneralNameCodec.encodeIpConstraint(String cidr)` для кодирования
  iPAddress в формате адрес+маска (8/32 байта). Расширение всегда
  critical (RFC 5280 §4.2.1.10), min/max не поддерживаются
  (`ChainValidator` режектит). IP-ограничения принимаются в CIDR-нотации
  (`"192.168.1.0/28"`).

- **Поддержка `caIssuers` в `GostCertificateBuilder` — fluent-сеттер и
  статический построитель AIA-расширения.**

  Ранее `GostCertificateBuilder` позволял указать только OCSP-URI в
  AIA-расширении (`.ocspResponder(uri)` и
  `buildAiaOcspExtension(String)`). Указать caIssuers URI для
  автодостройки цепочки было нельзя — парсер и геттер
  `GostCertificate.getCaIssuersUris()` существовали, но API записи
  отсутствовало. Теперь добавлены: fluent-сеттер `.caIssuer(uri)`,
  константа `CA_ISSUERS_AD` в `GostOids` и единый статический метод
  `buildAiaExtension(ocspUri, caIssuersUri)`, поддерживающий все
  комбинации — только OCSP, только caIssuers или оба в одном экземпляре
  расширения (требование RFC 5280 §4.2). Старый метод
  `buildAiaOcspExtension` удалён.

- **Чтение FreshestCRL в `GostCrl` (`isFreshestCrl()` /
  `getFreshestCrlUris()`) и публичный
  `GostCertificateBuilder.buildFreshestCrlExtension()`.**

  Ранее FreshestCRL (2.5.29.46, RFC 5280 §5.2.6) был write-only:
  `GostCrlBuilder.withFreshestCrl()` кодировал расширение, но `GostCrl`
  при парсинге молча пропускал его — ни геттеров, ни разбора. Теперь
  добавлены `isFreshestCrl()` и `getFreshestCrlUris()`, структура
  DistributionPoint парсится через `GostExtensionParser.parseCdpUris`
  (идентична CDP). Публичный
  `GostCertificateBuilder.buildFreshestCrlExtension()` позволяет
  кодировать расширение отдельно, симметрично `buildCdpExtension()`.
  Добавлены round-trip и фаззинг-тесты.

- **FreshestCRL: fluent-сеттер `GostCertificateBuilder.freshestCrl()` и
  read-path `GostCertificate.getFreshestCrlUris()` — симметрично
  `crlDistributionPoints`/ `getCdpUris()`.**

  Ранее FreshestCRL (2.5.29.46, RFC 5280 §5.2.6) на сертификатной
  стороне был write-only: расширение можно было закодировать только
  через generic `additionalExtensions(buildFreshestCrlExtension(...))`,
  а при парсинге сертификата URI молча игнорировались (не было ни поля в
  `ExtensionsResult`, ни геттера в `GostCertificate`). Теперь добавлены:
  fluent-сеттер `.freshestCrl(uri1, uri2)`, автоматическая запись в
  сертификат через `buildTbs()`, парсинг в `GostExtensionParser` через
  существующий `parseCdpUris()` (структура DistributionPoint идентична
  CDP), поле `freshestCrlUris` в `ExtensionsResult` и геттер
  `getFreshestCrlUris()` в `GostCertificate` с SSRF-предупреждением (со
  ссылкой на `SsrfGuard` и `JdkHttpCrlFetcher`). Добавлены unit-тест
  парсинга и round-trip тест builder → parser.

- **AuthorityKeyIdentifier в построителе и парсере CRL —
  `GostCrlBuilder.withAki()` и `GostCrl.getAuthorityKeyIdentifier()`
  (RFC 5280 §5.2.1).**

  Ранее AKI-расширение в CRL отсутствовало в обе стороны:
  `GostCrlBuilder` не умел его кодировать, `GostCrl` не умел парсить.
  Теперь добавлены fluent-методы `withAki(byte[])` и
  `withAki(PublicKeyParameters)` (переиспользуют
  `GostCertificateBuilder.buildAkiExtension()`), геттер
  `getAuthorityKeyIdentifier()` и парсинг `parseAkiExtension()` внутри
  `GostCrl` (локальное дублирование паттерна `GostExtensionParser`,
  нулевой риск регрессии для сертификатов). Параметр `caPriv` в
  `GostCrlBuilder` переименован в `signerPriv` — построитель подписывает
  CRL любым переданным ключом, без привязки к роли CA. Добавлены
  round-trip, фаззинг и кросс-валидационные (openssl) тесты.

- **Метод `ChainValidator.validateChainWithRevocation` — валидация
  цепочки + проверка отзыва в одном вызове.**

  Ранее разработчик должен самостоятельно вызывать
  `ChainValidator.validateChain()`, затем `CrlVerifier` или
  `OcspVerifier` отдельно. Теперь вызов
  `validateChainWithRevocation(chain, trustedKeys, revocationData)`
  делает PKIX-валидацию и проверку CRL/OCSP за один шаг. Данные отзыва
  передаются через новый record `CertRevocationData`; приоритет OCSP над
  CRL — по RFC 5280. Pull-модель (готовые данные, без сети) — для
  fetch-модели с OCSP/CRL-фетчерами, настраиваемыми лимитами и
  nonce-проверкой используйте
  `GostX509TrustManager.validateChainWithOcsp()`.

- **Поддержка IssuerAltName (2.5.29.18, RFC 5280 §4.2.1.7) — парсер,
  строитель и геттеры.**

  Ранее расширение IssuerAltName нигде не обрабатывалось: парсер
  `GostExtensionParser` молча пропускал его (non-critical) или режектил
  сертификат (critical), строитель `GostCertificateBuilder` и
  `GostCertificate` не предоставляли доступа. Теперь добавлены:
  константы `EXT_IAN` в `GostOids` и `IAN_OID_BYTES` в `GostDerParser`,
  парсинг в `GostExtensionParser` (через переиспользование
  `parseSanGeneralNames` — структура GeneralNames идентична SAN), поля
  `ianDnsNames`/`ianIpAddresses` в `ExtensionsResult`, геттеры
  `getIssuerAltNameDnsNames()`/`getIssuerAltNameIpAddresses()` в
  `GostCertificate`, fluent-сеттеры `ianDns()`/`ianIp()` и статический
  метод `buildIssuerAltNameExtension()` в `GostCertificateBuilder`.
  IssuerAltName полностью изолирован от hostname-верификации
  (проверяется только SAN по RFC 6125) и от построения/валидации цепочек
  (только DN-матчинг по RFC 5280 §6.1).

- **`GostCertificate.getExtensions()` и `hasExtensions()` — bulk-доступ
  к расширениям X.509v3 через единый объект
  `GostExtensionParser.ExtensionsResult`.**

  Ранее конструктор парсил расширения в `ExtensionsResult` и
  распаковывал в ~30 индивидуальных полей, но структурированный
  результат выбрасывался как локальная переменная. Для чтения расширений
  требовалось вызывать 64+ именованных геттера (`getSanDnsNames()`,
  `getKeyUsageBits()`, `getEkuOids()`, …) — каждый по отдельности. В
  отличие от `GostCsrParser.getExtensions()`, возвращающего весь набор
  расширений одним вызовом — асимметрия API. Стало: парсенный
  `ExtensionsResult` сохраняется в поле; публичные методы
  `getExtensions()` и `hasExtensions()` — зеркало CSR-паттерна. Javadoc
  предупреждает о границе доверия: автокопирование расширений при
  перевыпуске небезопасно — короткий срок сертификатов в CA/Browser
  Forum введён для периодической переаттестации (владение доменом,
  полномочия на EKU, статус CA).

- **`GostCertificateBuilder.fromCertificate(GostCertificate, ECParameters)`
  — identity-мост из существующего сертификата для перевыпуска
  (renewal).**

  Ранее зеркало `fromCsrIdentity` для готового сертификата
  отсутствовало: разработчик был вынужден вручную создавать билдер и
  перекладывать subject DN и публичный ключ из `GostCertificate` через
  `getSubjectDnBytes()` и `getPublicKey()`. Стало: статическая фабрика
  `fromCertificate` копирует identity (DN + ключ) в новый билдер.
  Расширения не копируются — оператор обязан явно прочитать их через
  `getExtensions()` и принять решение по каждому типу. Javadoc
  документирует: метод не выполняет криптографическую верификацию
  существующего сертификата — ответственность за доверенный источник на
  вызывающем коде.

- **`GostCertificateBuilder.KeyUsage.isSetIn(int bits)` — проверка флага
  KeyUsage в битовой маске без ручной битовой арифметики.**

  Ранее единственным способом проверить наличие флага в сырой маске
  `keyUsageBits` было ручное выписывание
  `(bits & KeyUsage.X.mask) != 0`, требующее знать точное значение бита.
  Стало: `KeyUsage.DIGITAL_SIGNATURE.isSetIn(ext.keyUsageBits)` —
  инкапсуляция битовой проверки, скрывающая внутреннее `mask`-поле от
  публичного API.

### Исправлено

- **`GostExtensionParser.ExtensionsResult.presentExtensionOids` —
  мутабельный `HashSet` расшарен наружу через
  `GostCsrParser.getExtensions()`.**

  Ранее поле `presentExtensionOids` передавалось в конструктор
  `ExtensionsResult` как `new HashSet<>()` без обёртки — вызывающий код
  через `csr.getExtensions().presentExtensionOids.add(...)` мог
  испортить внутреннее состояние парсера для всех последующих читателей.
  Стало: `Collections.unmodifiableSet()` при конструировании
  `ExtensionsResult` — изменяемая коллекция остаётся внутри
  `GostExtensionParser` для накопления OID, наружу отдаётся неизменяемая
  обёртка. Исправление в одной точке покрывает и
  `GostCsrParser.getExtensions()` (уже отгружен), и новый
  `GostCertificate.getExtensions()`.

- **`verifyAll` пробрасывает оригинальный `Reason` ошибки вместо жёстко
  зашитого `SIGNATURE_INVALID`.**

- **Парсер `GostOcspResponse` исправлен: byKey-ответы (тег `0xA2`)
  больше не отклоняются.**

  Ошибка в проверке тега: принимался только `[0]` (ошибочно) и `[1]`
  (byName), а `[2]` (byKey) отсутствовал. Теперь парсер корректно
  разбирает оба варианта CHOICE ResponderID по RFC 6960.

  Ранее при любой ошибке подписанта в strict-режиме `verifyAll` всегда
  бросал `PkixException(Reason.SIGNATURE_INVALID, ...)`, теряя настоящую
  причину (например, `EXPIRED`, `DN_MISMATCH`, `REVOKED`). Теперь
  используется `e.reason()` — вызывающий код получает точную
  диагностику.

- **`ChainValidator` — опциональная проверка CertificatePolicies
  leaf-сертификата.**

  Добавлен перегруженный метод
  `validateChain(chain, caPublicKeys, requiredPolicyOids)`. Проверяет,
  что leaf-сертификат содержит хотя бы одну из требуемых политик или
  `anyPolicy` (2.5.29.32.0). При отсутствии расширения
  CertificatePolicies или несовпадении выбрасывается `POLICY_VIOLATION`.
  PolicyMappings, PolicyConstraints, InhibitAnyPolicy не реализованы —
  проверяется только конечный сертификат. Старая сигнатура
  `validateChain(chain, caPublicKeys)` сохраняет поведение без проверки
  политик.

- **DoS: защита от crafted TLV с ложной длиной в
  `parseEmbeddedCertificates()` и `parseEmbeddedCrls()`
  `CmsSignedDataVerifier`.**

  `DerCodec.decodeLength()` возвращает задекларированную длину, но не
  проверяет, что она помещается в оставшийся буфер. `Arrays.copyOfRange`
  с `to > src.length` тихо дополняет результат нулями — вход в десятки
  байт мог аллоцировать ~2GB. Добавлена проверка `pos + total > end`
  перед `copyOfRange` в обоих методах.

- **Countersignature (RFC 5652 §11.4) — `CountersignatureBuilder`,
  `CAdESExtender.embedCountersignature()`,
  `CAdESExtender.verifyCountersignature()`,
  `CAdESSignerResult.countersignatures()`.**

  Ранее библиотека поддерживала только уровни CAdES-BES (базовая
  подпись) и CAdES-T (с меткой времени). Теперь добавлена поддержка
  countersignature (RFC 5652 §11.4): вложенный `SignerInfo`,
  подписывающий содержимое октета `signatureValue` родительского
  подписанта. `CountersignatureBuilder` строит countersignature с
  правильным `message-digest` (без `content-type` — RFC 5652 §11.4).
  `CAdESExtender.embedCountersignature()` встраивает countersignature в
  `unsignedAttrs [1]` каждого подписанта, автоматически добавляет
  сертификат countersigner’а в поле `certificates` SignedData.
  `verifyCountersignature()` выполняет полный цикл верификации:
  CMS-подпись + `signingCertificateV2` + метки времени (опционально) +
  countersignature — с построением и валидацией цепочки countersigner’а
  до `trustedCerts` (fail-closed). Метки времени опциональны:
  countersignature может добавляться на CAdES-BES без TSP. Структура
  проверена кросс-валидацией с OpenSSL (`asn1parse`, `dgst -verify`).
  OID `id-countersignature` (1.2.840.113549.1.9.6) зарегистрирован в
  `GostOids`.

- **CAdES-C — атрибуты `complete-certificate-references` /
  `complete-revocation-references` (RFC 5126 §6.2).**

  Ранее библиотека поддерживала уровни CAdES-BES (базовая подпись),
  CAdES-T (с меткой времени) и countersignature, но не имела атрибутов
  полных ссылок на сертификаты и отзыв (CAdES-C). Теперь
  `CAdESExtender.embedCompleteRefs()` встраивает в `unsignedAttrs`
  подписанта два атрибута: `complete-certificate-references` (хэши
  CA-сертификатов цепочки до доверенного корня, SEQUENCE OF OtherCertID)
  и `complete-revocation-references` (хэши CRL и/или OCSP-ответов с
  идентификаторами, SEQUENCE OF CrlOcspRef).

### Изменено

- **IDP-расширение в CRL больше не отклоняется безусловно.**

  Ранее `GostCrl.verify()` выбрасывал `IDP_NOT_SUPPORTED` при любом
  присутствии IssuingDistributionPoint. Теперь IDP парсится: пустой IDP
  (все флаги false) принимается, `indirectCRL=true` — реджект
  (fail-closed). Генерация IDP через `GostCrlBuilder.withIdpExtension()`
  и кодирование через `assembleCrl()` обновлены с хардкоденного пустого
  SEQUENCE на динамическое построение по флагам (`buildIdpExtension()`).

## Модуль crypto-gost-tls13

## Модуль crypto-gost-jsse

# \[0.6.2\] - 06-07-2026

Продолжаем гигиену безопасности после масштабного рефакторинга в 0.6.0.
Этот релиз целиком посвящен устранению оставшихся проблем безопасности.
Релиз вносит небольшой **breaking change**.

## Модуль crypto-gost-core

### Исправлено

- **CTR-ACPKM-OMAC: CMAC вычислялся под ключом шифрования вместо
  MAC-ключа (`CtrAcpkmMode`/`Cmac`).** `CtrAcpkmMode` и внутренний `Cbc`
  в `Cmac` делили один мутируемый `Kuznyechik`-инстанс;
  `cipher.init(encKey)` перезаписывал раундовые ключи после
  `mac.init(macKey)`, и все блочные операции CMAC (`update`/`doFinal`)
  фактически шли под ключом шифрования K(1), а не под MAC-ключом K(2) —
  разделение ключей KDF\_TREE (RFC 9337 §5.1.1) для CMAC не работало.
  Практической подделки тега без знания DK нет (оба ключа — производные
  секреты), но нарушен архитектурный инвариант Encrypt-then-MAC и
  ломается интероп PKCS12/PBES2-OMAC с эталонными реализациями.

  Исправление: `Cmac` теперь получает собственный экземпляр
  `Kuznyechik`, не общий с CTR. Добавлен независимый тест (пересчёт тега
  через проверенные `KdfTreeGostR3411_2012_256` + отдельный `Cmac`) —
  существующие roundtrip-тесты дефект не ловили, так как шифрование и
  проверка использовали один и тот же некорректный путь.

- **Ключевой материал не затирался после
  `CtrAcpkmMode.encryptWithMac()`/ `decryptWithMac()`.** Оба статических
  метода создают `CtrAcpkmMode` (и, внутри, два экземпляра `Kuznyechik`
  — для CTR и для CMAC), но не вызывали `mode.destroy()` после
  использования — раскрытые раундовые ключи (`skHi`/`skLo`) оставались в
  куче до сборки мусора. Оба метода обёрнуты в
  `try/finally { mode.destroy(); }`.

       *Ключевой материал не затирался в `CtrAcpkmMode.decryptOnly()`/`encryptOnly()`.*
      Раскрытые раундовые ключи Kuznyechik оставались в куче до GC. Обёрнуто
      в `try/finally { mode.destroy(); }` — по аналогии с уже исправленной
      OMAC-парой (`encryptWithMac`/`decryptWithMac`).

- **`inputBuffer` не затирался перед сбросом в JCA `CipherSpi`
  (`GostMgmCipherSpi`, `GostCtrAcpkmCipherSpi`, `GostCipherSpi`).**
  Буфер мог содержать накопленный plaintext/ciphertext; `Arrays.fill`
  добавлен перед каждым `inputBuffer = new byte[0]` (7 мест).

- **`DerCodec`: indefinite-length (0x80) молча принимался для
  примитивных типов, вопреки X.690 §8.1.3.6.** Приводило к реальному
  молчаливому мис-парсингу в `parseOid` (усечённый OID без исключения) и
  `parseBoolean` (чтение произвольного байта вместо валидации длины) —
  security-значимо, так как затрагивает разбор algorithm/extension OID и
  флагов вроде `critical`/`cA`. Добавлен общий `decodeDefiniteLength()`,
  применён во всех примитивных парсерах, unified с уже существовавшими
  inline-проверками в `GeneralizedTime`/`UTF8String`.

- **`SignatureCodec.encode()` тихо усекал компоненты подписи `r`/`s` при
  превышении ожидаемой длины поля.** Заменено на явный
  `IllegalArgumentException` (fail-closed) при `length > rolen + 1` —
  защита публичного API от невалидированного внешнего ввода; на текущих
  внутренних вызывающих путях (`r`/`s` уже приведены `mod n`) поведение
  не меняется.

- **`Hmac.init(byte[])` алиасил массив вызывающего без defensive copy, в
  отличие от `init(CipherParameters)` (через `SymmetricKey.getKey()`).**
  Асимметрия контракта публичного API. Эксплуатируемого вектора не
  обнаружено (ссылка на массив не удерживается после `init()`), но
  устранена для симметрии с `init(CipherParameters)` и ясности
  контракта: `initWithKeyBytes` теперь всегда работает с собственной
  копией ключа (`Arrays.copyOf` для короткого пути), безусловно затирает
  её после использования. Мёртвая переменная `hashedCopy` удалена.

## Модуль crypto-gost-pkix

### Добавлено

- **`GostPkcs7.extractCertificates(byte[])` / `(byte[], int)`** —
  публичный API разбора PKCS#7/CMS SignedData (`.p7b`) и извлечения
  вложенных X.509-сертификатов. Автоопределение DER/PEM.
  Распространённый формат обмена сертификатами в РФ-PKI, для которого
  `CmsSignedDataVerifier` неприменим (тот проверяет подписантов и
  требует их наличия). Разбор поля `certificates` вынесен в общий с
  `CmsSignedDataVerifier` метод `parseEmbeddedCertificates`. Лимиты
  `CmsConstants.MAX_P7B_CERTS` = 256 и `MAX_P7B_SIZE` = 10 МиБ защищают
  от DoS.

- **`GostPkcs7.buildCertsOnly(GostCertificate...)` и режим
  `CmsSignedDataBuilder.certsOnly()`** — формирование certs-only
  PKCS#7/CMS SignedData (`.p7b`) без подписантов: контейнер только с
  сертификатами. Зеркальная операция к `extractCertificates`. Структура
  —
  `SignedData { version=1, digestAlgorithms={}, encapContentInfo=id-data без content, certificates[0], signerInfos={} }`;
  поле `certificates` есть `SET OF` и кодируется DER-отсортированным
  (X.690 §11.6). Потолок `MAX_P7B_CERTS`. Кросс-валидация записи
  подтверждена OpenSSL (`pkcs7 -print_certs`) и BouncyCastle
  (`CMSSignedData.getCertificates`).

- **`OcspVerifier`: перегрузки с раздельными ролями RFC 6960** —
  `verify(..., GostCertificate certIdIssuer, GostCertificate responderAuthority, ...)`.
  `certIdIssuer` — источник CertID-хэшей истинного издателя листа;
  `responderAuthority` — authority подписи ответа (прямой ключ или
  издатель делегированного responder’а). Аддитивны: существующие
  перегрузки с одним параметром делегируют с
  `responderAuthority = issuerCert`, поведение не изменилось. Нужны для
  редких легитимных сценариев (плановая смена ключа CA с действующим
  кросс-сертификатом).

### Изменено

- **`GostCrl`: жёстко зашитые `MAX_CRL_SIZE`/`MAX_REVOKED_ENTRIES`
  заменены на настраиваемые лимиты.** Прежние приватные константы 10
  МБ/100 000 не пропускали полный CRL национального УЦ (40 МБ).
  Добавлены `public static final DEFAULT_MAX_CRL_SIZE` = 64 МБ и
  `DEFAULT_MAX_REVOKED_ENTRIES` = 1 000 000, плюс перегрузки
  `GostCrl(byte[], int, int)`, `fromDer(byte[], int, int)`,
  `fromPemOrDer(byte[], int, int)` для явного указания лимитов. Прежние
  однопараметрические конструктор/фабрики делегируют в новые с новыми
  дефолтами — сигнатуры не менялись, изменились только значения по
  умолчанию.

- **`CrlVerifier.verify()`: добавлены перегрузки с явными `maxCrlSize`/
  `maxRevokedEntries`** — для прямого и base/delta CRL. Существующие
  4/5/6-параметрические сигнатуры делегируют в новые с
  `GostCrl.DEFAULT_MAX_CRL_SIZE`/`DEFAULT_MAX_REVOKED_ENTRIES`.

- **`GostExtensionParser.MAX_SAN_ENTRIES` 100 → 512.** Предыдущий лимит
  100 записей не пропускал UCC-сертификаты (Cloudflare/Azure) с 200+
  SAN.

- **`OcspVerifier`: порог свежести `MAX_OCSP_AGE_MS` (для ответов без
  `nextUpdate`) стал конфигурируемым.** В этом же цикле была введена
  константа 24 ч (см. «Исправлено»), но без способа переопределения —
  легитимный CA, выпускающий ответы без `nextUpdate` с фактическим
  сроком годности &gt;24 ч, приводил к отклонению без обхода. По образцу
  `CrlVerifier` добавлена публичная перегрузка
  `verify(byte[], byte[], GostCertificate, byte[] expectedNonce, long maxOcspAgeMs)`;
  существующие перегрузки делегируют в неё с дефолтом
  `GostOids.MAX_OCSP_AGE_MS` (24 ч не изменились). Значение константы 24
  ч сохранено как документированный дефолт.

- **`GostOcspResponseBuilder.noNextUpdate()`** — opt-out, позволяющий
  строить OCSP-ответ без поля `nextUpdate` (RFC 6960 §2.4 — поле
  опционально). Нужен для эмуляции таких CA и тестирования локальной
  политики свежести (`maxOcspAgeMs`); ранее билдер всегда проставлял
  `nextUpdate` (дефолт now + 3 года).

### Исправлено

- **`GostPemUtils.pemToDer` не срезал PEM-заголовки с цифрами в метке.**
  Регекс `PEM_HEADER` был `-----[A-Z ]+-----` (класс символов без цифр),
  поэтому стандартные метки `PKCS7` и `X509 CRL` не вырезались, и дефис
  заголовка попадал в Base64-декодер (`Illegal base64 character 2d`).
  Класс расширен до `[A-Z0-9 ]+` — латентный дефект, затрагивавший и
  PEM-CRL, не только `.p7b`.

- **OCSP `responseStatus` (ENUMERATED) не ограничивался по длине
  (`GostOcspResponse`).** RFC 6960 кодирует статус (0-6) одним байтом,
  но цикл побитового сдвига по `statusTlv` выполнялся без проверки —
  crafted-ответ с ENUMERATED до ~256КБ (в пределах
  `MAX_OCSP_RESPONSE_SIZE`) вызывал до 256K итераций на разбор одного
  ответа (CPU DoS). Добавлена проверка длины ≤ 1 байт до цикла,
  fail-closed через `PkixException`.

- **`CertIdHasher.extractSubject`/`extractBitStringValue` разбирали
  TBSCertificate позиционно, без проверки тегов полей.** Порядок полей
  (`serialNumber`, `signature`, `issuer`, `validity`, `subject`,
  `subjectPublicKeyInfo`) предполагался фиксированным; malformed DER с
  чужим тегом на месте одного из полей приводил к чтению не тех байт.
  Несовпадение уже ловилось ниже по стеку через сравнение хэшей
  (`OcspVerifier.verifyCertId`, fail-closed), но без диагностики
  причины. Добавлен `checkTag()` — явная проверка `TAG_INTEGER`/
  `TAG_SEQUENCE`/`TAG_BIT_STRING` перед каждым переходом.

- **`GostPkcs12Loader.load()`/`decryptPrivateKey()` не затирали исходный
  `char[] password`** — только производный `byte[]`, в отличие от
  `GostPkcs12Builder.build()`, который затирает оба. Симметрия
  восстановлена: пароль клонируется на входе, затирается клон;
  оригинальный `char[]` вызывающего не трогается (ответственность
  вызывающего), паттерн идентичен `GostPkcs12Builder`.

- **`GostCrl`: серийный номер в revoked-записи ограничивался по
  \*кодированной** длине, а не по величине\* — DoS-барьер плюс ложное
  отклонение легитимного CRL. Проверка длины перед
  `new BigInteger(1, serial)` защищает от аллокации огромного
  `BigInteger` (потолок ограничен только `MAX_CRL_SIZE`), но сравнивала
  кодированную длину TLV с `GostOids.MAX_SERIAL_OCTETS`=20 (RFC 5280
  §4.1.2.2). Положительный 20-октетный серийник со старшим битом
  кодируется в DER 21 байтом (ведущий `0x00` для сохранения знака) и
  отвергался целиком, тогда как `GostCertificateBuilder` такой серийник
  разрешает (сверяет `bitLength`) — асимметрия. Теперь сверяется
  **величина** (ведущий знаковый `0x00` не учитывается), симметрично
  билдеру; добавлен guard от чтения за границей TLV при нулевой длине
  INTEGER (`ArrayIndexOutOfBoundsException` на crafted-входе).
  Non-minimal кодировки (лишние ведущие нули) намеренно не отвергаются:
  серийники сравниваются как `new BigInteger(1, serial)` — величина
  нормализуется, malleability нейтрализована, а толерантность нужна для
  interop.

- **`GostCrl.parseExtensionInteger` (cRLNumber/BaseCRLNumber) не
  ограничивал длину INTEGER** — аналогичный DoS-вектор. Добавлен
  `MAX_CRL_EXT_INTEGER_OCTETS`=8, `PkixException` при превышении
  (fail-closed — не тихая деградация в `null`, консистентно с
  anti-rollback проверкой в `CrlVerifier`).

- **`SsrfGuard.isPrivate()` не блокировал туннельные/транслирующие
  IPv6-диапазоны** (NAT64 `64:ff9b::/96`, Teredo `2001::/32`, 6to4
  `2002::/16`, IPv4-mapped `::ffff:0:0/96`) — ни один из встроенных
  `isSiteLocal/isLinkLocal/...` их не детектирует, что позволяло через
  DNS указать на туннельный адрес, инкапсулирующий приватный IPv4.
  Добавлен явный wholesale-block по префиксу.

- **OCSP-делегатная EKU-проверка (`isOcspSigning()`) была permissive**
  (`!ekuPresent || ekuOcspSigning`), тогда как RFC 6960 §4.2.2.2 требует
  у делегированного responder обязательный `id-kp-OCSPSigning` —
  сертификат без EKU ошибочно проходил как валидный delegate. Приведено
  к `ekuPresent && ekuOcspSigning`, консистентно с уже строгой
  TSP-веткой. Дополнительно убран `anyExtendedKeyUsage` из числа
  достаточных EKU для delegation — RFC 6960 требует именно конкретный
  OID.

- **`ExtensionsResult.EMPTY` (сертификат без блока extensions вовсе)
  давал `ekuOcspSigning=true` и `ekuTimeStamping=true` одновременно** —
  асимметрия с обычным путём (extensions есть, EKU нет →
  `timeStamping=false`). Сертификат без extensions ошибочно проходил и
  как OCSP-делегат, и как TSA. Оба флага в `EMPTY` приведены к `false`;
  permissive-дефолт для общего TLS EKU (`ekuValid`/`ekuClientAuth`, RFC
  5280 §4.2.1.12) не тронут — разные RFC, разная семантика.

- **DoS через неограниченное число `SingleResponse` в OCSP-ответе
  (`GostOcspResponse`).** Цикл разбора `responses` в `BasicOCSPResponse`
  не имел верхней границы: злоумышленник мог передать OCSP-ответ до
  2^24-1 байт (RFC 6066) с сотнями тысяч `SingleResponse`, каждый —
  минимум 3 аллокации `byte[]`. Добавлен лимит `MAX_SINGLE_RESPONSES` =
  256 по образцу уже существующего `MAX_DELEGATED_CERTS`. При превышении
  — `PkixException`.

- **DoS через неограниченное число X.509-расширений в одном сертификате
  (`GostExtensionParser`).** Цикл разбора `Extensions` не имел верхней
  границы; граница `end` — TLV-граница блока, а не лимит количества.
  Добавлен лимит `MAX_EXTENSIONS_PER_CERT` = 64; счётчик
  инкрементируется на каждой итерации цикла (включая non-SEQUENCE TLV),
  иначе лимит обходится "мусорными" вставками. При превышении —
  `IllegalArgumentException` (fail-closed, согласно контракту класса на
  unchecked-исключения при невалидном DER).

- **Nonce больше не попадает в текст `PkixException` при верификации
  TSP-ответа (`TspResponse`).** Нарушало No-debug требование (nonce — в
  списке материала, запрещённого в сообщениях исключений). Сообщения об
  ошибке несовпадения/отсутствия nonce теперь не содержат значений
  nonce.

- **Memory DoS через неограниченный TSP-ответ (`JdkHttpTspTransport`).**
  `BodyHandlers.ofByteArray()` буферировал весь HTTP-ответ TSA без
  ограничения размера. Переход на потоковое чтение
  (`BodyHandlers.ofInputStream()`) с лимитом `MAX_TSP_RESPONSE_SIZE` = 1
  МБ; Content-Type проверяется до чтения тела. Fail-closed:
  `IOException` при превышении лимита (в отличие от soft-fail
  `JdkHttpOcspFetcher`, где OCSP — опциональная проверка).

- **Ключевой материал не затирался при исключении в `GostPkcs12Mac`
  (`verify()`/`compute()`).** Промежуточный `km` (вывод PBKDF2) и
  `hmacKey` зануляются только в happy path; при исключении между
  `System.arraycopy` и HMAC-операциями оставались незатёртыми в куче.
  Оба метода обёрнуты в `try/finally` с гарантированным `Arrays.fill`.

- **Тихий integer overflow в `GostDerParser.oidBytesToDottedString` при
  malformed OID.** Base-128 subidentifier без ограничения числа
  continuation-байт мог переполнить `long`, давая семантически
  бессмысленный arc без исключения. Добавлен лимит
  `MAX_OID_SUBIDENTIFIER_BYTES` = 9 (потолок для 63-битного `long`);
  превышение — `IllegalArgumentException`, fail-closed.

- **Name Constraints (RFC 5280 §4.2.1.10) не проверялись при валидации
  цепочки (`ChainValidator`).** Было: расширение `nameConstraints`
  вообще не парсилось (`GostExtensionParser`) и не проверялось
  (`ChainValidator`) — subordinate CA мог выдать сертификат для
  произвольного домена вне разрешённого CA пространства имён,
  ограничение оказывалось декоративным. Стало: добавлен парсинг
  `permittedSubtrees`/`excludedSubtrees` для типов `dNSName` и
  `iPAddress` (`NameConstraintsData`, новый класс), root-to-leaf проход
  в `ChainValidator.validateChain()` (накопление ограничений от trust
  anchor вниз, включая NC самого root’а; self-issued CA исключены из
  проверки собственного имени per RFC 5280 §6.1.4(k), но их ограничения
  накапливаются). Label-aware suffix matching для dNSName
  (`host.example.com` матчит `example.com`, `notexample.com` — нет). Для
  типов имён вне dNSName/iPAddress (rfc822Name, directoryName, URI,
  otherName), non-critical расширения и нарушения `min=0/max=absent`
  (RFC 5280 §4.2.1.10) — fail-closed reject всей цепочки, а не тихий
  пропуск ограничения.

- **NameConstraints: снят false-reject цепочки при наличии
  неподдерживаемого типа GeneralName в NameConstraints CA-сертификата.**
  Исходный fail-closed отвергал цепочку при любом нераспознанном типе —
  даже когда leaf-сертификат не содержал SAN этого типа (rfc822Name,
  directoryName, URI, otherName). Реальный кейс: CA, выпускающий и
  email-, и TLS-сертификаты одним промежуточным сертификатом
  (rfc822Name + dNSName в NameConstraints), ломал любую TLS-цепочку. Это
  противоречит RFC 5280 §4.2.1.10: ограничение должно применяться только
  если соответствующая форма имени присутствует в SAN проверяемого
  сертификата. Исправление: `hasUnsupportedNameType` больше не вызывает
  `PkixException` — ограничения неподдерживаемых типов игнорируются с
  `WARNING` в лог. Проверка dNSName и iPAddress продолжает работать в
  полном объёме. Безопасность решения обеспечена отсутствием в
  `GostCertificate` accessor’ов для этих форм имён из SAN — данные формы
  физически не могут повлиять ни на одно решение библиотеки.

- **`GostCertificate`/`GostCrl` не ограничивали размер входного DER
  перед `clone()`.** Единственный реально безлимитный вектор — прямой
  разбор PKCS#12 (TLS уже ограничен `MAX_CERT_SIZE`=256 КБ на входе в
  `TlsMessageParser`, CRL-фетч по HTTP — 5 МБ в `JdkHttpCrlFetcher`).
  Добавлены собственные лимиты: `GostCertificate.MAX_CERT_SIZE` = 256
  КБ, `GostCrl.MAX_CRL_SIZE` = 10 МБ — defence-in-depth на уровне самого
  парсера, а не только на границе вызывающего кода.

- **`GostPkcs12Parser`: `iterationCount`/`iterations` PBKDF2 усекались
  через `BigInteger.intValue()` до проверки диапазона.** DER-значение
  вне `int` (например `0x1000003E8`) молча усекалось до младших 32 бит
  (`1000`) и проходило проверку `MAX_ITERATIONS`, хотя заявленное в DER
  значение на порядки больше. Проверка `MAX_ITERATIONS` перенесена на
  `BigInteger` до усечения — в `parseMacData` и `parsePbes2Params`.

- **`OcspVerifier`: сравнение OCSP nonce и CertID-хэшей
  (`issuerNameHash`/ `issuerKeyHash`) через `Arrays.equals()` — не
  constant-time.** Заменено на `MessageDigest.isEqual()` в 5 местах
  (nonce — anti-replay по RFC 8954; хэши issuer —
  defence-in-depth/консистентность, секретных данных с обеих сторон
  сравнения нет).

- **`CrlVerifier`: issuer DN сертификата не проверялся против issuer DN
  CRL при вызове через 3-арг перегрузку (`certIssuerDn` по умолчанию
  `null`, проверка тихо пропускалась).** Позволяло принять CRL от
  другого CA при совпадении открытого ключа (shared CA key). 3-арг
  перегрузка удалена, `certIssuerDn` стал обязательным параметром во
  всех перегрузках, включая base+delta CRL (там был тот же пробел —
  issuer DN сверялся только между base и delta, но не с сертификатом;
  найдено и закрыто дополнительно к находке аудита). Production-путь
  (`GostX509TrustManager`) уже передавал `certIssuerDn` — изменений не
  требует.

- **TSP nonce (`TspResponse`) сравнивался через `BigInteger.equals()` —
  не constant-time.** Заменено на `MessageDigest.isEqual()` по байтовому
  представлению — консистентно с уже исправленным OCSP nonce.

- **OCSP-ответ без `nextUpdate` был валиден бессрочно
  (`OcspVerifier`).** Единственной защитой было «`thisUpdate` не в
  будущем» — старый, давно подписанный ответ проходил проверку свежести
  без ограничения по возрасту, открывая окно для replay. Добавлена
  константа `GostOids.MAX_OCSP_AGE_MS` (24 часа, локальная политика по
  RFC 6960 §2.4) — для ответов без `nextUpdate` теперь проверяется
  возраст относительно `thisUpdate`.

- **SSRF-защита (`getAiaUris()`/`getCdpUris()` в `GostCertificate`) была
  только предупреждением в Javadoc, без enforcement на уровне модуля.**
  `SsrfGuard` перенесён из `crypto-gost-jsse` в `crypto-gost-pkix`
  (`org.rssys.gost.pkix.util`) — устраняет обратную зависимость
  `pkix->jsse` и даёт единую реализацию классификации private/reserved
  адресов для fetcher’ов и любого прямого потребителя `pkix`-API.

- **`GostDerParser.oidBytesToDottedString()` молча принимал OID короче 2
  байт** (пустая строка при `len=0`, усечённый результат при `len=1` без
  исключения). Теперь `len < 2` — fail-closed
  `IllegalArgumentException`.

- **Переполнение `int` при разборе `pathLenConstraint` в
  BasicConstraints (`GostExtensionParser`).** DER INTEGER длиннее 4 байт
  молча переполнял накопитель; при переполнении в отрицательное значение
  проверка `pl >= 0` в `ChainValidator` пропускала ограничение pathLen
  целиком (defence-in-depth — CA и так может не указывать pathLen для
  того же эффекта). Добавлена валидация длины INTEGER (1-4 байта) до
  накопления, иначе `IllegalArgumentException`.

- **`GostOcspRequest`/`GostOcspResponse` не ограничивали размер входного
  DER** (в отличие от `GostCertificate`/`GostCrl`, где лимит уже есть) —
  Memory DoS через oversized OCSP-запрос/ответ, в том числе stapled OCSP
  в TLS (минует HTTP-транспортный лимит `JdkHttpOcspFetcher`). Добавлены
  `MAX_OCSP_REQUEST_SIZE` = 64 КБ и `MAX_OCSP_RESPONSE_SIZE` = 256 КБ,
  проверка до парсинга, `PkixException` — консистентно с остальными
  проверками в этих конструкторах.

- **OCSP nonce (RFC 8954) молча пропускался при malformed DER
  (`OcspVerifier.verifyNonce`).** Метод содержал собственный,
  независимый от `GostOcspResponse` низкоуровневый парсер с множеством
  безусловных `return` на структурных ошибках — при `strict=false`
  (production-путь, `TlsCertUtils`) любое расхождение между двумя
  парсерами тех же байт позволяло обойти nonce-проверку. Устранена сама
  причина: nonce теперь извлекается один раз в `GostOcspResponse`
  (`getNonce()`), `verifyNonce` использует уже распарсенное значение и
  безусловно отклоняет ответ при отсутствии/несовпадении nonce. Параметр
  `strict` и дублирующий парсер удалены.

- **`JdkHttpTspTransport` не имел SSRF-защиты**, в отличие от
  `JdkHttpOcspFetcher`/`JdkHttpCrlFetcher`. Добавлена проверка схемы
  (только `http`/`https`) и `SsrfGuard.isPrivateAddress()` до отправки
  запроса.

- **`ChainValidator` не имел собственного лимита глубины цепочки**
  (защита существовала только выше по стеку — `CertChainBuilder`, TLS
  message parsing). Добавлен `MAX_CERT_CHAIN_LENGTH = 10` как
  defence-in-depth для прямых вызовов `validateChain()`.

- **`GostPkcs12Parser.parseSafeContents()` не ограничивал число
  `SafeBag`** — Memory DoS через PKCS#12 с большим числом bag’ов.
  Добавлен `MAX_SAFE_BAGS = 10 000`.

- **`GostPemUtils` не ограничивал размер входного PEM** — Memory DoS
  через многогигабайтный PEM/Base64. Добавлен `MAX_PEM_SIZE = 10 МБ` в
  `pemToDer()`/`decodePemBlocks()`.

- **PKCS#12 (`MacData`, `PBES2`) допускал соль PBKDF2 нулевой/малой
  длины**, снижая стойкость до детерминированного значения. Добавлен
  `MIN_PBKDF2_SALT_SIZE = 8` байт.

- **`GostCrl` не ограничивал число revoked-записей** — при 10 МБ входа
  минимальная запись (<sub>17\ байт)\ даёт\ до</sub> 600K объектов на
  парсинг. Добавлен `MAX_REVOKED_ENTRIES = 100 000` (defence-in-depth к
  уже существующему `MAX_CRL_SIZE`).

- **`CmsSignedDataVerifier` не ограничивал число встроенных сертификатов
  и `SignerInfo`** — у CMS SignedData не было ни size-, ни count-лимита,
  в отличие от остальных парсеров; каждый `SignerInfo` — полноценная
  ГОСТ-верификация подписи (CPU-DoS). Добавлены
  `MAX_EMBEDDED_CERTS = 64` и `MAX_SIGNER_INFOS = 50` (`CmsConstants`),
  проверка до дорогих операций (`parseCert`/крипто-верификация).

- **`GostExtensionParser`: pathLen INTEGER с MSB=1 (4 байта) переполнял
  `int` в отрицательное значение**, из-за чего `ChainValidator`
  (`pl >= 0`) молча пропускал pathLen-ограничение — остаточный дефект
  после более раннего фикса длины INTEGER. Добавлена проверка `val < 0`.

- **SAN-расширение не ограничивало число записей** внутри одного
  extension (`MAX_EXTENSIONS_PER_CERT` этого не покрывал). Добавлен
  `MAX_SAN_ENTRIES = 512`.

- **OCSP good-статус (`GostOcspResponse`) принимал non-canonical
  constructed-тег `0xA0` без проверки на пустое содержимое** — DER
  malleability. Проверка «NULL, длина 0» теперь применяется к обеим
  формам тега (`0x80` и `0xA0`), алиас `0xA0` сохранён только для
  пустого случая.

- **`SsrfGuard` проверял только первый резолвнутый адрес** (`getByName`)
  — не закрывал multi-A-record сценарий (публичный и приватный адрес в
  одном DNS-ответе). Заменено на `getAllByName` с fail-closed проверкой
  всех адресов.

- **`CmsSignedDataVerifier`: битый встроенный сертификат в
  `SignedData.certificates` молча пропускался** (`LOG.WARNING` + skip) —
  fail-open на парсинге недоверенного входа. Заменено на fail-closed:
  `PkixException(Reason.PARSE_ERROR)`.

- **`GostDerParser.oidBytesToDottedString()` не ограничивал общее число
  арок OID** — только длину каждой отдельной арки
  (`MAX_OID_SUBIDENTIFIER_BYTES`). OID из тысяч однобайтовых арок
  легитимно парсился, раздувая `StringBuilder` пропорционально их числу.
  Добавлен `MAX_OID_SUBIDENTIFIERS = 128`.

- **Маска тега `uniformResourceIdentifier` в AIA/CDP
  (`GostExtensionParser`) гасила constructed-бит**
  (`(tag & 0xDF) == 0x86`), пропуская наравне с корректным primitive
  `0x86` non-standard constructed `0xA6` (RFC 5280 §4.2.1.6 требует
  строго primitive). Заменено на точное сравнение с новой константой
  `TAG_URI`. Обхода не было (URI далее проходят SSRF-проверку), но
  толерантность была избыточной и не соответствовала строгому
  DER-подходу остального кода.

### Документация

- Уточнён контракт доверия `GostOcspResponse.getResponses()` и
  `SingleOcspResponse.isGood()`/`isRevoked()`/`isUnknown()`: статус
  отражает только результат разбора DER и не является доверенным до
  успешного `verify()`. Guard по образцу `GostCrl` не введён осознанно —
  это намеренное parse/verify-разделение, используемое в interop/
  кросс-валидационных сценариях (фиктивные подписи, ответы от чужих
  реализаций без GOST-подписи); guard сломал бы эти легитимные пути.

- Задокументирован как осознанный трейд-офф побайтовый (не
  семантический) способ сравнения subjectDN для подсчёта self-issued в
  `ChainValidator` (`GostCertificate.subjectDnEquals()`) — риск в
  сторону false positive (избыточная строгость pathLen), не security
  bypass.

- Задокументировано как осознанное решение (RFC 6960 §4.2.2.2.1,
  id-pkix-ocsp-nocheck): делегированный OCSP-responder-сертификат не
  проверяется на отзыв (`OcspVerifier.tryDelegatedVerification`).

- Задокументирован остаточный DNS-rebinding TOCTOU для всех трёх
  HTTP-фетчеров (`SsrfGuard`, `JdkHttpTspTransport`) — полное закрытие
  требует ручной реализации HTTP (raw socket + SNI), не входит пока в
  необходимую функциональность; практический риск ограничен probing’ом
  внутренней сети (ответ всегда верифицируется подписью).

- Уточнён Javadoc `CrlVerifier.extractNextUpdate`/`extractCrlNumber` —
  явно отмечено, что результат из неверифицированных байт годится только
  для метаданных кэша, не для acceptance-решения.

- Уточнён javadoc `NameConstraintsData.isEmpty()`: явно объяснено,
  почему флаги ошибок
  (`hasUnsupportedNameType`/`hasInvalidMinMax`/`nonCritical`) намеренно
  входят в проверку — без этого `ChainValidator` пропустил бы
  fail-closed-блок при взведённом флаге и пустых списках (fail-open).

- Задокументирован инвариант `ByteBuffer.wrap(fullArray)` (`position=0`)
  в `CertChainBuilder` — обязателен для корректной дедупликации по
  Subject DN в `HashSet`.

- Уточнено, что `GostDerParser.arrayRangeEquals()` намеренно не
  constant-time (сравнивает только публичные данные — DN, OID
  алгоритма).

- Пояснено lossy-декодирование `US_ASCII` для dNSName в SAN
  (`GostExtensionParser`) — байты вне ASCII заменяются на U+FFFD, обхода
  hostname-проверки нет.

## Модуль crypto-gost-tls13

### Изменено

- Вызов `OcspVerifier.verify()` в `TlsCertUtils` обновлён под новую
  сигнатуру (без параметра `strict`, удалённого при устранении находки
  выше). Поведение не изменилось — ранее уже вызывался с фактическим
  `strict=false`.

- **Проброс настраиваемой политики свежести OCSP (`maxOcspAgeMs`, RFC
  6960 §2.4) сквозь слой валидации.** `TlsCertUtils.verifyOcspResponse`
  и `TlsCertificateValidator.checkServerCertificateChain`/
  `checkClientCertificateChain` получили перегрузки с параметром
  `maxOcspAgeMs`, вызывающие соответствующую перегрузку
  `OcspVerifier.verify`. Прежние сигнатуры делегируют с дефолтом
  `GostOids.MAX_OCSP_AGE_MS` (24 ч) — `TlsSession` и бенчмарки не
  затронуты.

### Исправлено

- **`checkClientCertificateChain` не обрабатывал stapled-OCSP
  клиентского сертификата вовсе (mTLS).** Симметричная серверная ветка
  (`checkServerCertificateChain`) верифицирует уже присланный OCSP-ответ
  при наличии issuer’а; клиентская — не делала этого нигде, отозванный
  клиентский сертификат со stapled-ответом проходил бы проверку молча.
  Добавлена та же ветка (`leaf.hasOcspResponse()` →
  `TlsCertUtils.verifyOcspResponse`), без сети — активный fetch
  клиентского OCSP вне скоупа (SSRF/латентность через AIA недоверенного
  сертификата), отзыв остаётся конфиг-зависимым с обеих сторон.

- **Валидация `ticket_age` при PSK-возобновлении (RFC 8446 §4.2.11.2).**
  Сервер теперь проверяет `obfuscated_ticket_age` из ClientHello против
  `now - issueTime` тикета (допуск `PSK_AGE_TOLERANCE_MS` = ±60 с). При
  расхождении — fallback на полный handshake: clock skew не рвёт
  соединение, полный ECDHE-рукопожатие происходит прозрачно.

- **`TlsRecord.setSequenceNumber()` больше не допускает откат
  порядкового номера.** Публичный метод (только для тестов/бенчмарков)
  позволял выставить `seqNum` назад на уже использованном ключе — при
  повторном `protect()`/ `unprotect()` это привело бы к повтору nonce в
  MGM-AEAD. Теперь откат после первого использования ключа бросает
  `IllegalStateException`.

- **`RecordProtectBench.unprotect` (bench/tls) переведён на
  комбинированный protect+unprotect замер.** Прежний приём — сброс
  `seqNum` вызовом `setSequenceNumber()` прямо в измеряемом методе —
  стал недопустим после введения guard’а против отката порядкового
  номера (см. выше). Чистый decrypt при необходимости вычисляется
  вычитанием отдельно измеряемого `protect()`. Историческая
  сопоставимость с прошлыми числами в `bench/results/tls/` —
  приблизительная, не построчная.

- **`assembleHandshakeMessage()` не ограничивал суммарный размер
  реассемблируемого handshake-сообщения.** `msgLen` — 24-битное поле (до
  16 МБ); реассемблирование из многих TLS-записей позволяло накопить
  буфер такого размера без верхней границы (per-connection resource
  exhaustion, требует аутентифицированного собеседника). Добавлен
  `TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE` (~3.2 МБ) — вычисляемая, а
  не хардкод-константа: по построению равна потолку приёма `Certificate`
  (самого крупного легитимного сообщения, с полной цепочкой
  `MAX_CERT_CHAIN_LENGTH` и per-entry OCSP-staple до 64 КБ),
  автоматически остаётся консистентной при изменении `MAX_CERT_SIZE`/
  `MAX_CERT_CHAIN_LENGTH`. Проверка — fail-closed, до накопления буфера.

- **`PskStore.onTicketReceived()` — контракт интерфейса обещает
  логирование при `RuntimeException` от реализации, но код молча
  поглощал исключение.** Добавлено `LOG.WARNING` (только класс
  исключения, без ключевого материала) в обоих местах
  (`sendNewSessionTicket`/`handleNewSessionTicket`).

- **`psk`, `ticket`, `ticketNonce` не затирались после передачи в
  `PskEntry`** (который клонирует их при конструировании — оригиналы
  избыточны). `psk` — ключевой материал, затирание обязательно;
  `ticket`/`ticketNonce` — гигиена единой дисциплины. `wipeArray` в
  `finally`, после последнего использования каждого массива.

### Примечания

- **`exporter_secret` (RFC 8446 §7.5) не реализован.** Задокументировано
  в `TlsKeySchedule` — библиотека не предоставляет
  `exportKeyingMaterial()`, следовательно channel binding и подобные
  сценарии не поддерживаются.

## Модуль crypto-gost-jsse

### Добавлено

- **`GostTrustManagerParameters`
  (`implements ManagerFactoryParameters`)  
  поддержка в
  `GostTrustManagerFactorySpi.engineInit(ManagerFactoryParameters)`.**
  Штатный JSSE-путь
  `TrustManagerFactory.getInstance("GostX509", …).init(params)` теперь
  прокидывает CA-ключи, политики и лимиты CRL/OCSP в
  `GostX509TrustManager` без «сырого» вызова конструктора. Прежде
  `engineInit(ManagerFactoryParameters)` бросал
  `UnsupportedOperationException`; путь `engineInit(KeyStore)` не
  изменился.

- **`GostSslBuilder`: методы `crlPolicy`/`crlFetcher`/`maxCrlSize`/
  `maxRevokedEntries`/`ocspFetcher`/`maxOcspAgeMs`.** Ранее удобный
  билдер вообще не включал CRL-проверку (жёстко `DISABLED`) и не давал
  настроить лимиты — полная конфигурация была достижима только «сырым»
  конструктором `GostX509TrustManager`. `crlPolicy(null)` трактуется как
  `DISABLED`. `GostSsl.buildContext` получил перегрузку, строящую
  TrustManager полным конструктором; прежняя сигнатура делегирует в неё
  с безопасными дефолтами.

### Изменено

- **`JdkHttpCrlFetcher.DEFAULT_MAX_RESPONSE_SIZE` 5 МБ → 64 МБ** —
  синхронизация с новым дефолтом `GostCrl.DEFAULT_MAX_CRL_SIZE`; иначе
  fetcher отсекал бы данные раньше парсера.

- **`JdkHttpCrlFetcher.DEFAULT_TIMEOUT_MS` 5 с → 30 с** — согласование с
  размерным дефолтом `DEFAULT_MAX_RESPONSE_SIZE` = 64 МБ: 5 с не
  покрывали легитимный сценарий «крупный CRL по медленному каналу»,
  таймаут срывался и на не-REQUIRE политике CRL-проверка тихо
  пропускалась (false-negative на отзыв). Значение ориентировано на
  реальный p99, а не на 64 МБ-потолок (он остаётся DoS-порогом).
  Конфигурируемость через конструктор `JdkHttpCrlFetcher(Duration, int)`
  уже была — изменён только дефолт no-arg конструктора; на внутренние
  пути jsse не влияет (там fetcher всегда передаётся явно), затрагивает
  только внешних потребителей.

- **`JdkHttpOcspFetcher.DEFAULT_MAX_RESPONSE_SIZE` 64 КБ → 256 КБ** —
  значение приведено в соответствие с
  `GostOcspResponse.MAX_OCSP_RESPONSE_SIZE` (256 КБ); иначе fetcher
  отсекал ответ раньше парсера.

- **`GostX509TrustManager`: новый конструктор с параметрами
  `maxCrlSize`/ `maxRevokedEntries`** — устраняет рассинхронизацию, при
  которой оператор мог поднять лимит `JdkHttpCrlFetcher`, но
  `checkCrl()` всё равно жёстко вызывал `CrlVerifier.verify()` с
  дефолтами. Существующий 5-параметрический конструктор делегирует в
  новый с `GostCrl.DEFAULT_MAX_CRL_SIZE`/ `DEFAULT_MAX_REVOKED_ENTRIES`
  — обратная совместимость сохранена.

- **`GostX509TrustManager`: конструктор с параметром `maxOcspAgeMs`
  (8-параметрический) и проброс порога свежести OCSP на mTLS-путь.**
  7-параметрический конструктор делегирует в новый с
  `GostOids.MAX_OCSP_AGE_MS` (24 ч). Проверка клиентского сертификата
  (`checkClientTrustedImpl`) раньше игнорировала настроенный порог
  свежести stapled-OCSP клиента (шла по дефолту 24 ч) — асимметрия с
  серверным путём; теперь `maxOcspAgeMs` передаётся и туда.

- **Удалён `KeyBridge` — дублировал GostECPrivateKey**.  
  `KeyBridge.GostPrivateKeyAdapter` и `GostECPrivateKey` независимо
  решали одну и ту же задачу: оборачивали `PrivateKeyParameters` в
  `java.security.PrivateKey` с поддержкой `Destroyable`. Метод
  `KeyBridge.fromJca()` не использовался.
  `GostX509KeyManager.getPrivateKey()` и `GostSSLEngine` переведены на
  `GostECPrivateKey`. Функциональность не изменилась.

- `SsrfGuard` перенесён в `crypto-gost-pkix`; импорты в
  `JdkHttpOcspFetcher`/`JdkHttpCrlFetcher` обновлены. Поведение не
  изменилось.

- **Предупреждение об отсутствии hostname verification — теперь
  per-connection, а не однократно на JVM
  (GostSSLEngine.beginHandshake())**.  
  Убран JVM-глобальный AtomicBoolean: однократность маскировала
  per-connection риск, включая случайное снятие safe-default через
  setSSLParameters. Осознанный opt-out через
  createForClientNoHostnameCheck() исключён из per-handshake WARNING
  (флаг explicitNoHostnameCheck) — намерение объявляется однократным
  WARNING при создании. Флаг влияет только на логирование, не на решение
  о проверке (оно определяется исключительно
  endpointIdentificationAlgorithm).

### Исправлено

- **Plaintext-запись (до установления handshake-ключей) не проверялась
  на максимальный размер (`GostSSLEngine.handlePlaintextRecord`).**
  `payloadLen` до 65535 байт допускал аллокацию `new byte[totalLen]` без
  проверки против `MAX_PLAINTEXT_LENGTH` (RFC 8446 §5.1, TLSPlaintext ≤
  2¹⁴) — доступно любому pre-auth TCP-клиенту. Проверка добавлена до
  аллокации, `ALERT_RECORD_OVERFLOW`, зеркалит существующую раннюю
  проверку в `TlsRecord.unprotect()`.

- **Входящие KeyUpdate не ограничивались по частоте.**
  `peerKeyUpdateCount` инкрементировался, но нигде не сравнивался с
  порогом — аутентифицированный пир мог флудить KeyUpdate, вызывая
  пересоздание ключей/`TlsRecord` на каждое сообщение. RFC 8446 §4.6.3
  такого требования не содержит (норму вводит только черновик
  rfc8446bis) — это hardening, не устранение нарушения протокола.
  Добавлен rate-limit по скользящему окну
  (`MAX_PEER_KEY_UPDATES_PER_WINDOW=10` за
  `KEY_UPDATE_RATE_WINDOW_NANOS` 1 c) — не lifetime-cap, чтобы не ломать
  легитимный auto-rekey на долгоживущих соединениях.

- **`pendingCloseRecord` не был `volatile` при cross-lock доступе.**
  Поле писалось/читалось под `outboundLock` (`closeOutbound`/`wrap`/
  `pollOutboundRecord`), но обнулялось под `inboundLock`
  (`destroyHandshakeEngine()` из `closeInbound`/`handleAlert`) — разные
  локи не дают happens-before между направлениями, возможен stale-read.
  Поле приведено к `volatile`, симметрично уже-`volatile` `closeSent`/
  `closeReceived`.

- **`GostSSLSocket.close()` не зачищал ключевой материал engine при
  закрытии до получения close\_notify от пира (P2).** `close()` вызывал
  только `engine.closeOutbound()`; в штатной ветке «закрываем первыми»
  (`closeReceived==false`) `destroyHandshakeEngine()` не срабатывал —
  `readerRecord`/`writerRecord`/`pendingWriteKey` оставались в куче до
  GC при любом graceful-close, а не только при обрыве TCP. `close()`
  теперь вызывает `engine.closeInbound()` после отправки close\_notify,
  зачистка гарантированно проходит через единую точку
  `destroyHandshakeEngine()`.

- **CRL rollback через отсутствие проверки монотонности `cRLNumber`
  (`GostX509TrustManager.checkCrl()`).** Защита от rollback уже была
  реализована в `CrlVerifier.verify()` (5-арг перегрузка), но
  production-код вызывал 4-арг версию без `minCrlNumber` — проверка
  никогда не выполнялась. Атакующий, контролирующий CDP (MITM/DNS
  spoofing) или кэш, мог подсунуть старый, валидно подписанный CRL в
  пределах окна `thisUpdate`/`nextUpdate`, где отзыв сертификата ещё не
  отражён (RFC 5280 §5.2.3).

- `CrlCache` переведён с `get()`/`put()` на атомарный `lookup()`,
  возвращающий `CrlCacheEntry(crlDer, lastKnownCrlNumber)`: последний
  известный `cRLNumber` сохраняется даже для истёкшей (expired) записи
  кэша — это монотонное знание используется как нижняя граница при
  следующей проверке. `GostX509TrustManager` теперь передаёт этот номер
  в `CrlVerifier.verify()`, fail-closed при обнаружении отката.

- **Hostname verification отсутствовала по умолчанию на engine-пути
  SSLContext.createSSLEngine(host, port) — расхождение с socket-путём
  (confused deputy)**.

  GostSSLSocket всегда создаёт клиента через
  GostSSLEngine.createForClient(), выставляющий
  endpointIdentificationAlgorithm = "HTTPS", тогда как
  GostSSLContextSpi.engineCreateSSLEngine(host, port) шёл через
  package-private конструктор, оставляя поле null — проверка имени
  пропускалась (extractHostnameForEndpointId возвращает null для
  не-HTTPS/LDAPS, и TlsCertificateValidator.checkServerCertificateChain
  не сверяет hostname при null). Вектор: перенос кода с socket API на
  engine API (Netty/Undertow/Tomcat) молча терял защиту от MITM —
  атакующий с валидным сертификатом доверенного CA, но для другого
  домена, проходил проверку.  
  Исправление: новая фабрика GostSSLEngine.createForContextClient()
  выставляет HTTPS при непустом host (сохраняя serverSessionContext для
  delayed-mode серверов вроде Tomcat), engineCreateSSLEngine(host, port)
  переведён на неё. Engine-путь теперь даёт те же гарантии, что
  socket-путь. \* **GostSSLEngine.setSSLParameters() игнорировал null в
  endpointIdentificationAlgorithm, вопреки контракту SSLParameters**.  
  null трактовался как «не менять», из-за чего явное отключение проверки
  по спецификации (setEndpointIdentificationAlgorithm(null)) не
  срабатывало — ловушка на фоне нового safe-default. Теперь endpoint id
  применяется безусловно: null (и "") отключают проверку по контракту
  JSSE; действует единообразно на socket и engine путях (GostSSLSocket
  делегирует напрямую).

### Документация

- Javadoc `JdkHttpCrlFetcher`/`JdkHttpOcspFetcher` дополнен тем же
  предупреждением об остаточном DNS-rebinding TOCTOU (см.
  `crypto-gost-pkix`).

# \[0.6.1\] - 02-07-2026

Данный релиз целиком посвящен устранению проблем безопасности,
выявленных в ходе аудита. Этот релиз содержит также небольшой **breaking
change**, но он был необходим.

**Новой функциональности в этом релизе нет.**

## Модуль crypto-gost-tls13

### Исправлено (безопасность)

- **Небезопасный дефолт в TLS-клиенте (P0, CWE-295).** `TlsClientConfig`
  теперь требует CA-ключ обязательно в конструкторе. Прежний конструктор
  `TlsClientConfig(ciphersuite)` удалён: он позволял создать клиента без
  проверки сертификата сервера, что открывало MITM-атаку с
  самоподписанным ГОСТ-сертификатом.

- **Отсутствие проверки hostname при наличии CA (P1).** Прежние фабрики
  `createClient(transport, cs, cert, key)` и
  `createClient(transport, cs, cert, key, caKey)` удалены — они не
  передавали hostname, что позволяло сертификату `evil.example.com` от
  того же CA пройти при подключении к `api.example.com`.

- **Защита в `TlsSession.createClient()`** — при отсутствии hostname и
  без явного `withoutHostnameVerification()` создание сессии завершается
  `IllegalArgumentException`. Это ломающее изменение для кода, который
  передавал `TlsClientConfig` без hostname.

- **PSK-тикет более не теряется при неверном подтверждении клиента
  (P1).** Ранее тикет безвозвратно изымался из хранилища до проверки
  подтверждения — злоумышленник мог уничтожить чужой тикет,
  подключившись с тем же идентификатором и заведомо неверным
  подтверждением. Теперь тикет изымается только после успешной проверки.
  При неудаче тикет остаётся в хранилище, клиент выполняет полное
  согласование без потери сессии.

### Добавлено

- **`TlsSession.createClientWithoutServerAuth()`** — явный небезопасный
  путь для тестов и отладки. Имя метода сигнализирует об отсутствии
  аутентификации сервера, аналогично
  `GostSslDev.trustAllClientContextInsecure()` в модуле
  `crypto-gost-jsse`.

- **`TlsClientConfig.withoutHostnameVerification()`** — явное отключение
  проверки hostname. Для mesh-сервисов, IP-соединений и тестов, где
  CA-аутентификация обязательна, но DNS-имя не используется. Без вызова
  этого метода или `withServerHostname()` `createClient()` бросает
  `IllegalArgumentException`.

### Изменено

- **Перенос логики делегированных OCSP-подписантов в
  `crypto-gost-pkix`.** Проверка цепочки и полномочий делегированных
  responder-сертификатов перенесена из `TlsCertificateValidator` в
  `OcspVerifier`. Код проверки OCSP на транспортном уровне сократился
  более чем вдвое.

## Модуль crypto-gost-jsse

### Добавлено

- **`SsrfGuard`** — общий утилитный класс для SSRF-защиты при
  HTTP-запросах по внешним URI. Блокирует private/reserved IP после
  DNS-разрешения (localhost, loopback, site-local, link-local,
  multicast). Fail-closed при неразрешаемом хосте.

- **`GostSSLEngine.createForClient()` — теперь включает проверку
  hostname по RFC 6125 по умолчанию.**
  `endpointIdentificationAlgorithm = "HTTPS"` устанавливается
  автоматически. Устранена MITM-уязвимость (CWE-297) при использовании
  `createForClient()` без явной проверки hostname.

- **`GostSSLEngine.createForClientNoHostnameCheck()`** — явный
  небезопасный путь для тестов, dev-сред и изолированных сетей. Имя
  метода и LOG.WARNING при каждом вызове сигнализируют об отсутствии
  проверки hostname.

### Исправлено

- **SSRF-уязвимость в `JdkHttpOcspFetcher` (CWE-918).** OCSP-запросы по
  URI из AIA-расширения непроверенного сертификата теперь проходят
  SSRF-проверку через `SsrfGuard.isPrivateAddress()`. Ранее
  блокировалась только не-HTTP схема, но не private/reserved IP —
  злоумышленник мог заставить TrustManager выполнить HTTP-запрос на
  внутренний адрес (metadata endpoints, админки). `JdkHttpCrlFetcher`
  переведён на тот же `SsrfGuard` (устранено дублирование).

- **Ключи readerRecord/writerRecord теперь затираются при закрытии
  соединения.** `destroyHandshakeEngine()` вызывал `destroy()` только на
  pending-ключах и handshakeEngine — активные traffic-ключи текущей
  эпохи оставались в heap. Исправлено: `readerRecord.destroy()` +
  `writerRecord.destroy()` + обнуление ссылок.

- **Добавлены WARNING в `GostSslBuilder.trustAll()` и конструкторе
  `GostX509TrustManager` при отсутствии CA-ключей.** Защита от
  случайного использования trust-all в production.
  `GostSslDev.trustAllClientContextInsecure()` — единственный легитимный
  путь.

- **SSRF-защита в `SsrfGuard`: устранены два обхода через IPv6.** Адреса
  `[::]` (IPv6 unspecified) не блокировались — добавлен предикат
  `isAnyLocalAddress()`. Диапазон `fc00::/7` (RFC 4193, Unique Local
  Address) не блокировался — добавлена побитовая проверка первого байта.

## Модуль crypto-gost-core

### Исправлено (безопасность)

- **Атака через подмену точки открытого ключа (CWE-347, invalid-curve
  attack).** Операции скалярного умножения в `ECPoint` не используют
  параметр `b` кривой, поэтому принимали точку с другой кривой с гладким
  порядком. Атакующий, контролирующий открытый ключ пира (в CMS, TLS
  ECDHE, JCA KeyAgreement), мог восстановить приватный ключ через
  оракул. Добавлен метод `ECPoint.isValidPublicKey()` с проверкой
  принадлежности кривой и подгруппе; проверка применена во всех точках
  входа: конструктор `PublicKeyParameters`, `KeyAgreement.vko()`,
  `GostDerCodec.decodePublicKey()`,
  `GostKeyFactorySpi.engineGeneratePublic()`,
  `TlsEncoding.decodePoint()`.

- **Зачистка ключевого материала в режимах шифрования и MAC.** Режимные
  классы (`Cbc`, `Cfb`, `Ofb`, `Ctr`, `CtrAcpkmMode`, `Mgm`), `Cmac`,
  `Hmac` и JCA-обёртки (`GostCipherSpi`, `GostMacSpi`) теперь затирают
  ключевой материал при переинициализации и завершении через
  `destroy()`. Ранее ключевые байты оставались в heap до сборки GC.

- **Закрытый ключ в `ECDSASigner` затирается при смене роли.** При
  переинициализации в режим верификации поле `dBytes` обнулялось через
  `= null` без затирания байтов. Теперь вызывается
  `Arrays.fill(dBytes, (byte) 0)` перед обнулением ссылки.

- **Constant-time удаление ISO 7816-4 паддинга.**
  `ISO7816d4Padding.padCount()` переписан без раннего выхода — тайминг
  не зависит от позиции маркера `0x80`. Добавлена явная проверка нулевых
  байт между маркером и концом блока.

- **Constant-time удаление PKCS#7 паддинга.**
  `Pkcs7Padding.removePadding()` переписан без раннего выхода — цикл
  проверки всегда проходит все padding-байты.

- **MGM: ключевое состояние не затиралось при провале тега
  аутентификации (CWE-226).** `GostMgmCipherSpi.doFinalDecrypt()` при
  `AEADBadTagException` затирал только plaintext-буфер — внутреннее
  key-derived состояние `Mgm` (`mulTabHi/Lo`, счётчики `yHi/zHi`,
  аккумулятор `sumHi/Lo`) оставалось в heap до следующей инициализации
  или сборки GC. Теперь `mgm.destroy()` вызывается сразу в error-path.

- **Гонка при конкурентном доступе к `GostSecretKey` (CWE-362).** Поля
  `keyBytes`/`destroyed` не были синхронизированы: `destroy()`
  (`Arrays.fill`) и `getEncoded()`/`toSymmetricKey()` (`Arrays.copyOf`),
  вызванные из разных потоков, могли дать torn-read — чтение частично
  обнулённого ключа. Добавлен `ReentrantLock` (не `synchronized` — не
  пиннит virtual threads JDK 21) вокруг всех операций с ключевым
  материалом.

- **Незатёртые копии ключевого материала в Hmac/KDF/JCA SPI (CWE-226).**

  - `Hmac.initWithKeyBytes()`: хэш-копия ключа (когда
    `key.length > blockLen`) не затиралась после использования.
    Затирается сейчас; ветка-алиас (`key.length <= blockLen`, `k = key`)
    не трогается — это ссылка на массив вызывающего.

  - `KdfGostR3411_2012_256.deriveKey()`: scratch-буфер `block` (фрагмент
    производного ключа на каждой итерации) не затирался после цикла.
    Теперь затирается в `finally`, тем же паттерном, что уже применялся
    в `KdfTreeGostR3411_2012_256`.

  - `GostCipherSpi`, `GostMgmCipherSpi`, `GostCtrAcpkmCipherSpi`: три
    идентичные копии `extractSymmetricKey()` создавали временный
    `byte[] encoded = key.getEncoded()`, не затирая его после
    конструирования `SymmetricKey`. Вынесено в общий
    `SymmetricKeyExtractor.fromKey()` (устранено тройное дублирование),
    `encoded` затирается в `finally`.

  - `Cmac.reset()` теперь затирает `mac` (последний вычисленный блок),
    как и `destroy()` — консистентность.

- **Неканоничное DER-кодирование длины принималось без проверки
  (malleability, X.690 §10.1).** `DerCodec.decodeLength()` принимал
  long-form кодирование длины (`0x81`-`0x84`) даже когда значение
  помещалось в более короткую форму — например, `0x81 0x05` вместо
  канонического `0x05`. Добавлена проверка минимальности для всех
  long-form веток. BER indefinite-length (`0x80`) осознанно сохранён —
  `DerCodec` используется как BER-парсер только для SPKI/PKCS#8 ключей
  (всегда definite DER на практике), а решения по сертификатам/CMS через
  него не принимаются.

### Добавлено

- **`Pbkdf2Streebog.MAX_ITERATIONS = 2_000_000`** — максимальное число
  итераций PBKDF2. Верхний предел в `pbkdf2()` для защиты от
  CPU-исчерпания при импорте недоверенных PFX-файлов.

## Модуль crypto-gost-pkix

### Исправлено

- **DoS-защита в `GostPkcs12Parser`: верхний предел `iterationCount`
  (CWE-405).** Параметр `iterationCount` в PBES2-params и `iterations` в
  MacData парсился из недоверенных DER без ограничения — атакующий мог
  подложить PFX с `Integer.MAX_VALUE` итераций и исчерпать CPU (два
  независимых вектора: PBES2 KDF и MAC-верификация). Оба поля теперь
  валидируются через `Pbkdf2Streebog.MAX_ITERATIONS` на этапе парсинга.
  Дополнительный эшелон — проверка в `Pbkdf2Streebog.pbkdf2()`
  (закрывает также JCA `SecretKeyFactory`).

- **Обход проверки атрибутов contentType и messageDigest в CMS (P0).**
  `CmsSignedDataVerifier` молча пропускал подписанные данные без
  обязательных атрибутов `contentType` и `messageDigest` — подпись
  проверялась, а целостность контента нет. Теперь отсутствие любого из
  атрибутов при наличии подписанных атрибутов вызывает ошибку (RFC 5652
  §5.4).

- **Отсутствие проверки полномочий подписанта OCSP (P0).**
  `OcspVerifier` не проверял расширение, разрешающее подпись
  OCSP-ответов (`id-kp-OCSPSigning`), у делегированных подписантов.
  Сертификат без этого полномочия мог быть использован для подписи
  OCSP-ответа — проверка добавлена встроенно, отдельно вызывать не
  нужно.

- **Неканоничное DER-кодирование длины в `GostDerParser` (malleability,
  X.690 §10.1).** Аналогично `crypto-gost-core/DerCodec` — long-form
  длина принималась без проверки минимальности. Добавлена та же
  проверка. BER indefinite-length (`0x80`) в этом парсере запрещён и был
  запрещён и ранее — он используется для решений по сертификатам/CMS
  (fail-closed остаётся неизменным).

- **`digestFor()` в `CmsSignedDataVerifier` принимал неизвестный OID
  алгоритма хэширования как Streebog-256 без ошибки (fail-open).**
  `digestAlgorithm` в `SignerInfo` — controlled полем подписанта; при
  значении, отличном от Streebog-256/512, теперь `PkixException` вместо
  молчаливого fallback. Затрагивает и content-digest сверку, и
  `signedAttrsHash`, используемый при проверке подписи.

- **`CAdESExtender.checkCertValidityAtTime()` не учитывал допуск на
  рассинхронизацию часов.** Сравнение `genTime` TSA с
  `notBefore`/`notAfter` сертификата теперь, как и везде в библиотеке
  (`GostCertificate.isExpired()`, `GostCrl`, `OcspVerifier`,
  `TspResponse`), допускает `GostOids.CLOCK_SKEW_MS` (5 минут).

- **PBKDF2: нижний порог числа итераций для untrusted PFX (CVE-класс:
  brute-force).** `GostPkcs12Parser` принимал
  `iterations`/`iterationCount` вплоть до `1`, включая обход через
  отсутствующее (`OPTIONAL DEFAULT 1`) поле `iterations` в `MacData`.
  Добавлен `GostOids.MIN_PBKDF2_ITERATIONS_PFX` (1000) — проверяется для
  обоих полей независимо от того, явно ли они закодированы.
  `parsePfx()`/`parsePbes2Params()`/`GostPbes2.decryptKey()`/`GostPkcs12Loader.load()`/
  `decryptPrivateKey()` получили перегрузки с настраиваемым порогом —
  для legacy-файлов из доверенного источника вызывающий может осознанно
  его снизить.

- **CRL: не проверялась монотонность `cRLNumber` (CRL rollback, RFC 5280
  §5.2.3).** `CrlVerifier.verify()` получил перегрузку с `minCrlNumber`
  — CRL со значением ниже переданного отклоняется как rollback. Добавлен
  `extractCrlNumber()` для дешёвого извлечения номера без полной
  верификации (по аналогии с `extractNextUpdate()`). Отслеживание
  последнего известного `cRLNumber` — на стороне вызывающего кода.

### Изменено

- **Публичный API `OcspVerifier` переведён на сертификат вместо голого
  ключа.** Все перегрузки, принимающие `PublicKeyParameters`, стали
  внутренними. Единственный публичный метод принимает `GostCertificate`
  — полномочия подписанта и сверка связки сертификат-ответ выполняются
  принудительно, их невозможно пропустить в вызывающем коде. Параметры
  CertID вычисляются автоматически, исключая риск рассинхронизации.

# \[0.6.0\] - 30-06-2026

Данный релиз вносит **ломающие** изменения в связи с новым модулем
`crypto-gost-pkix` и миграцией кодовой базы на него.

## Модуль crypto-gost-pkix

### Добавлено

- **Модуль `crypto-gost-pkix`** — новый модуль для PKIX-инфраструктуры:
  ГОСТ-реестр OID, CMS (RFC 5652 + TC26), X.509-сертификаты, OCSP, CRL,
  CSR (PKCS#10), PKCS#12, CAdES-T, TSP.

- **CMS SignedData** — построение (`CmsSignedDataBuilder`) и верификация
  (`CmsSignedDataVerifier`) по RFC 5652 §5. Результат верификации —
  record `VerifiedSignedData` (данные + сертификат подписанта).
  Поддерживаются инкапсулированные и detached подписи, signed-атрибуты,
  встроенные сертификаты, валидация цепочки доверия. Верификатор
  совместим с форматом подписи КриптоПРО (cryptcp → crypto-gost, BER
  indefinite-length).

- **CMS EnvelopedData** — шифрование (`CmsEnvelopedDataBuilder`) и
  расшифрование (`CmsEnvelopedDataDecryptor`) по RFC 5652 §6.
  KeyAgreeRecipientInfo с VKO + KExp15 (RFC 9189 §8.2.1) + Кузнечик
  CTR-ACPKM (RFC 9337 §7). Эфемерные ключи и CEK затираются после
  использования. Поддержка нескольких получателей.

  **Совместимость:** КриптоПРО 5.0 использует KeyTransRecipientInfo с
  ГОСТ 28147-89 (RFC 4490 §5). Совместимость с КриптоПРО на уровне
  EnvelopedData отсутствует: разные поколения стандартов GOST CMS.

- **Базовые CMS-структуры:** `CmsContentInfo` (с BER indefinite-length),
  `CmsAttribute`, `CmsAlgorithmIdentifier`, `CmsIssuerAndSerialNumber`,
  `CmsKeyWrap` / `Kexp15CmsKeyWrap`.

- **`GostOids`** — перенесён из `crypto-gost-tls13` в
  `crypto-gost-pkix`. Добавлены CMS OID: `CMS_SIGNED_DATA`,
  `CMS_ENVELOPED_DATA`, `AGREEMENT_VKO_256`, `WRAP_KUZNYECHIK_KEXP15`,
  атрибуты подписи. Добавлена константа `STREEBOG_512_HASH_LEN = 64`.
  Добавлены OID-константы X.509-расширений: `EXT_SKI`, `EXT_CP`,
  `EXT_AKI`. Добавлены CRL entry extension OID: `EXT_CRL_REASON`
  (2.5.29.21), `EXT_INVALIDITY_DATE` (2.5.29.24),
  `EXT_CERTIFICATE_ISSUER` (2.5.29.29). Добавлены CRL-level расширения:
  `EXT_CRL_NUMBER` (2.5.29.20), `EXT_DELTA_CRL_INDICATOR` (2.5.29.27),
  `EXT_FRESHEST_CRL` (2.5.29.46).

- **Семантическое исправление УКЭП/УНЭП:** Константы `EKU_UKEP` /
  `EKU_UNEP` переименованы в `POLICY_KC1` / `POLICY_KC2`, поскольку OID
  `1.2.643.100.113.x` соответствуют классам криптосредств KC1/KC2 (RFC
  9215 §5.2, Приказ ФСБ №795 п.28) и размещаются в CertificatePolicies
  (2.5.29.32), а не в ExtendedKeyUsage. В `GostCertificateBuilder`
  добавлен `buildCertificatePoliciesExtension()`, в `GostOids` —
  константы `POLICY_KC1` / `POLICY_KC2`, в `GostDerParser` —
  `KC1_OID_BYTES` / `KC2_OID_BYTES`. В `matchesOidFilter()` добавлена
  поддержка фильтра по `CP_OID_BYTES` (структурный аналог EKU-ветки).
  **Ломающее изменение:** использование старых имён приведёт к ошибке
  компиляции.

- **`PkixException`** — checked-исключение PKIX-слоя
  (`extends Exception`). Ошибка верификации сертификата — часть
  контракта. TLS-адаптер ловит и оборачивает в `TlsException` с
  маппингом alert-кода по `Reason` enum вместо grep по тексту сообщения.

- **`GostCertificate`** — парсинг и верификация X.509-сертификатов ГОСТ
  Р 34.10-2012: извлечение DN, serial, validity, расширений (KeyUsage,
  EKU, BasicConstraints, SAN, CDP, AIA), верификация подписи, проверка
  срока, проверка hostname по dNSName/iPAddress (RFC 6125):
  `verifyHostname()` — полная проверка сертификата, `matchDnsName()` —
  атомарное wildcard-сопоставление hostname↔dNSName для внешних
  вызывающих (KeyManager).

- **`ChainValidator`** — валидация цепочки сертификатов: проверка
  подписей, DN-связности (issuer → subject), KeyUsage
  (keyCertSign/digitalSignature), BasicConstraints (CA flag + pathLen),
  EKU. Без TLS-алертов.

- **OCSP/CRL:** `GostOcspResponse` — парсер OCSP-ответа (RFC 6960):
  разбор OCSPResponse в структурированный объект, извлечение
  `SingleOcspResponse` (certStatus, thisUpdate, nextUpdate), проверка
  подписи, поддержка делегированных сертификатов и nonce-расширения;
  `GostOcspRequestBuilder` — fluent-построитель DER OCSP-запросов:
  CertID (Streebog-256/512), nonce (RFC 8954), опциональная подпись
  запроса (RFC 9215 §4.2), multi-cert (несколько CertID в одном
  OCSPRequest); `GostOcspRequest` — парсер входящих OCSP-запросов:
  `List`&lt;`CertId`&gt;, nonce, `verifySignature()`; `CertId` record —
  OCSP CertID (hashAlgOid, issuerNameHash, issuerKeyHash, serialNumber);
  `SingleOcspResponse` record — разобранный single OCSP response с
  полями certStatus (good/revoked/unknown), thisUpdate, nextUpdate;
  `OcspVerifier` — верификация OCSP-ответов, использует
  `GostOcspResponse` для разбора; `GostCrl` — объект-парсер CRL
  (извлечение issuer, срока, revoked-списка, верификация подписи), новые
  геттеры: `getCrlNumber()`, `getBaseCrlNumber()`, `isDelta()`,
  `getReason(byte[] serial)` — парсинг CRL-level и entry-level
  расширений после `verify()`; `CrlVerifier` (RFC 5280 §6.3) —
  верификация CRL: проверка подписи, срока, issuer DN (§6.3.3(c)), поиск
  серийного номера. Верификация пары base+delta CRL:
  `CrlVerifier.verify(baseDer, deltaDer, serial, caKey)` — сверка
  cRLNumber, thisUpdate, issuer DN; delta-записи перекрывают base;
  `REMOVE_FROM_CRL` удаляет из base. Все выбрасывают `PkixException`
  (checked).

- **Сертификатные утилиты:** `GostDerParser` — DER-парсер (бывший
  `TlsDerParser`), бинарные OID для CRL-расширений:
  `CRL_NUMBER_OID_BYTES`, `CRL_REASON_OID_BYTES`,
  `DELTA_CRL_INDICATOR_OID_BYTES`, `FRESHEST_CRL_OID_BYTES`; константа
  `TAG_ENUMERATED` (0x0A); `CertIdHasher` — хеширование
  issuerName/issuerKey для OCSP CertID (бывший `OcspCertIdHasher`).

- **PKCS#12 (RFC 7292):** `GostPkcs12Parser` — разбор PFX (вложенный
  AuthenticatedSafe, SafeBag, MacData, EncryptedPrivateKeyInfo,
  PBES2-params); `GostPkcs12Builder` — построение PFX-контейнеров с ГОСТ
  PBE; `GostPkcs12Loader` / `Pkcs12Loader` — загрузка ключей и
  сертификатов; `GostPkcs12Mac` — вычисление и проверка MAC PFX (RFC
  9548 §7); `GostPbes2` — шифрование/расшифровка ключей по PBES2-ГОСТ
  (RFC 9337).

- **X.509-строители (fluent API):** `GostCertificateBuilder` — сборка
  сертификатов (TBS + подпись, расширения
  SKI/AKI/SAN/KeyUsage/EKU/CDP/AIA). SKI вычисляется как Streebog-256 от
  байт точки ключа (32 байта, RFC 5280 §4.2.1.2); AKI — копия SKI
  издателя в `[0] IMPLICIT OCTET STRING`; `GostCrlBuilder` — построение
  CRL (RFC 5280, AlgorithmIdentifier — signwithdigest без параметров
  согласно RFC 9215 §2) с поддержкой CRL entry extensions: reasonCode,
  invalidityDate, certificateIssuer для indirect CRL. Fluent-методы для
  Delta CRL: `withCrlNumber()`, `withDeltaCrlIndicator()`,
  `withFreshestCrl()`; валидация: deltaCRLIndicator без cRLNumber →
  `IllegalStateException`; `GostCsrBuilder` — построение CSR (RFC 9215
  §4); `GostCsrParser` — разбор и верификация PKCS#10 CSR (RFC 2986
  §4.1): извлечение DN, SPKI (публичный ключ), OID алгоритма подписи,
  proof-of-possession (verifySelf), расширения extensionRequest
  (SAN/KU/EKU/SKI/AKI и др. через `GostExtensionParser`),
  PEM-сериализация с заголовком `CERTIFICATE REQUEST`;
  `GostOcspResponseBuilder` — OCSP-ответы (RFC 6960) с делегированными
  сертификатами и поддержкой nonce (RFC 8954). Вспомогательный
  `GostSignatureHelper` (doHash  
  buildAlgId для X.509-подписей).

- **`GostDnParser.encodeDn()`** — сборка DER Distinguished Name по
  набору атрибутов (CN, O, OU, L, ST, C).

- **`ReasonCode` enum** — причины отзыва сертификата (RFC 5280 §5.3.1):
  `UNSPECIFIED`, `KEY_COMPROMISE`, `CA_COMPROMISE`,
  `AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`,
  `CERTIFICATE_HOLD`, `REMOVE_FROM_CRL`, `PRIVILEGE_WITHDRAWN`,
  `AA_COMPROMISE`. Используется в `RevokedEntry` при построении CRL.
  Метод `fromValue(int)` — обратный lookup по числовому коду.

- **`RevokedEntry` record** — структура записи отзыва для
  `GostCrlBuilder`: serial, revocationDate, опциональные reasonCode /
  invalidityDate / certificateIssuer. Сокращённый конструктор (serial,
  date) для записей без расширений.

- **`GeneralNameCodec`** — кодек GeneralName (RFC 5280 §4.2.1.6) для
  DNS, IP и directoryName. Выделен из `GostCertificateBuilder`,
  переиспользуется в SAN (сертификаты) и certificateIssuer (indirect
  CRL).

- **`CmsSignedAndEnvelopedData`** — совмещённая подпись и шифрование
  (RFC 5652, CMS triple-wrapped). Статические методы
  `signThenEncrypt()`, `encryptThenSign()`, `decryptAndVerify()`,
  `verifyAndDecrypt()`. Поддержка нескольких получателей.

- **`PkixDemo`** — демонстрационная программа, последовательно
  выполняющая все возможности модуля pkix с проверкой результатов:
  сертификаты, PKCS#12, CSR, цепочки, CRL, OCSP, CMS SignedData
  (инкапсулированная, detached, signed-атрибуты), CMS EnvelopedData, CMS
  SignedAndEnvelopedData, GostOids, Certificate Policies, GostDnParser.

- **CAdES-T / TSP (RFC 3161, ETSI EN 319 122)** — долговременная
  электронная подпись с метками времени.:

  - `CAdESAttributes` — `signingCertificateV2` (ESS, RFC 5035),
    автоматическое добавление через `CmsSignedDataBuilder.withCAdES()`.;

  - `CAdESExtender` — встраивание `signature-time-stamp` в
    unsigned-атрибуты SignerInfo (CAdES-BES → CAdES-T).;

  - TSP-клиент: `TspRequestBuilder`, `TspResponse`, `TstInfo`,
    `JdkHttpTspTransport` (HTTP POST, `java.net.http`).;

  - TSP-сервер: `TspRequest` (разбор входящих TimeStampReq),
    `TspResponseBuilder` — построение TimeStampResp: granted, rejected,
    grantedWithMods, nonce-echo, accuracy, ordering, CAdES-атрибуты,
    авто-определение digest (256/512) по ключу TSA, цепочка сертификатов
    в ответе.;

  - `TstInfo.ordering` — новое поле (RFC 3161 §2.4.2), поддержка в
    парсере и билдере.;

  - Поддержка нескольких подписантов: каждому — отдельная метка.;

  - `CmsSignedDataVerifier.verifyAll()` — AND-семантика (все подписанты
    обязаны пройти).;

  - Кросс-валидация с BouncyCastle, КриптоПРО, OpenSSL (модуль
    `x-validation-tests/cadest`).;

  - Интеграционный тест с боевым TSP-сервером
    `pki.skbkontur.ru/tsp2012/tsp.srf`: HTTP POST, разбор TimeStampResp,
    извлечение TSA-сертификата, проверка messageImprint + подпись TSA,
    построение цепочки (TSA → ООО «Сертум-Про» → Минцифры России),
    `addTimestamp` → CAdES-T → `verifyCAdEST` — полный цикл пройден.
    Также проверены `testca.cryptopro.ru` (ГОСТ 34.11-94 — не
    поддерживается crypto-gost) и `pki.tax.gov.ru` (Стрибог, но DN
    цепочки не совпал по порядку RDN). См. пример `examples/pkix/` —
    `TspRealServerDemo`.

### Изменено

- **`GostPkcs12Loader` / `Pkcs12Loader` — breaking change.**
  Двухаргументный `load(pfxData, password)` удалён — его неявный
  `allowJdkFallback=true` тихо делегировал не-ГОСТ PFX в SunJCE, нарушая
  правило «криптография только через org.rssys.gost.\*». Оставлен только
  3-аргументный `load(pfxData, password, allowJdkFallback)`. Все
  вызывающие (включая `GostSsl`, `GostSslBuilder`) обновлены.

- **`Pkcs12Loader` —
  `@Deprecated(since = "0.6.0", forRemoval = false)`.** Javadoc
  указывает на `GostPkcs12Loader.load()` и
  `GostPkcs12Loader.adaptPrivateKey()` напрямую. Прослойка сохранена для
  возможности загрузки PFX через JDK.

- **`GostPkcs12Loader.adaptPrivateKey()` — `static` → `public static`.**
  Метод доступен извне пакета `pkix.cert` напрямую, без
  deprecated-прослойки.

- **`GostCertificateBuilder` — self-signed сертификаты.** При сборке
  self-signed сертификата (без явного `.issuerDn()`) issuer DN
  автоматически копируется из subject DN. Сертификаты проходят
  `openssl verify`.

- **`GostCertificateBuilder.buildCdpExtension()` — кодирование CDP.**
  Реализован RFC 5280 §4.2.1.14: `DIST_POINT_NAME` CHOICE с
  `[0] IMPLICIT` fullName (тег заменяет SEQUENCE, а не оборачивает его).
  `openssl x509 -text` отображает: `Full Name: URI:http://...`.

- **`GostOcspResponseBuilder` — responderId и статусы сертификата.**
  **responderId:** `[1] EXPLICIT` (byName) с реальным subject DN
  подписанта (RFC 6960 §4.2.1). **Статусы:** `.good()`,
  `.revoked(String)`, `.revoked(String, ReasonCode)`, `.unknown()`.
  Кодирование: good — `[0] IMPLICIT NULL`, revoked —
  `[1] IMPLICIT RevokedInfo` (GeneralizedTime + опциональный
  `[0] EXPLICIT ENUMERATED` CRLReason), unknown — `[2] IMPLICIT NULL`
  (RFC 6960 CertStatus CHOICE).

- **`SingleOcspResponse.isUnknown()` — поддержка примитивного тега.**
  Принимает оба DER-тэга неизвестного статуса: `0xA2` (constructed) и
  `0x82` (primitive), симметрично `isGood()` (`0xA0` / `0x80`).

- **`GostCertificateBuilder.extendedKeyUsage(boolean, String...)`** —
  построение EKU с флагом критичности (RFC 5280 §4.2.1.12).

- **`CmsSignedDataBuilder` — SignerInfo.signatureAlgorithm.** Использует
  OID алгоритма подписи с дайджестом (`SIGN_ALG_*`, 1.2.643.7.1.1.3.x),
  как в сертификатах, CRL и OCSP (RFC 5652 §5.3).

- **`GostPkcs12Builder` — выбор длины хеша MAC.** Fluent-метод
  `macHashLen(int)` в `Builder` (32 = Streebog-256, 64 = Streebog-512).
  `GostPkcs12Mac.compute()` — новая перегрузка с параметром `hashLen`.
  По умолчанию Streebog-512. **Примечание:** OpenSSL 3.6.0-gost не
  поддерживает HMAC-Streebog для PKCS12 MAC — кросс-валидационный
  `@Disabled`.

- **Кросс-валидационные тесты — сертификаты, CRL, OCSP.** Три новых
  модуля в профиле `crossval`: `x-validation-tests/cert/` — 9 тестов
  (verify self-signed, цепочка, x509 -text, -pubkey, -checkhost,
  -fingerprint, -issuer, PEM roundtrip, порченая подпись);
  `x-validation-tests/crl/` — 7 тестов (пустой, отозванный, reasonCode,
  fingerprint, порченая подпись, Delta CRL с deltaCRLIndicator, base CRL
  с freshestCRL); `x-validation-tests/ocsp/` — 7 сценариев +
  параметризация по кривым (good, revoked, unknown, verify, обе кривые,
  запрос к openssl -reqin, запрос от openssl -reqout).

- **Кросс-валидация OCSP и TSP с BouncyCastle (в обе стороны).**
  `x-validation-tests/ocsp/` — +23 теста: good/revoked/unknown ответы,
  delegated certs, nonce, верификация подписи, запросы единичные и
  multi-cert, CertID round-trip, обе кривые.
  `x-validation-tests/cadest/` — +15 тестов TSP: TimeStampReq/Token/Resp
  round-trip, nonce, verify с критическим EKU `timeStamping`,
  TspResponseBuilder → BC (granted/rejected/nonce/imprint).

- **Расширение кросс-валидации CMS и PKCS12.** `x-validation-tests/cms/`
  — +2 теста (asn1parse + библиотечная верификация для инкапсулированной
  и detached SignedData; L3 openssl cms -verify заблокирован
  ограничением OpenSSL 3.6.0-gost). `x-validation-tests/pkcs12/` — +1
  тест (библиотечный ключ → PFX → OpenSSL, `@Disabled` — ограничение
  OpenSSL).

- **Makefile-очистка без Maven.** `make clean` в корне и подмодулях
  заменяет `mvn clean -q` на `find -name target -exec rm -rf`. Исключён
  запуск JVM, очистка мгновенная. Новые модули `cert/`, `crl/`, `ocsp/`
  — с Makefile и в списке очистки.

### GostOids — новые константы

- `STREEBOG_256_HASH_LEN = 32` — для `macHashLen(32)` в PKCS#12.

### Добавлено

- **Расширение `DerCodec`** — для поддержки CMS: `encodeNull()`,
  `encodePrintableString()`, `encodeSetOf()` с DER-сортировкой (X.690
  §11.6), `compareDer()`. Поддержка длин 0x83/0x84 (до 4GB). BER
  indefinite-length: `INDEFINITE_LENGTH`, `findEoc()` с отслеживанием
  вложенности, `parseSetContents()` для SET OF с BER. Константы
  `TAG_NULL`, `TAG_PRINTABLE_STRING`, `TAG_IA5_STRING`,
  `TAG_ENUMERATED`.

- **`DerCodec.encodeTime()`** — кодирование времени в UTCTime /
  GeneralizedTime (RFC 5280 §4.1.2.5), автоматический выбор тега по
  длине строки.

- **`DerCodec.encodeContextConstructed()`** — кодирование explicit
  context tag `[n]` для DER.

- **`GostDerCodec.subjectPublicKeyPointBytes(PublicKeyParameters)`** —
  извлечение байт точки открытого ключа (x\_LE || y\_LE, RFC 4491
  §2.3.2) для вычисления Subject Key Identifier. Выделено из
  `encodePublicKey()` без дублирования.

### Изменено

- **`DerCodec.checkTag` — публичный доступ.** Сделан `public` (был
  `private`). Используется `GostPkcs12Parser` и `GostCertificate` для
  проверки тегов DER.

- **`CtrAcpkmMode.encryptOnly()`.** Добавлен публичный метод
  `encryptOnly()` — семантически корректный алиас `decryptOnly()` (CTR
  симметричен). Используется в `CmsEnvelopedDataBuilder` и
  `GostPbes2.encryptKey()` вместо `decryptOnly()`.

### Исправлено

- **DoS-защита в `DerCodec.parseBitString()` и `parseInteger()`.**
  Добавлена проверка длины контента ≤ 65536 байт перед
  `Arrays.copyOfRange()`. Фаззинг-тесты (`DerCodecFuzzTest`) выявили
  OutOfMemoryError при гигантских DER-длинах, генерируемых Jazzer’ом.
  `parseOctetString()` оставлен без лимита — используется для
  пользовательских данных произвольного размера (CMS EnvelopedData,
  SignedData). Находка фаззера.

## Модуль crypto-gost-tls13

### Добавлено

- **`TlsCertUtils`** — новый класс со статическими TLS-утилитами:
  `hasSignatureScheme()`, `getNamedGroup()`, `verifyOcspResponse()`,
  `matchesOidFilter()`. Вся TLS-специфичная логика, ранее жившая в
  instance-методах `TlsCertificate`, вынесена сюда.

### Изменено

- **Зависимость `crypto-gost-pkix`** — `GostOids` вынесен в новый
  модуль.

- **`GostCertificate` — основной тип сертификата во всём
  TLS/JSSE-коде.** `TlsSession.getPeerCertificates()` возвращает
  `List<GostCertificate>`. `TlsMessageParser.parseCertificate()` создаёт
  `GostCertificate` напрямую. Конфиги (`TlsClientConfig`,
  `TlsServerConfig`, `TlsClientCredentials`, `TlsServerCredentials`)
  типизированы по `GostCertificate`. `TlsMessageBuilder` хранит цепочку
  как `List<GostCertificate>`.

- **`TlsCertificate` — удалён.** Все статические фабрики (`fromDer`,
  `fromPemOrDer`, `listFromPem`, `chainToPem`, `isPem`, `isPkcs12`,
  `pemToDer`) доступны напрямую в `GostCertificate` (модуль
  `crypto-gost-pkix`). Замена тривиальна: `TlsCertificate.method()` →
  `GostCertificate.method()`. Экземплярная модель
  (`new TlsCertificate(der)`) → `new GostCertificate(der)`. Это breaking
  change.

- **`TlsCertUtils.KNOWN_EXTENSION_OIDS`** — сырые OID-строки заменены на
  константы из `GostOids` (`EXT_SKI`, `EXT_KU`, `EXT_SAN`, `EXT_BC`,
  `EXT_CDP`, `EXT_CP`, `EXT_AKI`, `EXT_EKU`, `EXT_AIA`). Устранено
  дублирование.

- **`TlsCertificateValidator` — принимает `List<GostCertificate>`
  напрямую.** Убран промежуточный `Stream`/`collect`-адаптер. Валидация
  цепочки делегируется в `ChainValidator` (pkix) без конвертации типов.
  `verifyOcspResponse`, `hasSignatureScheme` заменены на вызовы
  `TlsCertUtils.*`.

- **Сертификатная инфраструктура мигрирована в pkix.** Удалено 10
  продакшен-файлов из `tls13/cert/`: `TlsDerParser`, `OcspCertIdHasher`,
  `GostPkcs12Builder/Parser/Loader/Mac`, `GostPbes2`, `Pkcs12Loader`,
  `TlsOcspVerifier`, `TlsCrlVerifier`. Заменены на классы `pkix.cert.*`.

- **Упрощение `TlsTestHelper`.** Приватные `buildDn`, `buildCert`,
  `buildTbs`, `buildCrl`, `buildOcspResponse` удалены — делегированы в
  `GostCertificateBuilder`, `GostCrlBuilder`, `GostOcspResponseBuilder`.
  Мёртвые константы `TAG_CTX_0`/`TAG_CTX_3` и метод `Set` (→
  `encodeSet`) удалены. `buildAlgId` исправлен: signwithdigest OID без
  параметров (RFC 9215 §2), дублирующий `curveOidOf` удалён.

### Исправлено

- **Удалён устаревший Javadoc со ссылками на `TlsCertificate`.** Класс
  `TlsCertificate` удалён; ссылки в `GostCertificate.getEkuOids()`,
  `getPresentExtensionOids()` и `TlsCertUtils` заменены на актуальные
  описания.

- **`TlsCrlVerifierTest` — структурная проверка `Reason.REVOKED`.** В
  тест добавлен
  `assertEquals(PkixException.Reason.REVOKED, ex.reason())` вместо
  строковой проверки `contains("revoked")`.

## Модуль crypto-gost-jsse

### Изменено

- **`CertificateBridge` — полная миграция на `GostCertificate`.**
  Удалены overload’ы `toJca(TlsCertificate)` и `toTls()`. Добавлен
  `toGost(X509Certificate)` для конвертации JCA-сертификатов в
  `GostCertificate`. Добавлен `toJca(List<GostCertificate>)` для
  конверсии списка. Убран неиспользуемый импорт `TlsCertificate`.

- **`GostSSLEngine`, `GostX509KeyManager`, `GostX509TrustManager` — все
  сигнатуры переведены с `TlsCertificate` на `GostCertificate`.** Вызовы
  `matchesOidFilter()` заменены на `TlsCertUtils.matchesOidFilter()`.
  `getCertificateChainTls()` возвращает `List<GostCertificate>`.

- **`OcspRequestBuilder` делегирует в pkix.** Логика построения DER
  OCSPRequest, CertID и подписи вынесена в `GostOcspRequestBuilder`
  (модуль pkix). Устранено ~180 строк дублирования, зависимость от
  `TlsConstants` заменена на `GostOids`.

### Исправлено

- **Прямая зависимость `crypto-gost-pkix`.** Модуль jsse использовал 12
  классов из `org.rssys.gost.pkix.*` только транзитивно через tls13.
  Добавлена явная зависимость в pom.xml.

- **Удалён `@Deprecated OcspRequestBuilder.build()`.** Метод без
  nonce-защиты заменён на `buildWithNonce()`.
  `JdkHttpOcspFetcher.fetch()` обновлён. `OcspRequestBuilderTest`
  обновлён (4 вызова `build()` → `buildWithNonce()`).

- **FQN заменён на import.** `GostSsl.isEncryptedPrivateKey()`
  использовала `org.rssys.gost.pkix.GostOids.PBES2` — заменено на
  короткое имя с import.

- **`GostX509KeyManager.chooseAliasForHostname()` — wildcard матчил
  пустую первую метку.** Приватный метод `matchHostname()` не проверял
  `firstLabel.isEmpty()` — сертификат с `*.example.com` мог быть выбран
  для hostname `.example.com`, в отличие от
  `GostCertificate.verifyHostname()`. `matchHostname()` удалён, вызов
  заменён на `GostCertificate.matchDnsName()` (устранение дублирования +
  исправление бага).

## Фаззинг

### Добавлено

- **`CmsVerifierFuzzTest` (модуль pkix)** — фаззинг-тесты для
  `CmsEnvelopedDataDecryptor` и `CmsSignedDataVerifier` на случайном
  DER-входе. Защита от AIOOBE, NPE, OOM при битых CMS-сообщениях. Модуль
  pkix получил независимую копию `FuzzTestUtils` (29 строк,
  package-private).

- **`GostKdfFuzzTest` (модуль core)** — фаззинг-тест для
  `KDF_GOSTR3411_2012_256` и `KDF_TREE_GOSTR3411_2012_256`.

- **`GostCrlFuzzTest` (модуль pkix)** — фаззинг-тест парсинга CRL на
  случайном DER.

- **`GostCsrParserFuzzTest` (модуль pkix)** — фаззинг-тест парсинга CSR.

- **`TlsCertUtilsFuzzTest` (модуль tls13)** — фаззинг-тест
  TLS-сертификатных утилит.

- **`TlsHandshakeEngineFuzzTest` (модуль tls13)** — фаззинг-тест TLS
  handshake engine.

## Кросс-валидация

### Добавлено

- **Диагностический тест EnvelopedData (`envelopedDataDiagnostics()` в
  `CmsCrossValidationTest`).** Проверка DER-структуры через
  `openssl asn1parse`, структурная проверка параметров контентного шифра
  (SEQUENCE по RFC 9337 §7.3), roundtrip библиотека→библиотека. OpenSSL
  с gost-engine не поддерживает `CMS EnvelopedData` (нет реализации
  `EVP_PKEY_OP_ENCAPSULATE`/`DECAPSULATE` для ГОСТ-ключей), поэтому
  полноценная кросс-валидация невозможна.

## Документация

- Обновлены README.adoc в модулях `core`, `pkix`, `tls13`, `jsse` —
  актуализированы описания модулей, импорты и примеры кода после
  миграции сертификатной инфраструктуры и перехода на fluent builder
  API.

# \[0.5.6\] - 20-06-2026

## Модуль crypto-gost-core

### Добавлено

- **`GostCurves` — алиасы XchA/XchB (RFC 4357)**. Добавлены OID
  `1.2.643.2.2.36.0` (XchA) и `1.2.643.2.2.38.0` (XchB) как алиасы
  кривых CryptoPro-A и CryptoPro-B соответственно. ФНС и ряд других УЦ
  выпускают сертификаты с параметром XchA — без этих алиасов загрузка
  таких сертификатов завершалась ошибкой `Unknown GOST curve`.

## Модуль crypto-gost-tls13

### Исправлено

- **`TlsCertificate.parseCdpUris()` — поддержка IMPLICIT `[0]` fullName
  в CRL Distribution Points**. ФНС и другие УЦ кодируют `GeneralNames`
  без обязательной `SEQUENCE`-обёртки (элементы `GeneralName` лежат
  непосредственно под `[0]`). Ранее парсер ожидал только `TAG_SEQUENCE`
  (0x30) и молча пропускал CDP-записи в таком формате. Теперь оба
  варианта обрабатываются корректно.

- **`TlsDerParser.parseLength()` — поддержка 4-байтового поля длины
  DER**. Лимит `numBytes > 3` увеличен до `numBytes > 4`. Необходимо для
  разбора CRL ФНС объёмом ~45 МБ: длина внешнего `SEQUENCE` кодируется 4
  байтами (`0x84 0x02 0xB1 0x1F…`), что превышает максимум 3-байтовой
  кодировки (16 777 215 байт). Безопасность не снижается: `readTlv`
  проверяет `valueEnd ≤ der.length` независимо от заявленной длины;
  аллокаций по значению длины нет.

- **`TlsDerParser.readTlv()` — защита от integer overflow при 4-байтовой
  длине DER**. Фаззинг выявил два вектора:

  - `contentLen < 0` — 4-байтовая длина ≥ 2³¹ (например, `0x84848484`)
    интерпретировалась как отрицательный `int`; `valueEnd` оказывался
    отрицательным и проходил проверку `valueEnd > der.length` →
    `AIOOBE`.

  - `valueStart + contentLen` переполняет `int` — длина `0x7FFFFFFF`
    положительна, но сумма с `valueStart` уходит в отрицательное
    значение → тот же эффект.

    Добавлены две явные проверки перед использованием длины как индекса:
    `contentLen < 0` и `valueEnd < valueStart`. Crash-файлы добавлены в
    corpus фаззера.

### Добавлено (тесты)

- **`TlsCertificateTest`** — скорректирован и расширен набор тестов
  `TlsDerParser`: граничный случай `numBytes=5 > 4` обновлён под новый
  лимит; добавлены тесты на оба overflow-вектора в `readTlv`
  (`contentLen` отрицательный, переполнение `valueStart + contentLen`).

## Модуль examples/tls

### Добавлено

- **`CertificateStatusCheck`** — новый пример проверки статуса
  ГОСТ-сертификата по реальной инфраструктуре УЦ:

  - загрузка сертификата субъекта и CA из DER-файлов;

  - извлечение OCSP URI, `caIssuers` URI, CDP URI из расширений;

  - автоматическое скачивание CA-сертификата из `caIssuers` (RFC 5280);

  - OCSP-запрос с nonce (RFC 8954) через `JdkHttpOcspFetcher`;

  - верификация OCSP-ответа — подпись, статус, nonce, делегированный
    responder (`TlsOcspVerifier.extractDelegatedCerts`);

  - загрузка CRL через `JdkHttpCrlFetcher` с failover по CDP-точкам;

  - верификация CRL — подпись CA, срок действия, наличие серийного
    номера в списке отозванных (`TlsCrlVerifier`).

    Проверено на реальном сертификате ФНС России: CRL 45 МБ загружен и
    верифицирован, делегированный OCSP-responder («ФНС России»)
    корректно распознан и проверен.

# \[0.5.5\] - 19-06-2026

Этот релиз целиком посвящен кросс-валидации с Крипто-Про CSP. Установка
последнего, помогла выявить ранее не обнаруживаемые ошибки.

## Модуль crypto-gost-tls13

### Исправлено

- **`TlsMessageBuilder.buildHelloRetryRequest` — корректный wire-формат
  key\_share (RFC 8446 §4.2.8)**.  
  HRR передавал `KeyShareEntry` с пустым `key_exchange` (4 байта:
  NamedGroup + `0x00 0x00`), тогда как RFC 8446 §4.2.8 требует
  `KeyShareHelloRetryRequest` — только 2 байта NamedGroup без поля
  `key_exchange`. Исправлено: `ks = new byte[2]`. Старый формат нарушал
  совместимость с OpenSSL и КриптоПро.

- **`TlsHandshakeEngine.receiveClientHello` — `legacy_session_id` теперь
  отражается и в HRR (RFC 8446 §4.1.3)**.  
  Вызов `setClientSessionId` перенесён до возможной отправки HRR. Ранее
  HRR всегда содержал `legacy_session_id = 0x00`, даже если клиент
  передал session\_id в CH1, что нарушало требование §4.1.3 об
  эхо-отражении.

- **`TlsHandshakeEngine.computeEcdheShared` — убран кофактор из ECDHE**.
  Метод умножал приватный ключ на кофактор кривой (`myPriv * h`), что
  нарушает симметрию shared secret при `h > 1` (GC512C, h=4): стороны
  получали разные значения. RFC 9367 §4.1 требует обычный ECDH —
  приватный ключ уже в подгруппе порядка q, cofactor multiplication
  здесь семантически неверен. При `h=1` (все TLS-кривые кроме GC512C)
  поведение не изменилось. Удалено поле и геттер `getCofactor()` из
  `TlsCiphersuite` как более не используемые.

## Кросс-валидация с КриптоПРО CSP 5.0

Выполнен полный цикл кросс-валидации TLS 1.3 и криптоядра между
crypto-gost и КриптоПРО CSP 5.0 (curl 8.19.0-CPRO / csptest), включая
независимую трёхстороннюю сверку с OpenSSL 3.6 gost-engine.

### Изменения в коде

- `InteropTestServer` (*examples/tls*): добавлены CLI-флаги `--curve`,
  `--cipher` (L/S-mode), `--mtls`, `--client-ca-file <der>`, `--psk` и
  `--keyupdate` для покрытия всех сценариев кросс-валидации с CSP.

### TLS-сценарии

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Сценарий</th>
<th style="text-align: left;">Кривая</th>
<th style="text-align: left;">Cipher</th>
<th style="text-align: left;">Результат</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>curl GET / POST</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103 (L)</p></td>
<td style="text-align: left;"><p>✅ HTTP 200</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc raw TLS</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103 (L)</p></td>
<td style="text-align: left;"><p>✅ HTTP 200</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc, S-mode</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC105 (S)</p></td>
<td style="text-align: left;"><p>✅ Negotiated 0xc105, ErrorCode
0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc с HRR</p></td>
<td style="text-align: left;"><p>GC256C (0x24)</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc с HRR</p></td>
<td style="text-align: left;"><p>GC256D (0x25)</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc с HRR</p></td>
<td style="text-align: left;"><p>GC512A (0x26)</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc с HRR</p></td>
<td style="text-align: left;"><p>GC512B (0x27)</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc, S-mode + HRR</p></td>
<td style="text-align: left;"><p>GC512A (0x26)</p></td>
<td style="text-align: left;"><p>0xC105 (S)</p></td>
<td style="text-align: left;"><p>✅ Negotiated 0xc105, ErrorCode
0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>csptest -tlsc, S-mode + HRR</p></td>
<td style="text-align: left;"><p>GC512B (0x27)</p></td>
<td style="text-align: left;"><p>0xC105 (S)</p></td>
<td style="text-align: left;"><p>✅ Negotiated 0xc105, ErrorCode
0</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TLSTREE re-keying (POST
1K/12K/32K/64K)</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅ HTTP 200</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS (без клиентского
сертификата)</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅ alert certificate_required</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS полный цикл (с клиентским
сертификатом CSP)</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅ Peer certs: 1, HTTP 200</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>KeyUpdate инициирован сервером</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅ HTTP 200, CSP принял данные на новых
ключах</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>TLS 1.2 ClientHello (csptest -proto
6)</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✅ корректно отклонён</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>JSSE Undertow + curl</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>0xC103</p></td>
<td style="text-align: left;"><p>✅ эхо тела</p></td>
</tr>
</tbody>
</table>

Подтверждённые возможности протокола:

- HelloRetryRequest — полный цикл GC256A→GC256C/D/GC512A/B.

- Копирование `legacy_session_id` в HRR (RFC 8446 §4.1.3).

- ClientHello CSP предлагает 6 cipher suites (включая Магму
  0xC104/0xC106) и 7 ГОСТ-схем подписи (все кривые RFC 9367).

- ECDHE с кофактором 1 — корректен для всех TLS-кривых.

- S-mode (0xC105) совместим с HRR — подтверждено на GC512A и GC512B.

- mTLS с клиентским сертификатом CSP (файловый контейнер, ГОСТ Р
  34.10-2012) — сервер корректно верифицирует цепочку и завершает
  handshake.

- KeyUpdate (RFC 8446 §4.6.3) инициированный сервером — CSP принимает
  смену ключей и продолжает передачу данных без разрыва соединения.

- TLS 1.2 ClientHello отклоняется с `alert_missing_extension`
  (`"supported_versions extension required"`) — ожидаемое fail-closed
  поведение TLS 1.3-only сервера.

Известные ограничения протокола:

- `GC256A (0x0022)`: CSP (Schannel) не кладёт key\_share для этой группы
  в ClientHello, ожидая HRR от сервера. При прямом ECDHE (сервер
  отвечает GC256A key\_share) — ошибка `SEC_E_MESSAGE_ALTERED`.
  Ограничение клиента CSP; crypto-gost обрабатывает группу корректно.
  Рабочий сценарий: сервер на GC256B/C/D/GC512A/B → HRR → CSP
  переключается на запрошенную группу.

- `GC512C (0x0028)`: кофактор h=4, ECDHE на этой кривой расходится на
  уровне самой группы. В TLS 1.3 не используется — RFC 9367 разрешает
  только кривые с h=1.

- PSK session resumption: CSP (Schannel) не реализует повторное
  использование сессии TLS 1.3 — при повторном подключении выполняется
  полный handshake вне зависимости от полученного NewSessionTicket.
  Ограничение Schannel; InMemoryPskStore и логика NST в crypto-gost
  проверены внутренними тестами
  (`GostSslContextHandshakePskResumptionTest`).

### Криптоядро

- **Streebog-256** — хэши совпадают побайтово (`csptest -hash` vs
  `Digest.digest256()`).

- **Параметры кривой и EC-арифметика** —
  `id-GostR3410-2001-CryptoPro-A-ParamSet` подтверждён побайтово
  идентичным `ECParameters.cryptoProA()`; публичные ключи CSP лежат на
  кривой, корректного порядка (`n·Q = O`).

- **sign/verify** — подпись X.509-сертификата CSP (`-makecert`)
  верифицируется crypto-gost через `ECDSASigner` при декодировании
  подписи как `s‖r` (CSP хранит подпись как `r‖s`).

  Несовместимость выявлена только в команде
  `csptest -keyset -sign GOST12_256`: подписи, созданные именно этой
  командой, не верифицируются ни crypto-gost, ни OpenSSL 3.6
  gost-engine, ни самим CSP через `-pkverify`.

  Независимая трёхсторонняя сверка (3×3, все направления sign/verify)
  подтверждает: crypto-gost и OpenSSL gost-engine полностью взаимно
  совместимы. Точный механизм расхождения `-keyset -sign` не установлен
  (исходный код CSP закрыт); затронута только эта команда — TLS 1.3
  handshake, хэширование Streebog и параметры кривой подтверждены
  полностью совместимыми.

### Дополнительно (внутренние тесты)

- **KeyUpdate двусторонний** (`update_requested=true`) — проверен через
  `InMemoryTlsTransport` с передачей данных до и после обновления ключей
  с обеих сторон.

  Наблюдение: csptest интерпретирует `NewSessionTicket` как
  `Server requested renegotiate!` — артефакт отображения Schannel, не
  ошибка протокола. \* **PSK session resumption** — подтверждён тестом
  `GostSslContextHandshakePskResumptionTest` (модуль
  `crypto-gost-netty`).

# \[0.5.4\] - 14-06-2026

## Модуль crypto-gost-tls13

### Исправлено

- **Сервер не прерывает handshake при GREASE-значениях в key\_share (RFC
  8701 §3.1)**

### Добавлено

- **`TlsCertificate.pemToDer(byte[])`** — сделан публичным, устраняет
  дублирование с `GostSsl.pemToDer(String)` (приватный метод-обёртка
  удалён).

- **`TlsCertificate.isPem(byte[])` и `isPkcs12(byte[])`** — явные
  детекторы формата PEM и PKCS12. `isPkcs12` использует дискриминатор
  SEQUENCE + INTEGER 3 без полного разбора PFX.

- **`GostPkcs12Loader.decryptPrivateKey(byte[], char[])`** — расшифровка
  закрытого ключа (PKCS#8) по ГОСТ PBES2. Для не-ГОСТ PBE бросает
  `IllegalArgumentException`. Пароль затирается после расшифровки.

## Модуль crypto-gost-jsse

### Добавлено

- **`GostSslBuilder.trustCaFromPem(byte[] pemChain)`** — добавляет все
  CA-сертификаты из PEM-цепочки (включая multi-CA файлы) в trust store
  за один вызов.

- **`GostSslBuilder.certificate(byte[], byte[])` и `trustCa(byte[])`** —
  теперь с авто-определением формата PEM/DER. PEM-данные автоматически
  конвертируются в DER. Для PEM-цепочки в `trustCa` добавляются все
  сертификаты.

- **`GostSsl.loadPrivateKey(byte[])`** и
  **`GostSsl.loadPrivateKey(byte[], char[])`** — единая точка загрузки
  закрытого ключа с авто-определением формата (PEM/DER) и поддержкой
  расшифровки через ГОСТ PBES2.

# \[0.5.3\] - 12-06-2026

## Модуль crypto-gost-core

### Исправлено

- Уточнена документация к примерам.

- **Добавлены OID TC26-256-ParamSet B/C/D как алиасы кривых CryptoPro
  (RFC 7836).** Сертификаты с OID `1.2.643.7.1.2.1.1.{2,3,4}` ранее
  падали с `Unknown GOST curve`. ParamSet B — та же кривая, что
  CryptoPro-A; ParamSet C — CryptoPro-B; ParamSet D — CryptoPro-C.

## Модуль crypto-gost-tls13

### Исправлено

- **HelloRetryRequest без key\_share (RFC 8446 §4.2.8).**
  parseServerHello() больше не требует key\_share — RFC разрешает
  опускать его в HRR. handleHelloRetryRequest() при requestedGroup==0
  подставляет selectedNamedGroup (продолжает работу с той же группой,
  что в CH1). Добавлен buildHelloRetryRequest(cipherSuiteId, cookie) —
  генератор HRR без key\_share для тестов. gost-curl успешно соединяется
  с серверами, не включающими key\_share в HRR.

- **ALPN в EncryptedExtensions приведён к RFC 7301 §3.1.**
  buildEncryptedExtensions() теперь включает 2-байтовый
  ProtocolNameList.length; parseEncryptedExtensions() корректно
  пропускает listLen и читает имя со смещения off+3. Для кодирования
  listLen используется encodeUint16 вместо (byte)(1+nameLen) — устранено
  переполнение при длине протокола 255.

## Модуль crypto-gost-jsse

### Исправлено

- **Контекст ошибки в processHandshakeFrames().** Вместо «Handshake
  error» пробрасывается оригинальное сообщение TlsException — ускорена
  диагностика handshake-сбоев.

## Модуль examples/jsse (gost-curl)

### Добавлено

- **Поддержка mTLS в gost-curl.** Добавлены опции `--cert <файл>` и
  `--key <файл>` для клиентского сертификата. KeyManager создаётся через
  `GostX509KeyManager + CertificateBridge`.

- **Кросс-валидация со стендом TLS 1.3 ИнфоТеКС
  (<https://infotecs.ru/products/tls-test.php/>,
  <https://91.244.183.22>).** Выполнен прогон 28 сценариев на 21 порту
  (7 кривых × 3 режима: one-way, optional, mTLS).

Результаты: **28/28** успешно.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Режим</p></td>
<td style="text-align: left;"><p>Порты</p></td>
<td style="text-align: left;"><p>Результат</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>One-way TLS (игнорировать
cert)</p></td>
<td style="text-align: left;"><p>15001, 15011, 15021, 15031, 15071,
15081, 15091</p></td>
<td style="text-align: left;"><p>✅ 7/7</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>One-way TLS (опциональный
cert)</p></td>
<td style="text-align: left;"><p>15002, 15012, 15022, 15032, 15072,
15082, 15092</p></td>
<td style="text-align: left;"><p>✅ 7/7</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS с сертификатом</p></td>
<td style="text-align: left;"><p>15003, 15013, 15023, 15033, 15073,
15083, 15093</p></td>
<td style="text-align: left;"><p>✅ 7/7</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS без сертификата (ожидаемый
400)</p></td>
<td style="text-align: left;"><p>15003, 15013, 15023, 15033, 15073,
15083, 15093</p></td>
<td style="text-align: left;"><p>✅ 7/7</p></td>
</tr>
</tbody>
</table>

Все handshake — TLS 1.3, cipher suite —
`TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L` (0xC103), сервер nginx
1.26.3.

# \[0.5.2\] - 11-06-2026

## Модуль crypto-gost-jsse

### Исправлено

- **Устранено двойное шифрование close\_notify при закрытии соединения
  через стандартный JSSE wrap()**. closeOutbound() сохранял уже
  зашифрованную запись в outgoingQueue, откуда wrap() забирал её и
  шифровал повторно — клиент получал мусор и отвечал bad\_record\_mac
  (alert 20). Запись вынесена в отдельное поле pendingCloseRecord;
  wrap() передаёт её в dst напрямую. GostSSLSocket (использует
  pollOutboundRecord) не затронут. Добавлен regression-тест.

- **Исправлен deadlock при передаче больших файлов**\* через Undertow (и
  любой JSSE-совместимый сервер). unwrap() при получении close\_notify
  возвращал Status.OK вместо Status.CLOSED — сервер продолжал ждать
  данных и зависал. Добавлен regression-тест.

- **Устранён data race по JMM**. Поля readerRecord, writerRecord,
  deferredWriterDestroy, ciphersuite объявлены volatile. До этого поля
  записывались под одним локом (inboundLock или outboundLock), читались
  под другим без гарантий видимости.

- **Исправлен двойной счёт bytesProduced в drain loop** при обработке
  нескольких app data записей подряд после handshake: dstPosBefore не
  обновлялся между итерациями, дельта накапливалась от начальной
  позиции. Добавлен regression-тест.

### Добавлено

- Пример работы JSSE-сервера Undertow и клиента на базе OpenSSL 3.6.0 с
  engine-gost. Файлы
  [JSSE-сервер](examples/jsse/src/main/java/org/rssys/gost/jsse/examples/undertow/FileReceiveServer.java)
  и [клиент openssl](examples/jsse/send-file.sh). Сервер принимает в
  многопоточном режиме файлы, никуда их не сохраняет.

# \[0.5.1\] - 10-06-2026

## Модуль crypto-gost-tls13

### Исправлено

- **Исправлено нарушение RFC 8446 §5.2:** библиотека отклоняла TLS 1.3
  записи с padding с ошибкой ALERT\_RECORD\_OVERFLOW. По спецификации
  TLSInnerPlaintext может содержать до 255 байт padding после inner
  content type, что даёт максимум 16640 байт до тега — любой корректный
  TLS 1.3 стек вправе это использовать. Буфер plaintext в TlsRecord и
  граница проверки в doDecrypt расширены с
  MAX\_PLAINTEXT\_LENGTH (16384) до MAX\_CIPHERTEXT\_LENGTH − tagLen
  (16624). Написаны тесты.

- **Исправлено нарушение RFC 8446 §4.1.3**: при отсутствии пересечения
  cipher suites между клиентом и сервером теперь отправляется
  handshake\_failure вместо продолжения handshake с дефолтным
  ГОСТ-suite.

### Добавлено

- **oid\_filters (RFC 8446 §4.2.5)**. Сервер включает в
  CertificateRequest фильтры по OID расширений сертификата клиента.
  Клиент выбирает сертификат, удовлетворяющий фильтрам, или отправляет
  пустой certificate\_list.

  - Сервер:: `TlsServerConfig.withOidFilters(List<OIDFilter>)` — задаёт
    фильтры; engine автоматически включает их в CertificateRequest.

  - Клиент:: `ClientCertificateSelector` — функциональный интерфейс для
    выбора сертификата по `acceptedCaDns` и `OIDFilter`;
    `TlsClientConfig.withClientCertificateSelector(selector)` —
    установка.

  - Matching:: `TlsCertificate.matchesOidFilter(OIDFilter)` — реализует
    правила RFC 8446 §4.2.5:

    - **KU** (2.5.29.15): все биты фильтра — подмножество KU сертификата

    - **EKU** (2.5.29.37): все OID фильтра присутствуют в EKU;
      `anyExtendedKeyUsage` запрещён

    - **Известные расширения**: проверка наличия и (при непустых values)
      сравнение DER-значения

    - **Неизвестные OID**: игнорируются (per RFC)

  - Новые OID:: `GostOids.EKU_UKEP` = `"1.2.643.100.113.1"` (УКЭП),
    `GostOids.EKU_UNEP` = `"1.2.643.100.113.2"` (УНЭП); соответствующие
    `UKEP_OID_BYTES` / `UNEP_OID_BYTES` в `TlsDerParser`.

  - Кросс-валидация:: `testServerOidFilters` — проверка wire-формата
    oid\_filters с OpenSSL s\_client; `testServerMtls` расширен
    assert-ом `matchesOidFilter(УКЭП)` на peer-сертификате.

# \[0.5.0\] - 09-06-2026

## Общее

- Добавлены make-цели fuzz и fuzz-all для запуска фаззинг-тестов по
  отдельному модулю и по всем трём параллельно.

- В Makefile добавлен `SHELL := /bin/bash` — `PIPESTATUS` и `pipefail`
  требуют bash, не работают с dash (Debian/Ubuntu по умолчанию).

## Модуль crypto-gost-core

### Добавлено

- **`AuthenticatedStream` — KDF key separation**.  
  Вместо прямого использования одного мастер-ключа для шифрования (CTR,
  ключ `ctrKey`) и имитозащиты (CMAC, ключ `cmacKey`) каждый новый поток
  выводит два независимых ключа через KDF
  (`KDF_TREE_GOSTR3411_2012_256`). Начальное заполнение для KDF —
  случайный `streamNonce` (8 байт), который генерируется автоматически
  при создании потока и записывается в заголовок. Это гарантирует, что
  от одного и того же мастер-ключа, производные ключи для шифрования и
  имитозащиты будут разными.

  При расшифровании `streamNonce` читается из заголовка и KDF
  воспроизводит те же ключи. Ключи `cmacKey` и `ctrKey` вычислительно
  независимы друг от друга и от производных ключей других потоков.
  Мастер-ключ не модифицируется; производные ключи затираются при
  закрытии потока.

- Добавлены fuzzing-тесты для четырёх security-критичных точек, не
  покрытых ранее: верификация подписи ГОСТ Р 34.10
  (GostSignatureSpiFuzzTest, SignatureCodecFuzzTest), AEAD-теги MGM и
  CTR-ACPKM (GostMgmCipherSpiFuzzTest, GostCtrAcpkmCipherSpiFuzzTest),
  прямой парсинг DER-ключей без SPI-обёртки (GostDerCodecFuzzTest).

  - FuzzTestUtils переведён в public для использования из других
    пакетов. Исправлена регистрация провайдера в
    GostKeyFactorySpiFuzzTest (добавлен idempotent guard).

### Изменено

- **`AuthenticatedStream` — новый формат VERSION=0x02 (ломающее
  изменение)**.  
  Заголовок потока изменён: вместо фиксированной ASCII-сигнатуры «GOST»
  и четырёх нулевых байт — 8 случайных байт на поток (`nonce`). Каждый
  поток теперь начинается с уникальных байт, что исключает массовое
  обнаружение потоков по фиксированной сигнатуре. Весь заголовок включён
  в код аутентификации первого чанка — подмена любого байта заголовка
  обнаруживается при расшифровании. Потоки VERSION=0x01 не читаются —
  при попытке открытия возвращается сообщение о неподдерживаемой версии
  формата.

- **`AuthenticatedCipher` — EtM (Encrypt-then-MAC) + полный тег 128 бит
  (ломающее изменение)**.  
  `CMAC(IV || ciphertext)`, верификация до расшифрования — неверный тег
  не даёт oracle на plaintext. Длина тега увеличена с 64 до 128 бит,
  overhead — с 16 до 24 байт.

- **`AuthenticatedStream` — EtM (Encrypt-then-MAC) + полный тег 128 бит
  (ломающее изменение)**.  
  `CMAC(firstHeader || seqNo || flags || IV || ciphertext)` для первого
  чанка (seqNo=0), `CMAC(seqNo || flags || IV || ciphertext)` для
  остальных — IV и заголовок потока включены в аутентификацию, подмена
  любого байта заголовка или IV обнаруживается. Длина тега увеличена с
  64 до 128 бит, `CHUNK_HEADER_SIZE` — с 21 до 29 байт. Формат заголовка
  потока не изменился.

### Исправлено

- GostKeyFactorySpiFuzzTest: добавлена регистрация RssysGostProvider в
  static-инициализаторе (исправление NoSuchAlgorithmException при
  запуске через -Dtest=).

## Модуль crypto-gost-tls13

### Исправлено

- **Устранены выходы за границы массива в DER-парсерах** при усечённом
  или искажённом вводе (обнаружено фаззинг-тестами (Jazzer)):

  - TlsDerParser: parseLength, readTlv, parseSequence, parseTime —
    проверка границ перед обращением к массиву.

  - GostPkcs12Parser: peekLength, decodeLength, checkTag,
    parseConstructed — проверка границ; parseOid — проверка пустого и
    усечённого OID; parseEncryptedPrivateKeyInfo, parsePbes2Params,
    parseMacData — проверка полноты результатов разбора вложенных
    структур.

  - TlsCertificate: проверка непустоты внешней SEQUENCE сертификата и
    ненулевой длины поля версии; проверка наличия подписи и непустоты
    BIT STRING.

    Все нарушения структуры бросают IllegalArgumentException с указанием
    смещения.

### Добавлено

- **Реализована поддержка расширения max\_fragment\_length (RFC 6066
  §4)**: клиент может запросить уменьшение максимального размера
  TLS-фрагмента до 512, 1024, 2048 или 4096 байт; сервер подтверждает
  запрошенное значение в EncryptedExtensions; после handshake оба
  направления передачи фрагментируются по согласованному лимиту. Клиент
  отклоняет незапрошенное или изменённое значение от сервера с
  ALERT\_ILLEGAL\_PARAMETER.

## Модуль crypto-gost-jsse

### Добавлено

- Добавлен fuzzing-тест клиентского unwrap
  (GostSSLEngineUnwrapClientFuzzTest). Исправлена регистрация провайдера
  в GostSSLEngineUnwrapFuzzTest.

- **Реализована поддержка расширения max\_fragment\_length (RFC 6066
  §4)**: клиент может запросить уменьшение максимального размера
  TLS-фрагмента до 512, 1024, 2048 или 4096 байт; сервер подтверждает
  запрошенное значение в EncryptedExtensions; после handshake оба
  направления передачи фрагментируются по согласованному лимиту. Клиент
  отклоняет незапрошенное или изменённое значение от сервера с
  ALERT\_ILLEGAL\_PARAMETER.

### Изменено

- Удалён мёртвый код из GostSSLEngine: getReaderRecordForTest,
  getIncomingAppBufForTest, clearIncomingAppBufForTest.

# \[0.4.0\] - 07-06-2026

Данный релиз в большей степени посвящен кросс-валидации с внешними
средствами, такими как OpenSSL 3.6.0 (gost-engine + patch TLS 1.3) и
Bouncycastle 1.84.

Такая кросс-валидация позволила вскрыть большое количество ошибок, ранее
не обнаруживаемых на self-interop тестах. Также в рамках данного релиза
произведен большой рефакторниг кодовой базы. Детали всего этого описаны
ниже.

**Фактически это первый релиз, который совместим с внешним миром.**
Поэтому я удалил все предыдущие релизы в виде jar-файлов.

Crypto-gost как TLS 1.3 сервер успешно проходит полный handshake с
независимым стеком (OpenSSL gostprov) и обменивается данными. Это
означает: key schedule корректен, ECDHE работает, MGM-шифрование с
правильными ключами, TLSTREE re-keying не ломает поток, wire-формат
сертификата читается OpenSSL, подпись в CertificateVerify
верифицируется. Crypto-gost как TLS 1.3 клиент успешно верифицирует
сервер с ГОСТ-подписью и проходит handshake с OpenSSL s\_server.
Покрытые кривые: GC256B (CryptoPro-A), GC512A, GC512B. mTLS работает.

Теперь серверы приложений (Jetty 12, Tomcat 11, Undertow 2),
сконфигурированные с crypto-gost JSSE, корректно взаимодействуют с
OpenSSL s\_client на уровне TLS 1.3 + ГОСТ.

В отличие от x-validation-tests/jsse (raw GostSSLEngine/GostSSLSocket ↔
OpenSSL), эти тесты проверяют HTTP-уровень через серверное middleware:
SNI-обработку, session ticket passthrough, mTLS с внешним сертификатом,
Tomcat SSLUtil-обёртку.

Данный релиз содержит переход на публикацию артефактов в
[maven-репозиторий](https://gitflic.ru/project/red-stars-systems/crypto-gost/package).

## Модуль crypto-gost-core

### Исправлено

- **Исправлены OID эллиптических кривых TC26 (баг в GostCurves.java,
  GostOids.java)**.  
  По RFC 7836 и OpenSSL ветка 1.2.643.7.1.2.1.1.x — 256-битные кривые,
  1.2.643.7.1.2.1.2.x — 512-битные. В коде crypto-gost было наоборот.
  Математика кривых (ECParameters.java) верна — перепутаны только
  строковые идентификаторы OID.  
  **Следствие:**

  - Ключи TC26-A-256 кодировались в DER с OID от 512-битной кривой и
    наоборот;

  - Сертификаты Минцифры (512-бит, OID .1.2.1.2.1) читались только через
    fallback-костыль;

  - Кросс-валидация с engine-gost была сломана.

  - Удалён workaround FALLBACK\_256\_TO\_512 в GostDerCodec.java — он
    маскировал собственный баг, а не реальную несовместимость. После
    фикса все тесты проходят.

- **Исправлена кросс-совместимость ECDH для кривой TC26-C-512.**  
  KeyAgreement.computeSharedSecret теперь вычисляет скаляр (h·d) mod q
  вместо d, где h — кофактор кривой. TC26-C-512 — единственная
  стандартная ГОСТ-кривая с h=4. Остальные кривые имеют h=1 и поведение
  не изменилось. Поле cofactor добавлено в ECParameters.

- **Hmac.init — снято избыточное ограничение на пустой ключ.**  
  По RFC 2104 §2 ключ HMAC может быть любой длины, включая нулевую:
  пустой ключ дополняется нулями до длины блока, результат математически
  определён. Проверка key.length == 0 была ограничением реализации, не
  стандарта. Оставлен только null-guard.  
  Следствие: Pbkdf2Streebog.generate() теперь корректно работает с
  пустым паролем.

- **`Mgm.updateAAD()` — исправлен баг нарушения RFC 9058 при
  множественных вызовах**.  
  Несколько последовательных `updateAAD()` с некратными блоку данными
  давали другой тег аутентификации, чем один вызов с той же
  конкатенацией. Добавлен накопительный буфер `aadBuf`: неполный хвост
  хранится между вызовами и хэшируется только при наборе полного блока
  или финализации. Новый метод `ensureAadFinished()` вызывается из
  `processBytes`, `finishEncryption` и `finishDecryption` — корректно
  обрабатывает в том числе AAD-only сценарий (пустой plaintext).

- Устранено дублирование в Digest: четыре статических метода (digest256,
  digest512, hmac256, hmac512) вместо повторяющегося кода теперь
  делегируют двум приватным методам, которые используют уже существующие
  фабрики.

- **`AuthenticatedStream` — устранение четырёх уязвимостей**.  

  - **DoS через chunkLen (OOM)**: `OpeningStream` принимал `chunkLen` из
    wire без верхней границы — значение `0x7FFFFFFF` вызывало аллокацию
    ~2 ГБ до проверки CMAC. Исправлено: `chunkSize` из заголовка потока
    сохраняется в `OpeningStream`, `chunkLen > chunkSize` отклоняется с
    `AuthenticationException` до аллокации. Добавлена константа
    `MAX_CHUNK_SIZE = 1 МБ` — абсолютный лимит независимо от
    заголовка.  

  - **Reorder и duplicate чанков**: CMAC считался только от plaintext
    без привязки к позиции в потоке — перестановка или дублирование
    чанков проходило верификацию. Исправлено: в CMAC включён implicit
    AAD = `seqNo(8) || flags(1)`. Wire format не изменён — `seqNo`
    восстанавливается по позиции на обоих концах.  

  - **Подмена флага FLAG\_LAST**: флаг последнего чанка не был
    аутентифицирован — замена `FLAG_NORMAL` на `FLAG_LAST` и обратно не
    обнаруживалась. Исправлено через включение `flags` в AAD (см.
    выше).  

  - **Plaintext в памяти после `close()`**: внутренний буфер
    `ByteArrayOutputStream` не затирался после закрытия потока. Заменён
    на `byte[]` с явным `Arrays.fill` в `finally` блоке `close()`. При
    `AuthenticationException` в `OpeningStream` устанавливается
    `streamEnded = true` и `plainBuf` затирается до выброса
    исключения.  

### Добавлено

- [Методика кросс-валидации режимов блочного шифра
  Кузнечик](x-validation-tests/kuznyechik/doc/kuznyechik-cross-validation.md) +
  тесты. Охват: CTR/CBC/CFB/OFB/MGM, 43 размера (0..1 МБ), сверка с
  BouncyCastle, OpenSSL и предыдущей версией. Границы блоков,
  переполнение счётчика CTR и 16-битного счётчика, CVE-2025-14813.
  CBC/NoPad отдельно.

- [Методика кросс-валидации хэшей и
  MAC](x-validation-tests/digest-mac/doc/digest-mac-cross-validation.md) +
  тесты. Охват: Streebog-256/512, HMAC-Streebog-256/512,
  CMAC-Kuznyechik; 17 размеров (0..4097); сверка с BouncyCastle и
  OpenSSL. Фиксированный ключ, границы блоков Streebog (64) и Kuznyechik
  (16).

- [Методика кросс-валидации совместимости ключей ГОСТ Р
  34.10-2012](x-validation-tests/keys/doc/keys-cross-validation.md) +
  тесты. Охват: 7 кривых, DER encode/decode roundtrip, проверка Q = d×G,
  ASN.1-структура через BC, OpenSSL engine gost. 40 тестовых вызовов.
  Только DER-формат.

- [Методика кросс-валидации подписи ГОСТ Р
  34.10-2012](x-validation-tests/sign/doc/sign-cross-validation.md) +
  тесты. Охват: 7 кривых, двунаправленная подпись/верификация
  (crypto-gost ↔ BC/OpenSSL), детерминированный k (RFC 6979), tamper
  detection. ~3000 проверок.

- Тесты кросс-валидации PFX между crypto-gost и openssl в
  x-validation-tests/pkcs12.

Тесты кросс-валидации помогли выявить ошибку в OID эллиптических кривых
TC26 (см. Исправлено).

- **PBKDF2-HMAC-Streebog (Pbkdf2Streebog.java)** — RFC 9337. Выработка
  ключа из пароля по PBKDF2 с HMAC-Стрибог-256/512. Тест-векторы: RFC
  9337 Appendix A (6 векторов).

  - **JCA-обёртка PBKDF2-HMAC-Streebog
    (GostPbkdf2SecretKeyFactorySpi.java)**. Доступна как
    `SecretKeyFactory("PBKDF2WithHmacStreebog512")`. Алиас
    `"PBKDF2WithHmacGOST3411-2012-512"` даёт тот же результат.

- **KDF\_TREE\_GOSTR3411\_2012\_256
  (KdfTreeGostR3411\_2012\_256.java)** — RFC 7836 §4.5. Выработка ключей
  шифрования и подлинности для CTR-ACPKM-OMAC.

- **Режим CTR-ACPKM (CtrAcpkmMode.java)** — PBES2, RFC 9337 §7.3. Два
  варианта: CTR без кода подлинности и с CMAC
  (зашифровать-затем-подписать).

- **Обёртка JCA для Кузнечик-CTR-ACPKM (GostCtrAcpkmCipherSpi.java)**.
  Два подкласса — без OMAC и с OMAC. Доступны как
  `Cipher.Kuznyechik/CTR-ACPKM/NoPadding` и
  `Cipher.Kuznyechik/CTR-ACPKM-OMAC/NoPadding`.

- **`KeyAgreement.computeSharedSecret()` — ECDH shared secret (ГОСТ Р
  34.10-2012)**.  
  X-координата точки `d·Qpeer` в little-endian (RFC 9367 §8.5).
  Constant-time скалярное умножение, проверка совместимости кривых,
  защита от точки на бесконечности. Класс
  `org.rssys.gost.api.KeyAgreement`.

- **`GostKeyAgreementSpi` — JCA `KeyAgreement.ECDHGOST2012`**.  
  Однофазный JCA-интерфейс поверх `KeyAgreement.computeSharedSecret`.
  `engineGenerateSecret(String)` поддерживает алгоритмы `"ECDHGOST2012"`
  и `"RAW"`. Временный буфер обнуляется в `finally`.

- **`KeyAgreement.vkoGostR3410_2012_256()` — VKO\_GOSTR3410\_2012\_256
  (RFC 7836 §4.3.1)**.  
  Согласование 256-битного ключа с UKM и хэшированием Стрибог-256.
  Затирание промежуточных буферов.

- **`GostVkoKeyAgreementSpi` — JCA
  `KeyAgreement.VKOGOST3410-2012-256`**.  
  JCA-обёртка над VKO. UKM обязателен через `GostUkmParameterSpec`. OID
  `1.2.643.7.1.1.6.1`.

- **`GostUkmParameterSpec`** — `AlgorithmParameterSpec` для передачи UKM
  в VKO.

- **`KeyExport` — экспорт/импорт ключей KExp15/KImp15 (RFC 9189
  §8.2.1)**.  
  Аутентифицированное шифрование произвольного секрета парой ключей по
  схеме MAC-then-Encrypt: OMAC(K\_MAC, IV || S), затем CTR-Encrypt(S ||
  CEK\_MAC). Константы и форматы по RFC 9189 §8.2.1 (Кузнечик: блок 16
  байт, ключ 32 байта, IV 8 байт). Порядок параметров `kExp15`/`kImp15`
  соответствует RFC: K\_MAC перед K\_ENC. Затирание всех промежуточных
  буферов в `finally`, включая секрет при ошибке MAC. KAT: RFC 9189
  Appendix A.1.3.2 (TLS\_GOSTR341112\_256\_WITH\_KUZNYECHIK\_CTR\_OMAC).

- **`AuthenticatedCipher.computeCmac`**: добавлена перегрузка с
  AAD-параметром (`byte[] aad, byte[] data, SymmetricKey key`).
  Используется `AuthenticatedStream`.

### Изменено

- **`KdfGostR3411_2012_256` перенесён из `crypto-gost-tls13` в
  `crypto-gost-core`**.  
  Алгоритм `KDF_GOSTR3411_2012_256` (RFC 7836 §4.4) не зависел от
  tls13-модуля. Новый пакет: `org.rssys.gost.kdf`. Поведение и тесты не
  изменились.

- **Переработка режимов шифрования Кузнечик (CTR, CFB, OFB, CBC)** с
  целью повышения производительности. Во всех четырёх режимах побайтовая
  обработка и создание промежуточных байтовых массивов заменены на
  long-арифметику через прямой вызов encryptToFields базового шифра. В
  AbstractStreamMode добавлены общие поля VarHandle LONG\_BE и
  gammaHi/gammaLo, а также метод processBlocks для пакетной обработки
  полных блоков.

  - CTR — пакетная обработка блоков через long-XOR вместо байтового
    цикла и generateBuf.

  - CFB — устранены три выделения памяти на сегмент (createGamma); гамма
    пишется напрямую через encryptToFields; для полных блоков —
    long-XOR.

  - OFB — убран generateY (байтовый обход через processBlock); прямой
    вызов encryptToFields + long-XOR.

  - CBC — убраны new byte\[16\] на каждом блоке при зашифровании; при
    расшифровании R больше не используется как временный буфер —
    добавлен отдельный scratchBuf.

- Удален документ oid-reference.adoc(md), т.к. он дублировал данные из
  кода.

## Модуль crypto-gost-tls13

### Добавлено

- **Создание PFX-контейнеров ГОСТ (GostPkcs12Builder.java,
  PfxDerWriter.java)** — RFC 7292, RFC 9337, RFC 9548.  
  Fluent Builder API для сборки PFX с нуля: ключ + leaf-сертификат +
  произвольная цепочка CA. Шифрование ключа: PBES2-ГОСТ, Кузнечик
  CTR-ACPKM-OMAC (по умолчанию) или CTR-ACPKM, PBKDF2-HMAC-Стрибог-512,
  2000 итераций. Целостность: всегда HMAC-Стрибог-512 (RFC 9548 §7).
  Атрибуты SafeBag: `localKeyId` (20 байт, CryptoRandom), `friendlyName`
  (опционально). CA-сертификаты упаковываются без `localKeyId` —
  совместимо с фильтрацией `GostPkcs12Loader`. Атомарная запись в файл
  (`buildAndWriteTo(Path)` — temp + rename).  
  Созданные PFX совместимы с `GostPkcs12Loader.load(..., true)` и
  проходят структурную валидацию OpenSSL.

- **Вычисление MAC PFX (`GostPkcs12Mac.compute()`)** — RFC 9548 §7.  
  Парная операция к существующему `verify()`: PBKDF2(96 байт) →
  последние 32 байта как ключ HMAC-Стрибог-512, вычисление от
  `authSafe.contents`. Затирание производных ключей в `finally`.

- **Шифрование ключа по PBES2-ГОСТ (`GostPbes2.encryptKey()`)** — RFC
  9337 §5.  
  Парная операция к существующему `decryptKey()`: генерация salt и UKM
  через CryptoRandom, PBKDF2 → DK, Кузнечик CTR-ACPKM-OMAC или
  CTR-ACPKM, сборка DER `EncryptedPrivateKeyInfo`. Затирание DK и
  `SymmetricKey` в `finally`.

- **Расшифровка ключей по PBES2 (GostPbes2.java)** — RFC 9337.  
  Расшифровка PKCS8ShroudedKeyBag: PBKDF2-HMAC-Стрибог + Кузнечик
  CTR-ACPKM(-OMAC).

- **Разбор PFX (GostPkcs12Parser.java)** — RFC 7292.  
  Полный разбор структуры PKCS#12 без участия JDK: PFX,
  AuthenticatedSafe, SafeBag, MacData, EncryptedPrivateKeyInfo,
  параметры PBES2.

- **Загрузка PKCS12 (GostPkcs12Loader.java)** — RFC 9337/9548.  
  Если PFX содержит ГОСТ-шифрование — расшифровка собственными
  средствами, иначе прозрачная передача встроенному KeyStore JDK.  
  Фильтрация сертификатов по `localKeyId` (RFC 7292 §B.3): одноходовой
  обход bags с накоплением, пост-фильтрация после расшифровки ключа —
  корректно работает независимо от порядка bags в PFX. Сертификаты с
  `localKeyId`, отличным от ключевого, отбрасываются; сертификаты без
  `localKeyId` (CA) всегда включаются; если ключ не имеет `localKeyId` —
  все сертификаты проходят.  
  Цепочка упорядочивается leaf-first: leaf (`isCA == false`) на позиции
  0, CA отсортированы топологически по `issuer->subject` DER-совпадению
  — корректно для `TlsCertificateValidator` и любого порядка bags в
  исходном PFX.

- **Проверка целостности PFX (GostPkcs12Mac.java)** — RFC 9548 §7.  
  PBKDF2 из пароля даёт 96 байт, последние 32 — ключ HMAC-Стрибог-512
  для проверки `authSafe.contents`.

- Стресс-тест и методика пропускной способности TlsSession. Результат:
  ~47 МБ/с.

- Правильные alert-коды при валидации сертификатов: `unknown_ca(48)` для
  корня без доверенного CA, `certificate_revoked(44)` для отозванных по
  CRL/OCSP. `TlsHandshakeEngine` — сохранение alert-кода при
  `acknowledgeCertificateValidation(false, code)` с дефолтом
  `handshake_failure(40)`. `TlsOcspVerifier` — совместимость с
  OCSP-респондерами, кодирующими статус «good» как `[0] IMPLICIT NULL`
  (`0x80 0x00`).

- **HelloRetryRequest (HRR) — RFC 8446 §4.1.3, §4.2.8, §4.4.1**. Клиент
  и сервер теперь поддерживают смену ECDHE-группы через HRR. Клиент: при
  получении HRR заменяет транскрипт на `message_hash(CH1)`, генерирует
  новый ECDHE-ключ для запрошенной группы, отправляет второй
  ClientHello. При активном PSK binder пересчитывается от
  `Hash(message_hash + HRR + Truncated_CH2)`. Сервер: при несовпадении
  группы клиента отправляет HRR (ранее — silent accept первой группы из
  key\_share клиента). Защита от цикла: второй HRR подряд →
  `ALERT_UNEXPECTED_MESSAGE` (клиент), повторный CH с неправильной
  группой после HRR → `ALERT_ILLEGAL_PARAMETER` (сервер).

### Исправлено

- **Совместимость с TLS 1.3 через middlebox-прокси (RFC 8446 §D.4)**.  
  Добавлен пропуск записей ChangeCipherSpec (тип 20) в цикле приёма
  handshake-записей. Без этого при подключении к серверу, работающему в
  режиме совместимости с middlebox (OpenSSL по умолчанию), клиент падал
  с `IllegalArgumentException: Record payload too small for tag: 1`.  
  Добавлена константа `CT_CHANGE_CIPHER_SPEC = 20` в `TlsConstants`.

  - Добавлен проверочный тест `testSilentlyIgnoreChangeCipherSpec` —
    проверяет, что CCS-запись между ServerHello и EncryptedExtensions
    молча игнорируется и handshake завершается успешно.

- **Уточнение порядка байт X-координаты ECDHE (RFC 9367 §6.1.1)**.  
  Переменная в `computeEcdheShared` переименована: `xBe` →
  `xRawBe`/`xRawLe`. Логика не изменилась — результат был и остаётся
  little-endian согласно RFC 9367. Прежнее имя `xBe` вводило в
  заблуждение и провоцировало лишние обсуждения на code review.

- **Single key\_share для предпочтительной группы; смена дефолта GC256A
  → GC256B**.  
  Клиент генерирует одну ECDHE-пару для выбранной группы.
  `supported_groups` в ClientHello перечисляет все 7 групп. При
  несовпадении группы клиента и сервера соединение завершается alert’ом
  — поддержка HRR не реализована.  
  Дефолт сменён с GC256A на GC256B (CryptoPro-A): GC256A несовместим с
  OpenSSL gostprov.

  - \* **Метод `withSelectedNamedGroup(int)` в `TlsServerConfig`**.  
    Позволяет задать группу сервера, отличную от дефолтной. Используется
    для кросс-групповых сценариев (например, клиент GC256A — сервер
    GC512C).

- **Порядок формирования транскрипта для application traffic secrets
  приведён к RFC 8446 §4.4.1**.  
  Ранее клиентский Finished добавлялся в транскрипт до выработки app
  traffic keys (SATS/CATS). По спецификации транскрипт для Derive-Secret
  на этом этапе должен включать ClientHello…server Finished, но не
  client Finished. Сервер OpenSSL/gost-engine формирует
  server\_finished\_hash до получения клиентского Finished — из-за
  расхождения транскрипта app traffic secrets не совпадали, и первая же
  зашифрованная запись отклонялась с «MGM authentication tag mismatch».

  - Клиентский Finished (`receiveFinished`) больше не добавляется в
    транскрипт до `finishHandshake()`, а сохраняется в отдельном поле.

  - `finishHandshake()` добавляет клиентский Finished в транскрипт после
    выработки app traffic keys.

  - На стороне сервера (`receiveClientFinished`) хеш транскрипта для
    SATS/CATS сохраняется до добавления клиентского Finished, а не
    после.

  - Все 589 тестов проходят, включая кросс-валидацию с OpenSSL
    gost-engine.

- **Транскрипт для app traffic secrets при mTLS нарушал RFC 8446 §7.1
  Table 2 (баг в TlsHandshakeEngine)**.  
  RFC 8446 §7.1 Table 2 явно определяет: оба секрета прикладного трафика
  (`client_application_traffic_secret_0`,
  `server_application_traffic_secret_0`) вырабатываются через
  `Derive-Secret(Master Secret, "c/s ap traffic", ClientHello...server Finished)`
  — транскрипт включает сообщения **только до server Finished
  включительно**, без клиентских Certificate, CertificateVerify и
  Finished.  
  В режиме взаимной аутентификации (mTLS) `receiveClientCertificate()` и
  `receiveCertificateVerify()` добавляли эти сообщения в
  `HandshakeContext` до выработки app keys. В результате
  `receiveClientFinished()` вычислял `ctx.transcriptHash()` включая
  client Certificate и CertificateVerify, тогда как OpenSSL/gost-engine
  корректно использовал hash(CH…server Finished). Расхождение
  `clientAppTrafficSecret` приводило к тому, что первая же зашифрованная
  app-запись отклонялась с «MGM authentication tag mismatch».  
  **В non-mTLS баг не проявлялся**: клиентских
  Certificate/CertificateVerify в транскрипте нет, оба стека вычисляли
  одинаковый hash.  
  **Исправление**: в `TlsHandshakeEngine` добавлено поле
  `appTranscriptHash` — hash транскрипта, захватываемый сразу после
  `ctx.addToTranscript(serverFinishedFrame)` до любых клиентских
  сообщений аутентификации. `receiveClientFinished()` (сервер) и
  `finishHandshake()` (клиент) используют `appTranscriptHash` вместо
  позднего `ctx.transcriptHash()`. Поле затирается через
  `TlsUtils.wipeArray` после использования и в `destroy()`.  

  - Кросс-валидационный тест `testServerMtls` (Java-сервер + OpenSSL
    s\_client с mTLS, кривая GC256B, suite L) теперь проходит.

- **Эхо-отражение legacy\_session\_id в ServerHello (RFC 8446
  §4.1.3)**.  
  Ранее сервер всегда отправлял `legacy_session_id` нулевой длины, хотя
  по спецификации необходимо повторять значение из ClientHello для
  совместимости с промежуточными устройствами (middlebox). OpenSSL 3.6.0
  с патчем gost-engine проверяет совпадение session\_id и при
  несовпадении отвечал отказом (illegal\_parameter), не доходя до
  выработки ключей.  
  Исправлено: `TlsMessageBuilder` — добавлен `setClientSessionId()`,
  условная запись в `buildServerHello()`. `TlsHandshakeEngine` —
  извлечение session\_id из тела ClientHello и передача в сборщик.  

- **Сервер мог работать только с SUITE\_L, игнорируя выбор клиента**.  
  JSSE-сервер рекламирует оба набора (L и S), но при handshake упорно
  использовал L — даже если клиент предлагал только S или явно его
  предпочитал. Причина: код не искал пересечение наборов, а проверял
  «есть ли в списке клиента наш L». Если нет — соединение обрывалось.  
  Теперь сервер выбирает набор по правилам RFC 8446: сначала свой
  предпочтительный, потом первое совпадение из предложенных клиентом.
  Добавлена защита от битых ClientHello (bounds-check).

### Изменено

- **`KdfGostR3411_2012_256` перенесён из `crypto-gost-tls13` в
  `crypto-gost-core`**.  
  Алгоритм `KDF_GOSTR3411_2012_256` (RFC 7836 §4.4) не зависел от
  tls13-модуля. Новый пакет: `org.rssys.gost.kdf`. Поведение и тесты не
  изменились.

- Конструктор `InMemoryTlsTransport(LinkedBlockingQueue)` стал публичным
  (`public`) для создания кастомных транспортов с переопределённым
  `sendRecord` из тестов в других пакетах.

- **Переработка `TlsMessageBuilder` для key\_share**.  
  `buildClientHello` и `buildClientHelloWithPsk` получили перегрузки,
  принимающие `Map<Integer, byte[]>` (группа → точка). Старые методы с
  одним `byte[] ecdhePoint` делегируют новым через
  `Map.of(selectedNamedGroup, ecdhePoint)`. Внутренний
  `buildCommonExtensions` строит key\_share extension в цикле по entry
  map.

- **Конструктор `TlsSession` — два поля потеряли `final`**.  
  `selectedEcParams` и `messageBuilder` теперь перезаписываются в
  `createServer()`, если в `TlsServerConfig` задана нестандартная
  группа. Оба поля читаются только через публичные геттеры — побочных
  эффектов нет.

- **Логика выбора cipher suite убрана из публичного API
  `TlsMessageBuilder`**.  
  Метод согласования набора и его установка в билдере теперь полностью
  внутри класса — внешний код не может случайно перетереть согласованный
  набор. API свёлся к одному методу.

## Модуль crypto-gost-jsse

### Исправленно

- GostSSLEngine — извлечение TlsException из cause CertificateException
  для сохранения alert-кода; маппинг новых алертов в
  SSLPeerUnverifiedException

- **`GostSsl.buildContext()` — убрано обращение через устаревшую обёртку
  `Pkcs12Loader`**.  
  Внутренний вызов переведён напрямую на `GostPkcs12Loader.load()`.

- Исправлена ошибка в OcspRequestBuilder.buildSigned: структура
  AlgorithmIdentifier подписанного OCSP-запроса приведена в соответствие
  с RFC 9215 §4.2 — поле parameters убрано (ранее туда ошибочно
  помещались OID кривой и дайджеста). Одновременно устранено
  дублирование трёх тернарников по hlen.

- **CT\_CHANGE\_CIPHER\_SPEC не игнорировался в handleEncryptedRecord**
  — RFC 8446 §D.4 нарушен. OpenSSL отправляет legacy CCS для middlebox
  compatibility, engine падал с payload too small for tag: 1.

- **JSSE-движок не подхватывал согласованный cipher suite после
  handshake**.  
  Даже когда `TlsHandshakeEngine` правильно выбирал S (или другой
  набор), `GostSSLEngine` продолжал работать с L по умолчанию. Из-за
  этого TLSTREE-ключи (зависящие от набора) не совпадали — расшифровка
  записей клиента падала. Исправлено: теперь `GostSSLEngine` читает
  согласованный набор из handshake-движка сразу после его выбора.

### Добавлено

- **`GostSslBuilder.trustCa(byte[], char[])` — загрузка доверенных CA из
  PFX-контейнера**.  
  Симметричный overload к `certificate(byte[], char[])`. Извлекает все
  сертификаты с флагом CA из цепочки PFX и добавляет каждый в trust
  store через `trustCa(byte[])`. Необходим для сценария, когда
  CA-сертификат хранится в `.p12`, а не в отдельном DER/PEM-файле.

- **`PfxExportExample`** — пример создания PFX с ГОСТ-сертификатом.  
  Генерирует CA и серверный ключ/сертификат, собирает PFX через
  `GostPkcs12Builder`, сохраняет на диск и верифицирует загрузку
  обратно. Makefile-таргет `pfx-export`.

- **`PfxServerExample`** — пример JSSE-сервера из PFX-файлов.  
  Загружает серверный и CA-сертификаты из `.p12` через `GostSslBuilder`,
  поднимает echo-сервер. Makefile-таргет `pfx-server`.

### Кросс-валидационные тесты с серверами приложений

- **Кросс-валидация серверов приложений ↔ OpenSSL: новый модуль
  `x-validation-tests/jsse-server`**.  
  Закрывает пробел между двумя существующими слоями проверки:
  `x-validation-tests/jsse` (GostSSLEngine/Socket ↔ OpenSSL на уровне
  raw TCP) и `examples/jsse` (серверы приложений ↔ внутренний
  GostSSLSocket). Новый модуль проверяет, что серверное middleware
  корректно пропускает ГОСТ TLS 1.3 при подключении внешнего
  OpenSSL-клиента.  

  Запуск: `mvn test -Pcrossval` (вместе с остальными
  кросс-валидационными модулями).  

  **`ServerOpenSslCrossValTest`** — roundtrip: embedded-сервер +
  `openssl s_client` GET → `INTEROP_OK`.  
  Параметры: suite `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`, кривая
  GC256B.  

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Сервер</p></td>
<td style="text-align: left;"><p>Обвязка</p></td>
<td style="text-align: left;"><p>Тест</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Tomcat 11</p></td>
<td style="text-align: left;"><p>Кастомный
<code>SSLImplementation</code> + <code>SSLUtil</code> →
<code>SSLContextWrapper</code></p></td>
<td style="text-align: left;"><p>roundtrip</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Jetty 12</p></td>
<td
style="text-align: left;"><p><code>SslContextFactory.Server.setSslContext(ctx)</code></p></td>
<td style="text-align: left;"><p>roundtrip</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Undertow 2.3</p></td>
<td
style="text-align: left;"><p><code>addHttpsListener(port, host, ctx)</code></p></td>
<td style="text-align: left;"><p>roundtrip</p></td>
</tr>
</tbody>
</table>

**`TomcatJettyMtlsCrossValTest`** — mTLS: сервер с
`needClientAuth=true` +
`openssl s_client -cert -key -sigalgs gostr34102012_256b` →
`INTEROP_OK`.  

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Сервер</p></td>
<td style="text-align: left;"><p>Тест</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Tomcat 11</p></td>
<td style="text-align: left;"><p>mTLS</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Jetty 12</p></td>
<td style="text-align: left;"><p>mTLS</p></td>
</tr>
</tbody>
</table>

Итого: 5 тестов.  

Подтверждено три реальных факта, которые раньше были предположениями:

- Tomcat с кастомным SSLImplementation + SSLUtil корректно принимает
  ГОСТ TLS 1.3 от внешнего клиента.

- mTLS с внешним клиентом (OpenSSL s\_client -cert) проходит через Jetty
  и Tomcat. Это покрывает реальный production-сценарий — машина-к-машине
  с ГОСТ-сертификатами.

- Self-signed клиентский сертификат в mTLS — вынужденное ограничение:
  OpenSSL отказывается загружать ГОСТ-сертификат, подписанный CA, с
  ошибкой "ca md too weak". Это важное знание о поведении OpenSSL с ГОСТ
  PKI.

## Инфраструктура сборки

### Исправлено

- **Fuzz-тесты падали при `mvn test` на JDK 21 с maven-surefire
  3.2.x**.  
  Jazzer не совместим с дефолтным механизмом surefire (booter-jar):
  возникали `NoSuchFileException` и
  `NoClassDefFoundError: UnsafeProvider`.  
  Исправлено добавлением `SurefireForkNodeFactory` в `pluginManagement`
  корневого `pom.xml` — аналогично уже существующей конфигурации в
  модуле `crypto-gost-tls13`.

# \[0.3.4\] - 28-05-2026

Этот релиз целиком посвящён гигиене памяти, устранению аллокаций на
горячих путях и нескольким реальным race conditions в TLS 1.3 и JSSE.

## Модуль crypto-gost-tls13

### Добавлено

- Цепочка сертификатов удалённой стороны освобождается сразу после
  завершения согласования. Ранее она удерживалась в памяти до закрытия
  соединения, хотя после проверки подписи и верификации цепочки более не
  использовалась.

- Тела сообщений KeyUpdate вынесены в статические константы вместо
  создания нового массива при каждом вызове.

- PSK-ключ затирается и обнуляется сразу после вывода раннего секрета
  (deriveEarlySecret), а не откладывается до закрытия соединения.

- Результат обработки KeyUpdate кэшируется как статический экземпляр
  вместо создания нового объекта при каждом вызове.

- Нулевая соль для HKDF-Extract создаётся один раз при загрузке класса
  вместо выделения нового массива при каждом вызове без явной соли.

- Handshake-ключи затираются сразу после перехода соединения на ключи
  передачи данных. Ранее они оставались в памяти до закрытия соединения.

- PSK-запись затирается сразу после извлечения на сервере. Ранее после
  получения ключа из тикета объект PskEntry выходил за область видимости
  без явного затирания и ждал сборщика мусора.

- Буфер сборки handshake-сообщений в TlsSession освобождается сразу
  после завершения согласования. Ранее расширенный backing array (~18-20
  КБ) удерживался до закрытия сессии, хотя post-handshake сообщения
  (NST, KeyUpdate) занимают менее 100 байт.

- Добавлен бенчмарк — оценка стоимости аллокаций HkdfStreebog.newHmac()

### Исправлено

- Устранено состояние гонки при клиентском возобновлении сессии:
  PSK-ключ мог быть зачищен в хранилище конкурентным потоком между
  получением записи и её использованием. Добавлена проверка доступности
  ключа перед передачей в движок согласования; метод setPsk теперь явно
  отвергает нулевой ключ.

- Метки HKDF вычисляются один раз при загрузке класса вместо создания
  новых строк и массивов при каждом вызове. Снижает нагрузку на сборщик
  мусора при согласовании и обновлении ключей.

- Исходные секреты handshake-трафика (serverHandshakeTrafficSecret,
  clientHandshakeTrafficSecret) затираются сразу после завершения
  согласования. Ранее они оставались в памяти до закрытия соединения,
  хотя производные от них ключи уже были уничтожены раньше.

- Удалён избыточный блок удаления PSK-тикета в TlsSession:
  InMemoryPskStore.get() уже атомарно удаляет тикет внутри
  TlsHandshakeEngine.receiveClientHello(), повторный вызов
  pskStore.remove() был no-op. Заодно устранён потенциальный
  NullPointerException при pskStore == null.

## Модуль crypto-gost-jsse

### Добавлено

- Ограничение размера кэша OCSP-ответов: при превышении 500 записей
  случайная запись вытесняется. Ранее кэш рос без ограничений, что могло
  приводить к исчерпанию памяти при большом числе уникальных клиентских
  сертификатов.

- Вытеснение просроченных сессий из кэша GostSSLSessionContext: при
  добавлении новой сессии наиболее старая автоматически удаляется если
  истёк её срок действия; при обращении к сессии по идентификатору
  просроченная запись также удаляется из кэша. Ранее сессии
  накапливались до явного вытеснения по размеру кэша.

- При успешном возобновлении сессии через PSK запись host:port →
  идентификатор тикета теперь удаляется из внутренней таблицы сразу
  после подтверждения сервером. Ранее устаревшие записи накапливались до
  достижения лимита таблицы.

- Заглушка сессии до завершения согласования теперь создаётся один раз в
  конструкторе GostSSLEngine и переиспользуется. Ранее новый объект
  создавался при каждом вызове getSession() до начала согласования.

- В стресс-тест добавлена проверка допустимого уровня ошибок для профиля
  1: тест завершается с ошибкой если число сбоев превышает 1% от числа
  запросов. Ранее ошибки только подсчитывались, но не влияли на
  результат теста.

- Список поддерживаемых алгоритмов подписи вынесен в статическую
  константу. Ранее новый массив создавался при каждом вызове
  getLocalSupportedSignatureAlgorithms().

- Установлен лимит кэша клиентских сессий 20 480 записей через
  GostSSLContextSpi; GostSSLSessionContext по умолчанию возвращает 0
  (безлимит, по контракту SSLSessionContext). Исправлен также баг в
  GostSsl: настройка размера кэша теперь применяется к обоим контекстам,
  а не только к серверному.

### Исправлено

- Устранено состояние гонки при клиентском возобновлении сессии:
  PSK-ключ мог быть зачищен в хранилище конкурентным потоком между
  получением записи и её использованием. Добавлена проверка доступности
  ключа перед передачей в движок согласования; метод setPsk теперь явно
  отвергает нулевой ключ.

- Устранена лишняя копия расшифрованных данных в GostSSLEngine: при
  обработке входящих записей данные теперь читаются напрямую из
  внутреннего массива буфера без промежуточного выделения памяти.
  Снижает нагрузку на сборщик мусора на горячем пути приёма данных.

- Преобразование байт в шестнадцатеричную строку в GostX509TrustManager
  теперь использует таблицу символов вместо форматирования строки на
  каждый байт. Метод вызывается при каждом обращении к кэшу OCSP.

- Чтение TLS-записи использует две локальные аллокации вместо трёх:
  заголовок и тело читаются в один массив без промежуточного
  объединения. Постоянный буфер на сокет убран — не создаёт давления на
  память при большом числе соединений.

# \[0.3.3\] - 26-05-2026

## Модуль crypto-gost-core

### Исправлено

- **Рефакторинг Mgm**: устранены аллокации long\[16\] × 2 на каждый блок
  MAC на горячем пути. Таблица GF(2¹²⁸) умножения вынесена в
  scratch-поля mulTabHi/mulTabLo, результат — в mulResHi/mulResLo по
  паттерну encBufHi/encBufLo. Дублирующий метод gf128MulAccumTo и поля
  tmpHi/tmpLo удалены. Исправлен JavaDoc.

- Обнуление encBufHi/encBufLo в Kuznyechik.reset(): после завершения
  сессии промежуточные значения шифра больше не остаются в памяти
  экземпляра.

- Добавлена цепочка явного обнуления ключевого материала:

  - Kuznyechik.destroy() затирает раундовые ключи skHi/skLo и
    scratch-поля;

  - Mgm.destroy() делегирует в Kuznyechik.destroy() и обнуляет счётчики,
    MAC-аккумулятор, ICN и scratch-буферы;

  - TlsRecord.destroy() вызывает mgm.destroy() в составе существующей
    процедуры закрытия сессии.

  - GostMgmCipherSpi уничтожает предыдущий экземпляр Mgm перед
    реинициализацией.

  - MgmCipher.sealWithIcn и open гарантируют уничтожение через
    try-finally.

  - Исправлен порядок в Kuznyechik.init(): keyInitialized
    устанавливается в true только после успешного завершения
    generateSubKeys.

- Удалена избыточная таблица SI\_LO\[8\]\[256\] в Kuznyechik: таблицы
  SI\_HI и SI\_LO были математически идентичны, путь расшифрования
  переведён на единую SI\_HI. Экономия 16 КБ статической памяти,
  суммарный размер таблиц снижен с 160 КБ до 144 КБ.

- Рефакторинг FieldElement.invert(): пять предвыделенных буферов с
  CT-swap (cswap) вместо ~2500 ephemeral-аллокаций на вызов. CT-свойства
  сохранены: фиксированное число итераций, ветвлений по данным нет.
  Трёхпараметровый montMul оставлен как standalone CIOS с локальными
  аллокациями — JIT элиминирует bounds checks, производительность
  multiply/square на 512-бит на уровне baseline (+2% к v0.3.2).
  Четырёхпараметровая буферная версия переименована в montMulBuf и
  используется только в invert(). expPMinus2 кэширован в
  MontgomeryParams. Убран лишний вызов normalize() в
  ECDSASigner.generateSignature(). Добавлен тест эквивалентности montMul
  ≡ montMulBuf на 100 случайных входах для кривых 256 и 512 бит.

- Улучшена читаемость условия в conditionalSubtract: выражение
  (<sub>lt\ &</sub> gt & 1L) заменено на 1L ^ (lt | gt). Оба варианта
  математически эквивалентны, но новый читается напрямую — «не меньше и
  не больше, значит равно» — без риска случайно потерять & 1L при
  будущих правках. Добавлены тесты на граничный случай a == p. Старое:
  (<sub>lt\ &</sub> gt & 1L) — работало только благодаря & 1L,
  маскирующему битовую инверсию всех 64 бит. Новое, не требует маски, не
  сломается при рефакторинге.

- Устранено ветвление по данным в ECPoint.twice(): убран ранний возврат
  if (isInfinity()) return this в ECPoint.twice(). Результат теперь
  вычисляется для любой входной точки, выбор между новым результатом и
  исходной точкой выполняется через CT-select по маске z-координаты.
  Устраняет ветвление по секретному скаляру и timing-утечку позиции его
  старшего бита.

## Модуль crypto-gost-tls13

### Исправлено

- Устранено дублирование списка cipher suites:
  TlsConstants.OFFERED\_CIPHER\_SUITE\_IDS удалена, список передаётся в
  конструктор TlsMessageBuilder и используется как для сборки
  ClientHello, так и для валидации ServerHello. При добавлении нового
  suite достаточно обновить один вызов конструктора.

- Добавлены bounds-проверки в
  TlsCertificateValidator.verifyCertificateVerify: минимальная длина
  тела (&lt; 4 байт → ALERT\_DECODE\_ERROR) и корректность sigLen (4 +
  sigLen &gt; длина тела → ALERT\_DECODE\_ERROR). Ранее слишком короткое
  тело вызывало ArrayIndexOutOfBoundsException вместо корректного TLS
  alert, а завышенный sigLen молча дополнялся нулями.

- Исправлена верификация OCSP leaf в TlsCertificateValidator: при
  наличии issuer-сертификата в цепочке (chain.size() &gt; 1) OCSP-ответ
  теперь верифицируется ключом issuer даже без caPublicKeys. Ранее весь
  блок OCSP leaf пропускался при caPublicKeys = null, хотя ключ для
  верификации был доступен из цепочки. Поведение приведено к
  единообразию с intermediate OCSP.

- Добавлена проверка thisUpdate в TlsOcspVerifier: если thisUpdate
  находится в будущем (с допуском 5 минут на расхождение часов),
  выбрасывается ALERT\_BAD\_CERTIFICATE. Ранее это требование RFC 6960
  §3.2 (MUST) не выполнялось.

- Добавлена защита от пустой цепочки в
  TlsCertificateValidator.checkServerCertificateChain: явная проверка
  null || isEmpty с ALERT\_DECODE\_ERROR перед chain.get(0). Ранее
  пустой список вызывал IndexOutOfBoundsException вместо корректного TLS
  alert. Приведено к единообразию с checkClientCertificateChain.

- defensive hardening TlsKeySchedule: старое значение handshakeSecret
  затирается перед перезаписью в deriveHandshakeSecret, аналогично
  earlySecret в deriveEarlySecret. Добавлен явный API-контракт в Javadoc
  четырёх getter-ов (get\*TrafficSecret): caller обязан затереть
  возвращённый массив через TlsUtils.wipeArray после использования.

- TlsKeySchedule.deriveMasterSecret(): handshakeSecret затирается и
  обнуляется сразу после вывода masterSecret. По RFC 8446 §7.1 он более
  не нужен; defence-in-depth устраняет присутствие ключевого материала в
  heap до destroy().

- Исправлена утечка ключевого материала PSK в InMemoryPskStore:
  evictExpired() и get() теперь вызывают entry.destroyPsk() перед
  удалением просроченных записей. Ранее byte\[\] psk оставался в heap до
  GC вместо немедленного затирания. Приведено к единообразию с clear() и
  max-size eviction.

- Добавлена проверка границ массива перед чтением полей cipherSuite и
  compression в TlsMessageParser.parseServerHello(). Устраняет возможный
  выход за пределы массива при усечённом теле сообщения ServerHello.

- Добавлена проверка размера PSK-идентификатора в
  TlsMessageParser.parseClientHelloPskIdentity(): identityLen теперь
  ограничен сверху значением identitiesLen - 6. Устраняет возможную
  избыточную аллокацию при намеренно искажённом поле длины в расширении
  pre\_shared\_key.

- Добавлена обработка ошибок разбора в двух непокрытых местах:
  OcspCertIdHasher.hashIssuerName и hashIssuerPublicKey теперь
  перехватывают исключения при битом DER и пробрасывают их как
  IllegalArgumentException; TlsCrlVerifier.verify оборачивает весь
  разбор CRL в обработчик и пробрасывает ошибки как TlsException с кодом
  ALERT\_DECODE\_ERROR. Ранее при искажённом входе исключение уходило
  наружу без обработки.

- Исправлена семантика клиентского поиска PSK-тикета: ранее тикет
  удалялся из хранилища до начала согласования, что приводило к его
  безвозвратной потере при отказе сервера от возобновления сессии.
  Теперь тикет удаляется только после подтверждения сервером (получение
  ServerHello с расширением PSK). Добавлен метод peek() в интерфейс и
  реализацию хранилища — неразрушающий поиск с проверкой срока действия.

## Модуль crypto-gost-jsse

### Исправлено

- Гонка данных на pendingWriteKeysExist: теперь поле объявлено как
  volatile, что обеспечивает happens-before между записью ключевого
  кортежа (pendingWriteKey/pendingWriteIv/pendingWriteTagLen) под
  inboundLock и его чтением под outboundLock в wrap(). Без фикса метод
  wrap() мог не применить app-ключи и отправить данные под
  handshake-ключами, что вызывает fatal alert на принимающей стороне.

- Гонка данных на полях состояния: engineState, handshakeDone,
  closeSent, closeReceived. Теперь они объявлены как volatile, что
  обеспечивает visibility между записями под inboundLock/outboundLock и
  чтениями из getHandshakeStatus(), isOutboundDone(), isInboundDone() и
  перекрёстными обращениями между wrap и unwrap.

- Исправлено повреждение данных при гонке потоков (data corruption race)
  на outgoingQueue при конкурентных вызовах wrap() и unwrap().
  ArrayDeque&lt;byte\[\]&gt; заменён на
  ConcurrentLinkedDeque&lt;byte\[\]&gt;, обеспечивающий thread-safety
  для операций addLast, poll, addFirst, isEmpty при доступе из разных
  lock’ов или без лока.

- Исправлена гонка данных на writerRecord между wrap() (outboundLock) и
  unwrap() (inboundLock): в handleEngineKeyChanges() серверный путь
  замены writerRecord теперь не вызывает writerRecord.destroy() под
  inboundLock. Вместо этого старый writerRecord сохраняется в
  deferredWriterDestroy и уничтожается в wrap() под outboundLock через
  applyDeferredWriterDestroy(). Гонка была введена цепочкой уничтожения
  ключей (Kuznyechik.destroy() → keyInitialized = false), которая
  превратила существовавшую в v0.3.2 молчаливую гонку в
  IllegalStateException. Добавлена зачистка deferredWriterDestroy в
  destroyHandshakeEngine() на случай закрытия соединения до применения
  отложенного уничтожения.

- В GostSSLEngine.createCertValidationTask() добавлен перехват
  непроверяемых исключений при валидации сертификата. Ранее такое
  исключение оставляло движок в состоянии ожидания без возможности
  продолжить или завершить соединение. Теперь любая ошибка валидации
  переводит движок в состояние ошибки с корректным закрытием соединения.

- Уровень журналирования при ошибке валидации сертификата снижен с ERROR
  (SEVERE) до WARNING в GostX509TrustManager: отказ в доверии и отзыв
  сертификата — штатные сценарии, а не сбои инфраструктуры. Обновлён
  соответствующий тест.

- Устранено дублирование кода в GostSSLEngine: повторяющийся блок
  автоматического обновления ключей вынесен в приватный метод
  tryAutoKeyUpdate(), логика замены writerRecord — в методы
  swapWriterRecord() и setPendingWriteKeys(). Поведение не изменилось.

# \[0.3.2\] - 21-05-2026

Окончание функционального развития. Библиотека функционально закончена.
Нового API или какого-то развития больше не ожидается. Основные ошибки
были найдены и устранены. Далее только исправление ошибок, найденных в
процессе реальной эксплуатации.

## Модуль crypto-gost-core

### Добавлено

- В GostDerCodec.decodePublicKey добавлен workaround для нестандартных
  сертификатов Минцифры России (2025), где curveOid содержит OID
  256-битной кривой при фактически 512-битном ключе. При несоответствии
  размера точки ожиданиям OID — проверяется signAlgOid; если он
  указывает на 512-битный алгоритм, применяется явная таблица маппинга
  на правильную 512-битную кривую. Аналогично поведению OpenSSL
  gostprov.

### Исправлено

**Важно! До версии 0.3.2 подпись формировалась и проверялась в другом
формате. Поэтому настоятельно рекомендую обновиться до 0.3.2 минимум!**

- Исправлен формат подписи ГОСТ Р 34.10-2012 в SignatureCodec —
  компоненты переставлены с r∥s на s∥r (big-endian) в соответствии с
  X.509/RFC 4491. Предыдущий формат не был совместим с openssl-gost и
  реальными УЦ. TlsSignatureCodec (TLS 1.3, RFC 9367) не затронут.

- Исправлены тесты кросс-валидации bench/signature, которые явно
  переворачивали формат подписи.

## Модуль crypto-gost-netty

### Добавлено

- **PSK resumption через Netty pipeline:**  

  - Добавлена возможность разделять сессионный контекст между клиентским
    и серверным GostSslContext для поддержки PSK resumption в
    Netty-окружении.  

  - GostSSLSessionContext получил метод redirectToSharedState(), который
    переключает внутренние хранилища тикетов на общий объект.

  - GostSslContextBuilder получил метод sessionContext(), который
    вызывает redirect после инициализации SSLContext. После этого
    PSK-тикет, сохранённый сервером при первом хендшейке, становится
    виден клиенту при переподключении через тот же GostSslContext.

  - Новый тест GostSslContextHandshakePskResumptionTest верифицирует
    интеграцию через EmbeddedChannel — full handshake, передачу NST,
    переподключение и передачу данных. Корректность самого PSK-протокола
    покрыта на уровне движка в GostSSLEnginePostHandshakeTest.

    Главный сценарий для **PSK resumption через Netty pipeline**—
    высоконагруженный сервис где один процесс держит и серверную, и
    клиентскую сторону TLS. Типичный пример: reverse proxy или API
    gateway на Netty, где один EventLoopGroup принимает входящие
    соединения и одновременно открывает исходящие к бэкендам. При частых
    переподключениях (мобильные клиенты, нестабильные сети, connection
    pooling) PSK resumption убирает криптографически дорогую часть
    хендшейка — выработку эфемерного ключа и верификацию сертификата — и
    заменяет её симметричной операцией на основе сохранённого PSK. На
    ГОСТ-алгоритмах это особенно заметно, потому что ГОСТ-подпись дороже
    RSA/ECDSA на типичном железе.

## Модуль crypto-gost-tls13

### Добавлено

- **Поддержка multi-ca**:

  - TlsCertificateValidator: сигнатуры 3 методов изменены с
    PublicKeyParameters caPublicKey на List&lt;PublicKeyParameters&gt;
    caPublicKeys. Root-сертификат верифицируется по всем CA из списка
    (первый совпавший = доверенный).

  - OCSP delegated responder: при отсутствии issuer в цепочке
    fallback-ключ верифицируется по всем CA из списка (не только по
    первому).

  - TlsSession: хранение и проброс List&lt;PublicKeyParameters&gt;
    вместо одного ключа.

  - TlsClientConfig / TlsServerConfig: добавлены withCaPublicKeys(List)
    и getCaPublicKeys(); старые single-key методы — обёртки над новыми.

- Добавлен TlsCrlVerifier — парсинг и верификация CRL (подпись, срок,
  revoked, reject partial/indirect CRL).

- Фабричные методы TlsCertificate.fromDer(byte\[\]),
  fromPemOrDer(byte\[\]) и listFromPem(byte\[\]) для удобной загрузки
  сертификатов напрямую из DER/PEM без внешних утилит.

- Методы записи TlsCertificate.toDer(), toPem() и chainToPem(List).
  Симметричные аналоги fromDer()/fromPemOrDer()/listFromPem(). Полный
  roundtrip: читай и пиши DER/PEM через единый API без внешних утилит.

- Интеграционный тест верификации реальной цепочки сертификатов Минцифры
  (512-бит ГОСТ Р 34.10-2012, ParamSet A) —
  subCa.verifySignature(root.getPublicKey()) успешен.

- GenerateCsr.java: Новый пример генерации PKCS#10 CSR для ГОСТ Р
  34.10-2012 (256 и 512 бит, любой DN).

### Исправлено

- TlsMessageParser.parseCertificate: проверка лимита цепочки
  сертификатов вынесена ВНУТРЬ цикла парсинга — DoS-защита от цепочки из
  множества мелких сертификатов (каждый TlsCertificate выполняет полный
  DER-парсинг).

- TlsUtils.wipeArray: задокументировано known limitation JVM — JIT DCE и
  heap dump риски, невозможность гарантированной очистки на чистой Java.

- TlsHandshakeEngine.setPsk(): ключевой материал клонируется при
  передаче (psk.clone())

- Исправлен комментарий OCSP для intermediate: best-effort → fail-closed
  (код уже был fail-closed, документация вводила в заблуждение)

- InMemoryPskStore: очистка просроченных PSK-тикетов перенесена до
  проверки лимита — expired тикеты не занимают место живых, вытеснение
  случайных записей происходит только при реальном переполнении.

- HandshakeContext.destroy(): дайджесты транскрипта (hsDigest256,
  hsDigest512) теперь сбрасываются и обнуляются при уничтожении
  контекста (defence-in-depth).

- Защита от CPU-DoS через OCSP delegated сертификаты. Добавлен лимит
  MAX\_DELEGATED\_CERTS = 10 в TlsOcspVerifier.extractDelegatedCerts().
  При превышении возникает TlsException(ALERT\_DECODE\_ERROR) с
  fail-closed.

- InMemoryPskStore: evictExpired() вызывалась на каждый add() (каждый
  handshake), сканируя все 1000 PSK-записей O(n) на горячем пути.
  Перенесен вызов раз в ~1024 вставок — overhead снижен до O(n/1024).

- PskStore + InMemoryPskStore: добавлен clear() для корректного сброса
  состояния между JMH-итерациями.

- JsseHandshakeBench (bench/): добавлен @Setup(Level.Iteration)
  resetPskStore() — очищает PSK-хранилище между итерациями, чтобы
  накопление state не искажало замеры (не позволяет клиентскому коду
  влиять на JMH-бенчмарк).

## Модуль crypto-gost-jsse

### Добавлено

В примерах jsse модуля добавлен консольный клиент **gost-curl**, который
можно использовать на практике. Работает только с *ГОСТ TLS 1.3* и не
поддерживает западные алгоритмы, для которых уже есть стандартый `curl`.
Детали:

- **GostCurl** — консольный HTTP-клиент (curl-аналог):

  - Основан на OkHttp + GostSSLSocketFactory, HTTP/1.1 и HTTP/2.

  - Авто-детект PEM/DER для CA-сертификата.

  - Режимы --ca (проверка сервера) и --insecure (без проверки).

  - CLI: -X, -d, -H, -v, -o, -L, -k, --ca, --connect-timeout,
    --read-timeout.

  - Сборка: `make gost-curl` (Maven), `make gost-curl-jar` (fat JAR),
    `make gost-curl-native` (native binary через GraalVM 25+).

  - Тестовый сервер для проверки `gost-curl`:
    `make -C examples/jsse test-server`.

- **Поддержка multi-ca**:

  - GostX509TrustManager: новый конструктор
    (List&lt;PublicKeyParameters&gt;, OcspPolicy, OcspFetcher). Старые
    single-key конструкторы сохранены как обёртки.

  - GostSsl.buildContext: все trustedCaDers\[\] распаковываются в
    List&lt;PublicKeyParameters&gt; (ранее использовался только \[0\],
    остальные CA игнорировались).

  - GostSslBuilder: javadoc trustCa() исправлен — ограничение на один CA
    снято.

- **Добавлена CRL-проверка**: политика (CrlPolicy), HTTP-fetcher с
  SSRF-защитой (JdkHttpCrlFetcher), кэш с nextUpdate-инвалидацией
  (CrlCache).

  - Интеграция в GostX509TrustManager — CRL-проверка при отсутствии
    OCSP, цикл по CDP-зеркалам, fail-closed для REQUIRE-политики, CRL и
    для клиентских сертификатов.

- Новый отчет crypto-gost-jsse/doc/stress-test2.md о стресс-тесте.

### Исправлено

- Исправлен запуск stress-тестов: `surefire.excludedGroups` в корневом
  `pom.xml` исключал группу `stress`, из-за чего `JsseStressTest` не
  запускался.

- Исправлен `make springboot`: в профиль `springboot` добавлен
  `spring-boot-maven-plugin` 3.4.5, без которого `spring-boot:run` не
  резолвился (`NoPluginFoundForPrefixException`).

- Удалён неиспользуемый тестовый ресурс `test.p12` (пароль нигде не
  задавался, файл никем не загружался).

- GostSSLEngine: защита от OOM-атаки через handshakeInputBuf (лимит 2.6
  MB, ALERT\_RECORD\_OVERFLOW)

- GostSSLEngine: closeInbound() без closeOutbound() больше не бросает
  SSLException (RFC 8446 §6.1, совместимость с Netty)

- GostSSLEngine: setEnableSessionCreation(false) теперь соблюдается на
  сервере (ALERT\_HANDSHAKE\_FAILURE если нет PSK)

- GostSSLEngine: детали внутренних ошибок хендшейка убраны из текста
  исключений — уходят в DEBUG-лог, наружу только generic alert
  ("Handshake error" / "Handshake failed").

- GostSSLEngine: peerHost:peerPort понижены с INFO до DEBUG (152-ФЗ:
  hostname/IP могут быть персональными данными).

- Дефолтный GostX509TrustManager без CA-ключа теперь выдаёт WARNING с
  инструкцией по исправлению (actionable diagnostic).

- устранена утечка ключей при прерванном handshake —
  destroyHandshakeEngine() теперь зануляет
  pendingWriteKey/pendingWriteIv через TlsUtils.wipeArray

- Обеспечено затирание буферов расшифрованных данных —
  AppInputStream.read() теперь зануляет leftover через
  TlsUtils.wipeArray() перед освобождением и затирает readDst.array()
  после переноса остатка в leftover. AppInputStream.close() затирает оба
  буфера финально.

- OCSP-кэш: TTL теперь учитывает nextUpdate из OCSP-ответа
  (min(nextUpdate + GRACE\_MS, ocspCacheTtlMs)), а не только
  фиксированный 1 час. GRACE\_MS = 1 час (как в CrlCache). Исключает
  хранение устаревшего статуса отзыва.

- Исправлена гонка в GostSSLEngine.getDelegatedTask() при конкурентном
  вызове из нескольких потоков. pendingTask заменён на
  AtomicReference&lt;Runnable&gt; с атомарным getAndSet(null);
  taskInProgress не сбрасывается до завершения задачи — инвариант
  NEED\_TASK сохранён. Это больше косметика, т.к. в реальности такая
  гонка может возникнуть только при нарушении JSSE-контракта вызывающей
  программой.

### Изменено

- GostSsl.java: замена pemToDer(caPem) на
  TlsCertificate.fromPemOrDer().toDer(), toX509Chain() →
  CertificateBridge.toJca(), удалён приватный метод toX509Chain

- 5 тестов (Loopback, InitialStateContract, PostHandshake, UnwrapFuzz,
  SocketTcp): toJcaChain переписан через CertificateBridge.toJca()

# \[0.3.1\] - 17-05-2026

## Модуль crypto-gost-tls13

- Устранено дублирование OID-констант:

  - добавлены EXT\_SERVER\_AUTH и EXT\_CLIENT\_AUTH в GostOids,

  - приватные OID-массивы в TlsCertificate заменены на публичные
    константы TlsDerParser, хардкоженые OID-строки в TlsTestHelper,
    ExampleUtils, TlsSessionTest, TlsCertificateTest заменены на ссылки
    на GostOids.

  - В ExamplesCertHelper строка "RssysGostJsse" заменена на
    GostJsseConstants.PROVIDER\_NAME.

## Модуль crypto-gost-jsse

### Изменено

- GostTestCerts, GostTestContext перемещены из src/main в src/test;
  публикуются через test-jar.

- pom.xml — добавлена сборка test-jar (по образцу crypto-gost-tls13).

- JsseCertHelper перемещён в src/test. Добавлен ExamplesCertHelper в
  src/main — генерирует сертификаты через production API, фиксированные
  DN.

- Demo-классы (JettyEchoServer, NettyEchoServer, UndertowEchoServer,
  TomcatEchoServer, GostSslConfig) обновлены на ExamplesCertHelper.

- pom.xml — добавлена зависимость crypto-gost-jsse:test-jar (test
  scope).

- GostSSLEngine: замена перегрузок конструктора на factory-методы.  
  Убрана 6-аргументная перегрузка конструктора, где параметр
  sessionContext имел разную семантику для клиента и сервера.  
  Вместо неё — два явных factory-метода createForClient() и
  createForServer().  
  7-аргументный конструктор стал package-private: он нужен только для
  SSLContext.createSSLEngine(), где режим неизвестен до вызова
  setUseClientMode().

### Исправлено

- В GostSSLSessionContext кэш сессий был обёрнут в
  Collections.synchronizedMap, который использует synchronized-блоки.
  Это вызывало pinning виртуальных потоков, что сводило на нет
  преимущества vthreads. Заменили на ReentrantLock — LRU-семантика
  (LinkedHashMap с removeEldestEntry) сохранена, pinning устранён.

- GostSSLEngine: буфер для расшифрованных записей вынесен в поле
  экземпляра — устранена аллокация 16 КБ на каждый unwrap().

- GostSSLEngine: оптимизация горячего пути и защита от повторной
  обработки данных:

  - unwrap(): массив для отслеживания позиций dst-буферов вынесен в поле
    экземпляра с ленивым resize — устранена аллокация на каждый вызов.

  - handleEngineKeyChanges() обёрнут в try-catch(RuntimeException) с
    гарантированным handshakeInputBuf.reset() — предотвращена повторная
    обработка уже обработанных handshake-данных при неожиданном
    исключении.

  - Убрано лишнее клонирование ключей при смене трафиковых ключей:
    getKey()/getIv() уже возвращают защитные копии, внешний .clone()
    удалён.

### Добавлено

- GostSsl — статический фасад для создания SSLContext одним вызовом.
  Поддерживает три формата входных данных: PKCS12, PEM-строки,
  DER-байты. Методы verify() и verifyServer() для loopback-проверки
  совместимости ключей. GostSslBuilder для сложных случаев с OCSP
  stapling и session cache. GostSslException как единая точка обработки
  ошибок.

- JsseStressTest — длительный стресс-тест JSSE-провайдера под смешанной
  нагрузкой: 30 коротких сессий, 20 средних keep-alive, 5 длинных
  throughput-сессий и 10 chaos-обрывов параллельно в виртуальных
  потоках. Проверяет отсутствие утечек памяти, зависаний и корректность
  TLS при длительной работе. Запуск:
  `make -C examples/jsse test-stress`.

- UndertowStressTest — стресс-тест JSSE-провайдера через реальный
  HTTP-сервер Undertow с теми же четырьмя профилями нагрузки. Profile 3
  показал 0 ошибок на 17k HTTP-запросов (16KB, keep-alive) за 5 минут,
  283 MB transferred.

- Добавлены фаззинг-тесты на базе Jazzer:

  - TlsRecordUnprotectFuzzTest (crypto-gost-tls13) — три entry point
    TlsRecord.unprotect (ByteBuffer, byte\[\], zero-alloc) и stateful
    сессия из N последовательных записей для проверки seqNum и TLSTREE
    между вызовами. 15 seed-файлов.

  - GostSSLEngineUnwrapFuzzTest (crypto-gost-jsse) — pre-handshake путь
    GostSSLEngine.unwrap в состояниях INITIAL и HANDSHAKE. 7
    seed-файлов.

### Документация

- `crypto-gost-jsse/README.adoc` — обновлены примеры кода.

# \[0.3.0\] - 16-05-2026

## Общее

- Добавлен `.mvn/maven-config` для управления версией библиотеки из
  единого места.

- В корневой Makefile добавлены цели:

  - `doc` - для формирования документов md, на основе asciidoc.

  - `version` - для управления и обновления версией библиотеки

## Целевая платформа - JDK 21

Для JSSE-провайдера это означает: архитектура с самого начала должна
минимизировать зависимость от sun.security.ssl.\*. Дело в том, что API,
связанное с TLS значительно стабилизировалось только к JDK17: исправлены
десятки багов в state machine, session resumption, post-handshake auth,
0-RTT обработке.  

С JDK 17 по JDK 21 также произошли значительные улучшения и исправления
в TLS 1.3: post-handshake authentication, session ticket handling,
лучшая обработка middlebox compatibility mode, исправления в HKDF
использовании.  

Вирутальные потоки - важная вещь для производительности JSSE модуля.

JEP 452 — Key Encapsulation Mechanism API в JDK 21 заметное изменение
для криптографического стека. Появился javax.crypto.KEM —
стандартизированная абстракция для механизмов инкапсуляции ключей.

Постквантовые алгоритмы — это KEM по природе. TLS 1.3 hybrid key
exchange (RFC 9180-style) тоже мыслится в терминах KEM.

В ядре Mgm-режим, а значит TLS 1.3 может быть кратно ускорен благодаря
арифметике доступной в Java 21.

**Поэтому по совокупности факторов мной принято решение вести дальнейшую
разработу всех модулей под JDK 21.**

Старые версии (0.2.1 и ниже) для модулей `crypto-gost-core`,
`crypto-gost-tls13` остались доступны под JDK 11. Их можно скачать из
опубликованных релизов.

## Модуль crypto-gost-core.

Переход JDK 11 → JDK 21.

Было:

Кузнечик и MGM работали на байтовых массивах. Каждый 16-байтовый блок —
это byte\[16\], который создавался заново на каждой операции. Таблицы
подстановки хранились как byte\[\]\[\]\[\]. GF(2^128) умножение делалось
побитово — 128 итераций, каждая сдвигала 16 байт по одному.  
**Итог:** 4–6 МБ/с на TLS-записях.

Стало:

- Блок как два long вместо byte\[16\]. 128-битное состояние хранится как
  пара (hi, lo) — JIT держит их в регистрах, никаких аллокаций на
  горячем пути.

- Таблицы переупакованы в long\[\]\[\] с встроенной S-заменой. Вместо
  двух lookup-ов на байт (T\[i\]\[PI\[x\]\]) — один (T\_S\[i\]\[x\]).
  Вместо 256 байтовых XOR на раунд — 32 длинных.

- GF(2^128) переведён на 4-битный Horner. Вместо 128 однобитных итераций
  — 32 итерации по nibble с предвычисленной таблицей на 16 элементов.
  ~1.75× быстрее на MAC-шаге MGM.  

**Итог:** 4–6 МБ/с → 48–49 МБ/с на 16KB TLS-записях. Ускорение ~9× на
чистой Java, без нативного кода, без изменения протокола.

Остальные режимы: CBC, CFB, CTR, OFB - тоже кратно ускорены примерно в
8-9 раз, но бенчмарки проводились для проверки только для CTR, CFB.

## Модуль crypto-gost-jsse

Новый модуль `crypto-gost-jsse` — JSSE-провайдер для ГОСТ TLS 1.3. Это
прослойка между стандартным JSSE-API (`SSLContext`, `SSLEngine`,
`SSLSocket`, `KeyManagerFactory`, `TrustManagerFactory`) и ядром
протокола из `crypto-gost-tls13`. После регистрации провайдера любой
существующий Java-код, работающий со стандартным `SSLContext`, начинает
работать с ГОСТ TLS 1.3 без изменений в самом коде.

    Security.addProvider(new RssysGostJsseProvider());
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");

Дальше — обычный JSSE-сценарий: `ctx.init(km, tm, null)`,
`ctx.createSSLEngine(host, port)`, `wrap()`/`unwrap()`. Это даёт ГОСТ
TLS в любом Java-стеке, который умеет работать с `SSLContext`:
HTTP-клиенты, JDBC-драйверы, message brokers, embedded HTTPS-серверы,
Netty.

### Что реализовано

JSSE API

- `RssysGostJsseProvider` — регистрация провайдера через
  `Security.addProvider`. Имена сервисов — без алиасов «TLS» и «PKIX»,
  чтобы случайно не подменить стандартный SunJSSE.

- `GostSSLContextSpi` — реализация `SSLContextSpi`: создание
  `SSLEngine`, `SSLSocketFactory`, `SSLServerSocketFactory`, управление
  `SSLSessionContext`.

- `GostSSLEngine` — реализация `SSLEngine` (wrap/unwrap state machine).
  Раздельные блокировки для inbound и outbound (JSSE допускает
  параллельный вызов wrap и unwrap из разных потоков). Дорогие операции
  — валидация сертификата, OCSP-fetch — выносятся в `NEED_TASK`, чтобы
  не блокировать carrier thread виртуального потока.

- `GostSSLSession` — реализация `SSLSession`: peer-сертификаты, cipher
  suite, выбранный ALPN-протокол, время создания сессии.

- `GostSSLSessionContext` — реализация `SSLSessionContext` с
  LRU-эвикцией: настраиваемый размер кэша (`setSessionCacheSize`) и
  время жизни (`setSessionTimeout`).

SSLSocket

- `GostSSLSocket` / `GostSSLServerSocket` — реализация `SSLSocket`
  поверх обычного TCP-сокета. Поддерживает layered socket (как
  использует `HttpsURLConnection`), `HandshakeCompletedListener`,
  параллельное чтение и запись из разных потоков, `setSoTimeout`.

- `GostSSLSocketFactory` / `GostSSLServerSocketFactory` — фабрики
  сокетов, доступные через `ctx.getSocketFactory()`.

Key/Trust managers

- `GostKeyManagerFactorySpi` + `GostX509KeyManager` — управление ключами
  из стандартного `KeyStore` (PKCS12 с ГОСТ-ключами читается
  JDK-средствами через JCA-провайдер `crypto-gost-core`).

- `GostTrustManagerFactorySpi` + `GostX509TrustManager` — валидация
  цепочки сертификатов пира через `TlsCertificateValidator` из
  `crypto-gost-tls13`. Реализует `X509ExtendedTrustManager` — все шесть
  методов `checkClientTrusted`/`checkServerTrusted` (без контекста, с
  `Socket`, с `SSLEngine`).

OCSP — четыре политики

- `OcspPolicy.DISABLED` — OCSP-проверка отключена.

- `OcspPolicy.IF_PRESENT` — проверять только если OCSP-ответ
  присутствует (stapled). Если нет — fail-open.

- `OcspPolicy.STAPLING_REQUIRED` — OCSP stapling обязателен, без него
  соединение отклоняется.

- `OcspPolicy.STAPLING_OR_FETCH` — сначала пробуем stapled-ответ, при
  его отсутствии — fetch с CA через HTTP.

- `JdkHttpOcspFetcher` — реализация OCSP fetcher через стандартный
  `HttpURLConnection`. Извлекает URI ответчика из AuthorityInfoAccess
  сертификата, отправляет POST с подписанным OCSP-запросом.

- `OcspRequestBuilder` — построение OCSP-запроса с поддержкой nonce
  (RFC 8954) и опциональной подписи (RFC 6960 §3.1).

- Кеширование OCSP-ответов с настраиваемым TTL (по умолчанию час). Кэш
  разделяет ответы по `(issuerSerialHex, certSerialHex)`.

Bridge между JSSE и tls13

- `CertificateBridge` — конверсия `java.security.cert.X509Certificate`
  (JCA-тип) ↔ `TlsCertificate` (tls13-тип).

- `KeyBridge` — конверсия `java.security.PrivateKey` ↔
  `PrivateKeyParameters` (tls13-тип).

- `IanaMapper` — маппинг IANA-имён cipher suite и signature scheme
  (например, `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`) в числовые
  коды tls13. Нужен потому, что JSSE задаёт настройки строками, а tls13
  — числами.

- `AlertMapper` — конверсия TLS-алертов в `SSLException` подклассы
  (`SSLHandshakeException`, `SSLProtocolException`).

### Поддерживаемые JSSE-features

- Server-only TLS (стандартный HTTPS).

- mTLS: `setNeedClientAuth(true)` и `setWantClientAuth(true)` —
  обязательный и опциональный клиентский сертификат.

- ALPN (RFC 7301) через `SSLParameters.setApplicationProtocols`.

- SNI (RFC 6066) через `SSLParameters.setServerNames` — на клиенте, и
  multi-tenant выбор сертификата по hostname — на сервере.

- `KeyUpdate` (RFC 8446 §4.6.3): авто-инициация при приближении к SNMAX
  cipher suite, защита от флуда (не больше 32 KeyUpdate за сессию).

- Корректное закрытие через `closeOutbound`/`closeInbound`: обмен
  `close_notify` алертами, затирание ключей.

- `HandshakeCompletedListener` для `SSLSocket`.

### Дополнительный модуль crypto-gost-netty

Модуль `crypto-gost-netty` — обёртка для интеграции с Netty. Содержит
`GostSslContextBuilder` — билдер `io.netty.handler.ssl.SslContext`
поверх `GostSSLContext`. Позволяет использовать ГОСТ TLS в любом
приложении на Netty: gRPC, Reactor Netty, Vert.x. Через эту цепочку ГОСТ
TLS доступен в Spring WebFlux, RSocket и других reactive-стеках.

### Тестирование

- 86 unit-тестов: контрактные проверки `SSLEngine` initial state,
  loopback handshake клиент-сервер через `SSLEngine`, post-handshake
  (KeyUpdate, NewSessionTicket), ALPN-селектор, eviction
  `SSLSessionContext`.

- Тесты `GostSSLSocket` через реальные TCP-сокеты (loopback): обмен
  данными, mTLS, передача 100 КБ, последовательные соединения,
  auto-handshake при первой операции записи, layered socket как у
  `HttpsURLConnection`, `HandshakeCompletedListener`, параллельное
  чтение/запись из разных потоков, PSK resumption между двумя
  TCP-соединениями, разрыв соединения узлом, `SocketTimeoutException`
  при молчащем узле.

- Тест с встроенным HTTPS-сервером на `GostSSLServerSocket` через
  `HttpsURLConnection`-запрос — проверка реального HTTP-over-TLS
  сценария.

- OCSP-тесты: построение запроса с nonce и подписью, верификация политик
  (DISABLED, IF\_PRESENT, STAPLING\_REQUIRED), HTTP-fetch.

- Тесты `GostX509KeyManager`: выбор сертификата по issuer hint
  (`chooseClientAlias` с массивом issuers от сервера).

- Бенчмарки JMH (`bench/jsse`): `JsseHandshakeBench` (полный handshake,
  mTLS), `JsseRecordBench` (wrap/unwrap на 100 B / 1 KB / 16 KB).
  Накладные расходы JSSE-обёртки на record-уровне — в пределах
  погрешности измерений.

### Целевые сценарии использования

- Embedded HTTPS-серверы (Tomcat, Jetty, Undertow) — через стандартную
  настройку `SSLContext` в `application.yml` или connector config.

- HTTP-клиенты (RestTemplate, WebClient, OkHttp, JDK HttpClient, Apache
  HttpClient) — через
  `SSLContext.getInstance("TLSv1.3", "RssysGostJsse")`.

- JDBC-драйверы (PostgreSQL, MySQL и другие) с поддержкой кастомного
  `SSLContext`.

- gRPC, Reactor Netty, Vert.x — через модуль `crypto-gost-netty`.

- Любой код, использующий стандартный JSSE-API.

### Текущие ограничения

- Не сертифицирован. Сертификации нет в планах. Библиотека
  позиционируется для коммерческого и внутреннего использования.

- TLS 1.2 + ГОСТ не поддерживается и не планируется в силу множественных
  слабостей TLS 1.2 — только TLS 1.3 (RFC 9367).

- `SSLSession` resumption через `SSLSessionContext` работает на уровне
  tls13 (PSK), но JSSE-уровневый lookup по `peerHost`/`peerPort`
  доработан не полностью.

- Не проверена кросс-совместимость с другими внешними ГОСТ TLS
  реализациями.

- HelloRetryRequest, 0-RTT, Magma-MGM cipher suites — не поддерживаются
  (наследуется от ограничений `crypto-gost-tls13`).

#### Изменено в GostSSLEngine

- `setUseClientMode(false)` больше не требует hostname для серверного
  engine. Ранее вызов `createSSLEngine()` без host (как делают
  Tomcat/Spring Boot) приводил к `IllegalArgumentException`. Теперь —
  `LOG.warning`: PSK resumption отключается, но базовый handshake
  выполняется штатно.

#### Примеры интеграции (examples/jsse)

Добавлен модуль `examples-jsse` (теперь `examples/jsse/`) — 5 примеров
интеграции с серверами приложений, проверяющих полный цикл: сертификаты
→ SSLContext → embedded server → TLS 1.3 handshake → echo-протокол.

- **Netty 4.2**: `GostSslContextBuilder.forServer(km)` +
  `ServerBootstrap` + inline Netty-клиент. CountDownLatch синхронизация.

- **Jetty 12**: `SslContextFactory.Server.setSslContext(sslContext)` +
  `Handler.Abstract` (Jetty 12 core handler API).

- **Undertow 2**:
  `Undertow.builder().addHttpsListener(port, host, sslContext)` — самый
  лаконичный вариант (3 строки конфигурации).

- **Tomcat 11 (Jakarta EE 10)**: кастомный `SSLImplementation` с
  вложенными `GostSSLImplementation`/`GostSSLUtil`. В обход
  `SSLUtilBase.getKeyManagers()` (требует keystore file). Работает через
  `connector.setProperty("sslImplementation", ...)` →
  `IntrospectionUtils` → `setSslImplementationName()`.

- **Spring Boot 3.4**: `WebServerFactoryCustomizer` +
  `SSLImplementation` (та же схема, что standalone Tomcat 11). Провайдер
  регистрируется в `static {}` — до инициализации Spring-контекста.

Makefile в `examples/jsse/`: цели `netty`, `jetty`, `undertow`,
`tomcat`, `springboot`, `all` (последовательно), `test`
(@SpringBootTest).

`@SpringBootTest` + `GostSSLSocket.startHandshake()`: подтверждает TLS
1.3 handshake с ГОСТ-наборами в embedded Tomcat.

#### Модуль crypto-gost-jsse-testkit

Вспомогательные классы для создания ГОСТ TLS-контекста в тестах и
примерах. Используется примерами `examples/jsse`, доступен для тестов
`crypto-gost-jsse`.

- `GostTestCerts.createServerCert()` — генерация CA + подписанного
  сертификата с SAN localhost. DER-кодирование вручную, без внешних
  ASN.1-зависимостей.

- `GostTestContext.buildSslContext(certs)` — регистрация провайдера
  (`Security.addProvider`) + создание `SSLContext` (`TLSv1.3`,
  `RssysGostJsse`) + инициализация key/trust managers.

- Позволяет создавать SSLContext одной строкой вместо 10 строк
  boilerplate.

- Может быть использован тестами `crypto-gost-jsse` для устранения
  дублирования `Security.addProvider` + `SSLContext.getInstance`.

Этот релиз исправляет ошибки и дает улучшения для производительности и
готовности к реализации следующего модуля JSSE.

Исправлено несколько мест, где на каждую TLS-запись создавались
временные массивы в памяти. Теперь данные передаются от сетевого буфера
до расшифровки без лишних копий. От этого GC стало меньше работы, а на
активных соединениях (сотни и тысячи записей в секунду) разница заметна.

Итог по аллокациям: отправка записи 2→1, чтение данных 4→1, чтение
handshake 3→0. Для сессии с 1000 записей/с нагрузка на GC снижена с 80
до 30 MB/s.

### Изменено

- PSK lookup на стороне сервера перенесён из TlsSession и jsse-слоя в
  `TlsHandshakeEngine.receiveClientHello()`. При получении ClientHello
  engine сам извлекает PSK identity, ищет в store
  (`setServerPskStore()`) и проверяет binder. Исключено дублирование
  парсинга ClientHello, устранён layer violation в jsse-модуле.

- TlsRecord, шифрование: tls-запись собирается прямо из входного буфера
  в выходной, минуя промежуточные копии в памяти.

- TlsRecord, расшифровка: массив под входящую tls-запись выделяется один
  раз при создании объекта и переиспользуется. Ранее каждая расшифровка
  создавала новый массив.

- Транспортный уровень: при приёме записи (Socket- и Channel-транспорты)
  все три временных массива (заголовок, тело, итоговая запись) заменены
  на один переиспользуемый буфер.

- Канальный транспорт (ChannelTlsTransport): теперь чтение через
  ByteBuffer идёт напрямую в канал, без промежуточных копий.

- Сессия: три ключевых пути — приём handshake, приём данных приложения,
  post-handshake сообщения — теперь используют цепочку ByteBuffer от
  транспорта до расшифровки, без промежуточных массивов.

### Добавлено

- Тест на регрессию шифрования: запись с известными ключами — защита от
  случайного изменения алгоритма.

- Тест на нехватку места в выходном буфере: если буфер слишком мал,
  метод сообщает об ошибке, не начиная шифрование.

- Тест на смещение указателей в ByteBuffer после шифрования.

- Тест на переиспользование буфера расшифровки: три расшифровки разного
  размера подряд через один объект — проверка, что остатки предыдущей
  записи не попадают в результат следующей.

- Тесты ByteBuffer-пути для канального транспорта: heap и direct буферы.

- Добавлены IANA-имена для cipher suite (например,
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`), именованных групп кривых
  (`GC256A`–`GC512C`) и схем подписи
  (`gostr34102012_256a`–`gostr34102012_512c`). Теперь каждую сущность
  можно найти не только по числовому коду (0xC103), но и по её
  стандартному имени из реестра — это нужно для JSSE-модуля, где
  настройки TLS задаются строками, а не числами.

- TlsMessageBuilder.buildEmptyCertificateBody() — служебный метод для
  построения пустого списка сертификатов. Нужен, когда сервер запросил
  сертификат клиента, а у клиента его нет: по RFC 8446 он обязан
  отправить пустой список, а не обрывать соединение.

- TlsRecord.isApproachingRekeyLimit() — предикат для проактивного
  KeyUpdate. Возвращает `true` при достижении 80% от SNMAX cipher suite.
  Позволяет JSSE-слою инициировать KeyUpdate до исчерпания лимита
  записей, без прерывания передачи.

- TlsCertificate.getOcspUris() / getCaIssuersUris() — разделение URI из
  AuthorityInfoAccess по типу AccessMethod (OCSP responder vs
  caIssuers). Нужен для отправки OCSP-запроса по правильному URI.

- TlsCertificate.getEncoded() — полный DER-encoded сертификат. Нужен для
  построения OCSP-запроса и других задач, где требуется исходная
  DER-кодировка.

- TlsHandshakeEngine.setAlpnSelector(Function&lt;List&lt;String&gt;,
  String&gt;) — ALPN-селектор для JSSE. Позволяет прикладному коду
  выбирать протокол динамически через callback, а не из статического
  списка. Если selector задан — engine не выбирает ALPN самостоятельно.

- TlsRecord: порог rekey теперь instance-level
  (setRekeyThreshold(long)), а не жёстко зашитый 80% от SNMAX. Нужен для
  тестирования KeyUpdate без прогона триллионов записей.

- `GostOids.java` — единый источник OID-строк для ГОСТ-криптографии:
  подписи (SIG\_WITH\_DIGEST\_256/512), кривые (CURVE\_256A–512C),
  дайджесты (DIGEST\_256/512), расширения X.509v3
  (EXT\_BC/KU/SAN/EKU/AIA), DN-атрибуты (ATTR\_CN), OCSP-идентификаторы
  (OCSP\_AD/BASIC). Заменил разрозненные OID-литералы в TlsTestHelper,
  TlsCertificateTest, OcspRequestBuilder, GostTestCerts.

- TlsOcspVerifier: добавлена проверка issuerNameHash и issuerKeyHash в
  CertID OCSP-ответа (defense-in-depth). Ранее проверялся только
  serialNumber.

- `OcspCertIdHasher` — единый источник истины для вычисления хешей
  CertID (issuerNameHash, issuerKeyHash) OCSP-ответа (RFC 6960 §4.1.1).
  Выделен из `TlsOcspVerifier` для консистентного использования в
  верификации и построении OCSP-запроса. Хеш ключа считается от BIT
  STRING value SubjectPublicKeyInfo (с байтом unused-bits, без tag и
  length BIT STRING) — строго по RFC.

- `TlsOcspVerifier.verifyNonce()` — проверка OCSP nonce (RFC 8954).
  Поддерживает strict и best-effort режимы: strict — nonce обязателен,
  best-effort — проверка только если nonce присутствует в ответе.

- `TlsCertificate.getOcspNonce()` / `setOcspNonce()` — хранение nonce,
  отправленного в OCSP-запросе, для последующей верификации.

- `TlsCertificate.verifyOcspResponse(caKey, issuer)` — перегрузка с
  явным сертификатом издателя для проверки CertID (issuerNameHash +
  issuerKeyHash).

- Best-effort OCSP для intermediate сертификатов: в
  `TlsCertificateValidator.checkServerCertificateChain()` добавлен цикл
  верификации OCSP-ответов для intermediate сертификатов в цепочке. Если
  intermediate не имеет OCSP-ответа — цепочка не бракуется (fail-open,
  следуя RFC).

- `TlsSession.wasResumed()` — проверка выполнения handshake через PSK
  resumption. Возвращает `true`, если handshake прошёл без ECDHE (после
  ввода флага `wasResumed()` в `TlsSession` и флага `isPskAccepted()` в
  `TlsHandshakeEngine`).

- `InMemoryPskStore.getForResumption()` теперь возвращает entry с
  максимальным `issueTime` (самый свежий). Ранее — первый non-expired из
  недетерминированного порядка `ConcurrentHashMap.values()`, из-за чего
  при накоплении N&gt;1 entry клиент мог отправить stale ticket →
  fallback на full handshake.

- `TlsServerConfig.withTicketsToSend(int)` — количество
  NewSessionTicket, отправляемых после handshake (≥ 1, RFC 8446 §4.6.1).
  `ticket_nonce` монотонный (big-endian counter), гарантирует
  уникальность nonce в пределах соединения.

- `TlsOcspVerifier.extractDelegatedCerts(byte[])` — извлекает
  сертификаты делегированного OCSP-responder’а из поля `certs`
  BasicOCSPResponse (RFC 6960 §2.6, case b).

- `TlsCertificateValidator.checkServerCertificateChain()`: при неудаче
  верификации OCSP-ответа ключом issuer’а автоматически пробует
  делегированные responder-сертификаты из поля `certs` OCSP-ответа.

- `TlsCertificate.isOcspSigning()` — проверка EKU id-kp-OCSPSigning
  (1.3.6.1.5.5.7.3.9). Учитывает anyExtendedKeyUsage (2.5.29.37.0) и
  отсутствие EKU (сертификат без ограничений).

- `OcspRequestBuilder.buildSigned(byte[], byte[], PrivateKeyParameters, ECParameters)`
  — опциональное подписывание OCSP-запроса подписью GOST R 34.10-2012.
  Если ключ не задан — эквивалентно `buildWithNonce()`.

- `OcspCertIdHasher.hashIssuerName(TlsCertificate)` /
  `hashIssuerPublicKey(TlsCertificate)` — перегрузки, принимающие объект
  сертификата вместо DER-массива.

### Исправлено

- mTLS: если сервер запросил сертификат, а у клиента его нет, клиент
  больше не обрывает соединение с алертом «требуется сертификат». Теперь
  он отправляет пустой список сертификатов, как велит RFC 8446 §4.4.2, и
  сервер сам решает, принять соединение без клиентского сертификата или
  отказать. Исправление нужно для поддержки wantClientAuth в JSSE-модуле
  — когда сервер хочет получить сертификат клиента, но не требует его.

- Алерт при ошибке handshake: если сбой случился в момент переключения
  ключей шифрования, алерт уходил открытым текстом, а собеседник не мог
  его расшифровать и падал с технической ошибкой. Теперь алерт шифруется
  новыми ключами, и собеседник корректно его принимает — вместо того
  чтобы спотыкаться о непонятные байты.

- Handshake: если во время рукопожатия пришёл алерт, клиент или сервер
  раньше падали с «неожиданное сообщение» (unexpected\_message, 10) — и
  причину отказа приходилось угадывать. Теперь алерт распознаётся и
  пробрасывается с его настоящим кодом — диагностика сразу показывает,
  что именно пошло не так на той стороне.

- issuerKeyHash в OCSP CertID: исправлен расчёт хеша на RFC-строгий — от
  BIT STRING value SubjectPublicKeyInfo (с байтом unused-bits, без tag и
  length BIT STRING). Ранее хеш считался от полного SPKI, что не
  соответствует RFC 6960 §4.1.1. Исправлено в `OcspCertIdHasher`,
  `TlsOcspVerifier`, `OcspRequestBuilder`,
  `TlsTestHelper.buildOcspResponse`.

- Double-readTlv в findTbsOffset: код использовал tagStart (`tlv[0]`)
  вместо valueStart для позиционирования при последовательном разборе
  TLV, что приводило к повторному чтению tag+length — пропуску
  очередного поля. `readTlv` возвращает `[valueStart, valueEnd]`, а не
  `[tagStart, valueEnd]`. Исправлено в 6 местах:
  `OcspCertIdHasher.extractSubject`,
  `OcspCertIdHasher.extractBitStringValue`, `OcspRequestBuilder`,
  тестовые хелперы.

- PSK resumption: `InMemoryPskStore.getForResumption()` возвращал
  недетерминированный entry (зависит от bucket-порядка
  `ConcurrentHashMap`). При накоплении N &gt; 1 entry клиент мог
  отправить stale ticket, который сервер уже удалил (single-use, RFC
  8446 §4.6.1) → handshake проходил полный цикл ECDHE, PSK неверно
  показывал speedup ~0 %. Фикс: выбор entry с максимальным `issueTime`
  (самый свежий NST).

- OCSP delegated responders: при верификации OCSP-ответа, если подпись
  не совпала с ключом непосредственного issuer’а, теперь автоматически
  пробуются делегированные responder-сертификаты из поля `certs`
  BasicOCSPResponse (RFC 6960 §2.6, case b) с проверкой EKU
  id-kp-OCSPSigning.

- ALPN (RFC 7301): исправлена обработка mismatch — когда клиент и сервер
  предлагают разные протоколы (например, клиент h2, сервер http/1.1).
  JDK/JdkAlpnSslEngine по договорённости возвращает пустую строку "",
  если общий протокол не найден — а не null, как можно было бы ожидать.
  Раньше движок проверял только на null, пропускал пустую строку,
  пробовал найти её в списке клиента и падал с ошибкой. Теперь пустая
  строка понимается как «протокол не согласован» — рукопожатие
  продолжается без ALPN, как и велит RFC 7301.

- TlsTestHelper, TlsCertificateTest, OcspRequestBuilder: все OID-строки
  заменены на константы GostOids.\* (SIG\_WITH\_DIGEST\_256/512,
  DIGEST\_256/512, CURVE\_256A и др.).

## Бенчмарки

- Обновлены бенчмарки в связи с новой математикой, ускорения Кузнечика.

- Обновлены pom-файлы в бенчмарках для управления версией.

# \[0.2.1\] - 09-05-2026

## Модуль crypto-gost-tls

Выпуск посвящен в основном корректировке пользовательского API: удобству
использования, устранению двусмысленности.

### Добавлено

- Извлечение данных из сертификата:

- Ссылки на OCSP-сервер и точки распространения CRL (списки отзыва).

- Идентификаторы ключей (SubjectKeyIdentifier, AuthorityKeyIdentifier).

- Политики сертификата (CertificatePolicies).

- Человеко-читаемое представление Distinguished Name (строка вида
  "CN=example.com, O=Org" + поиск по отдельным полям).

- equals/hashCode/toString для TlsCertificate.

- Выбор сертификата по имени хоста (SNI):
  TlsServerConfig.withSniSelector(). Позволяет одному серверу на одном
  порту обслуживать несколько доменов с разными сертификатами — без
  предупреждений в браузере.

- Легковесный парсер SNI: TlsMessageParser.parseClientHelloSni().

- 50+ новых тестов: парсинг SNI, выбор сертификата по SNI, экранирование
  спецсимволов в DN, ALPN через конфиг.

- PskEntry — отдельный класс для PSK-записи (раньше был вложенным в
  PskStore). Проще импортировать и использовать.

### Изменено

- TlsSession.resolveSigScheme: упрощён до прямого маппинга namedGroup →
  signatureScheme.

- TlsCertificateValidator: обе проверки OCSP-стаплинга (== null / !=
  null) заменены на симметричные hasOcspResponse() / !hasOcspResponse().

- TlsSessionTest: исправлена проверка на getKeySize().

- TlsHandshakeEngine: messageBuilder — non-final (единственное
  исключение). В receiveClientHello() добавлен блок выбора сертификата
  по SNI после PSK и до acceptableSchemes. Конструктор принимает
  SniCertificateSelector.

- getAiaUris/getCdpUris: javadoc теперь предупреждает об SSRF-рисках и
  перечисляет обязательные проверки перед использованием URI.

- Конструктор TlsCertificate: javadoc описывает контракт безопасности —
  вызов обязан обрабатывать RuntimeException как «невалидный
  сертификат».

- TlsClientConfig.withAlpnProtocols: javadoc уточнён (null → без ALPN).

- Настройки TLS (cipher suite, сертификаты, CA) и транспорт (сетевой
  канал) теперь разделены. Раньше конфиг содержал транспорт — на каждое
  новое соединение приходилось создавать новый конфиг. Теперь конфиг —
  набор настроек, его можно создать один раз и переиспользовать, а
  транспорт подставлять при создании сессии:
  `TlsSession.createServer(config, transport)`.

- TlsClientConfig и TlsServerConfig больше не хранят транспорт — только
  настройки TLS.

- TlsSession.close() больше не закрывает сетевой канал — только
  отправляет close\_notify и зачищает ключи. Транспорт нужно закрывать
  отдельно (например, try-with-resources).

- PskStore (хранилище PSK-тикетов для session resumption) теперь
  интерфейс, а не класс. Старая реализация переименована в
  InMemoryPskStore — по названию понятно, что это in-memory хранилище,
  не persistent.

- Метод `add(...)` переименован в `onTicketReceived(PskEntry)` — теперь
  ясно, что это callback: вызывается стеком при получении тикета, не
  предназначен для прямого вызова. Метод `getAnyEntry()` переименован в
  `getForResumption()` — ищет любой валидный тикет для попытки
  resumption.

- Если своя реализация PskStore бросает исключение при сохранении тикета
  (onTicketReceived) — текущее соединение не рвётся, handshake
  продолжается.

- Метод для OCSP-стаплинга на сервере переименован: `withOcspResponse` →
  `withOcspStaplingResponse`. Раньше было непонятно, зачем серверу
  «OCSP-ответ» и как это связано с клиентским `withRequireOcspStapling`.
  Теперь оба метода говорят на одном языке: клиент требует механизм
  stapling, сервер поставляет для него данные.

- Метод для дешифрования TLS-записи через ByteBuffer теперь возвращает
  результат, а не бросает исключение, если данных пока не хватает или
  выходной буфер мал. Это штатные ситуации — например, пакет ещё не
  приехал по сети или буфер оказался меньше расшифрованных данных.
  Статус ответа (OK / нужно ещё данных / увеличь буфер) позволяет
  вызывающему коду реагировать без перехвата исключений.

- Упрощён API для клиентского сертификата в mTLS: раньше было два метода
  — `withClientCertificate` (один сертификат) и
  `withClientCertificateChain` (цепочка). Они писали в разные поля, и
  геттер сам решал, что отдавать. Теперь остался один метод
  `withClientCertificateChain`, который принимает один или несколько
  сертификатов через запятую — без путаницы и без скрытой логики в
  геттере.

### Удалено

- getSafeAiaUris(String…) — фильтрация URI только по схеме не защищает
  от SSRF; ответственность за безопасный HTTP-запрос передана
  вызывающему коду.

- Устаревшие конструкторы TlsClientConfig(TlsTransport, TlsCiphersuite)
  и TlsServerConfig(TlsTransport, …) — транспорт больше не часть
  конфига.

- Устаревшие перегрузки TlsSession.createServer(TlsServerConfig) и
  createClient(TlsClientConfig) — транспорт передаётся отдельным
  аргументом.

- Старый вложенный класс PskStore.PskEntry — теперь это отдельный класс
  PskEntry.

- Старый класс PskStore (он же был и классом, и реализацией) — заменён
  на интерфейс PskStore + реализацию InMemoryPskStore.

- Убран публичный метод `getContext()`, который отдавал внутреннее
  состояние handshake (секреты, ключи, транскрипт) наружу. Любой
  пользователь библиотеки мог через него получить доступ к черновику
  handshake — хотя на практике этим никто не пользовался. Метод был
  нужен для будущего JSSE-модуля, но для него достаточно других, более
  узких методов.

### Исправлено

- ALPN (RFC 7301) через TlsClientConfig: createClient() теперь передаёт
  список протоколов из конфига в TlsSession. Ранее работало только через
  прямой вызов session.setAlpnProtocols().

- mTLS: правильные алерты при отсутствии сертификата клиента. Раньше
  сервер отвечал «ошибка декодирования» (decode\_error, 50) — непонятно,
  что сломалось. Теперь сервер отвечает «требуется сертификат»
  (certificate\_required, 116) — сразу ясно, что клиент не прислал
  сертификат и нужно проверить настройки mTLS. Исправлены три сценария:
  клиент не прислал Certificate вообще, клиент прислал пустой
  Certificate, сервер прислал пустой Certificate.

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

### Модуль crypto-gost-pkix

- **CAdES-X Long Type 1** — построение и верификация долгосрочной
  подписи по RFC 5126 + ETSI TS 101 733. **Breaking:**
  `CAdESSignerResult` расширен с 6 до 9 параметров — код, напрямую
  создающий record или деструктурирующий его через pattern-matching,
  потребует обновления. Было: только CAdES-BES, T, C без проверки отзыва
  (crlHash deferred). Стало: проверка статуса отзыва каждого сертификата
  цепочки через встроенные certificate-values (SEQUENCE OF Certificate)
  и revocation-values (SEQUENCE { \[0\] CRL, \[1\] OCSP }) в
  unsignedAttrs. Методы embedXLongType1 и verifyCAdESXLong в
  CAdESExtender, content-time-stamp (ES-C) верификация в
  verifyCAdESXLong, +3 OID в GostOids (.20, .23, .24), +новый класс
  CAdESXLongData (кодеки CertificateValues/RevocationValues).

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
