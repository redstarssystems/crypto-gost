# PKIX-инфраструктура с ГОСТ-криптографией — crypto-gost-pkix

Модуль `crypto-gost-pkix` содержит ГОСТ-реестр OID, CMS, CAdES, TSP,
X.509-сертификаты и PKCS#12:

- **GostOids** — единый реестр объектных идентификаторов
  (ГОСТ-алгоритмы, PKCS#7/9/12, CAdES, TSP, OCSP, сертификатные
  расширения).

- **CMS SignedData (RFC 5652 §5 + RFC 4490)** — построение и верификация
  подписи с signed- и unsigned-атрибутами.

- **CAdES-BES/T (ETSI EN 319 122)** — долговременная электронная
  подпись: `signingCertificateV2`, метки времени от TSA.

- **TSP (RFC 3161)** — клиент и сервер службы штампов времени:
  `TimeStampReq`, `TimeStampResp`, транспорт HTTP, разбор запросов
  (`TspRequest`), построение ответов (`TspResponseBuilder`).

- **CMS EnvelopedData (RFC 5652 §6)** — ГОСТ-шифрование через связку
  VKO + KExp15 + Кузнечик CTR-ACPKM.

- **CMS SignedAndEnvelopedData** — совмещённая подпись и шифрование:
  sign-then-encrypt / encrypt-then-sign.

- **GostCertificate** — парсинг и верификация X.509-сертификатов (ГОСТ Р
  34.10-2012): подпись, срок, расширения (KeyUsage, EKU,
  BasicConstraints, SAN, CDP, AIA), hostname verification.

- **ChainValidator** — валидация цепочки сертификатов: подписи,
  DN-связность, KU/EKU, BasicConstraints, pathLen.

- **OCSP/CRL** — верификация OCSP-ответов (RFC 6960) и CRL (RFC 5280
  §6.3), разбор OCSP (`GostOcspResponse`, `SingleOcspResponse`),
  встроенный DER-парсер (`GostDerParser`), хеширование идентификатора
  сертификата (`CertIdHasher`).

- **X.509-строители:** `GostCertificateBuilder` — сборка сертификатов
  (TBS + подпись, расширения SAN/KeyUsage/EKU/CDP/AIA); `GostCrlBuilder`
  — построение CRL (RFC 5280); `GostCsrBuilder` — построение CSR (RFC
  2986 §4.1); `GostCsrParser` — разбор и верификация CSR
  (proof-of-possession, DN, SPKI, extensionRequest);
  `GostOcspResponseBuilder` — OCSP-ответы с делегированными
  сертификатами; `TspResponseBuilder` — TSP-ответы (TimeStampResp),
  включая rejection и grantedWithMods.

- **`GostDnParser.encodeDn()`** — сборка DER Distinguished Name по
  атрибутам (CN, O, OU, L, ST, C).

- **PKCS#12 (RFC 7292)** — загрузка (`GostPkcs12Loader`/`Pkcs12Loader`),
  построение (`GostPkcs12Builder`), парсинг (`GostPkcs12Parser`)
  PFX-контейнеров с нативной поддержкой ГОСТ PBE (PBKDF2-HMAC-Streebog +
  Кузнечик CTR-ACPKM).

- **DER-кодеки** — базовые CMS-структуры (ContentInfo,
  AlgorithmIdentifier, IssuerAndSerialNumber, Attribute).
  Вспомогательные классы расширяют `DerCodec` (core) поддержкой BER
  indefinite-length.

\+ Все криптографические операции выполняются модулем
`crypto-gost-core`. Модуль `crypto-gost-pkix` не имеет внешних
зависимостей, кроме core.

## Быстрый старт

Создаём ключевую пару ГОСТ Р 34.10-2012 (кривая tc26a256) и
самоподписанный сертификат.

    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.pkix.cert.GostCertificateBuilder;
    import org.rssys.gost.pkix.cert.GostDnParser;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.api.KeyGenerator;

    ECParameters params = ECParameters.tc26a256();
    var kp = KeyGenerator.generateKeyPair(params);
    byte[] subjectDn = GostDnParser.encodeDn("CN=Demo Cert,O=MyOrg,C=RU");
    GostCertificate cert = GostCertificateBuilder.create(params, subjectDn)
            .publicKey(kp.getPublic())
            .notBefore("20260101120000Z")
            .notAfter("21060101120000Z")
            .sanDns("gost.example.com")
            .issuerDn(subjectDn)
            .assembleCert(kp.getPrivate());

    // Для самоподписанных сертификатов .issuerDn() опционален —
    // библиотека автоматически подставит subjectDn.
    // Сертификат — публичный документ, не содержит секретов.
    // PEM-представление можно свободно передавать по сети.
    String certPem = cert.toPem();

    // Двухшаговый вариант (TBS-сборка отдельно, для кросс-валидации):
    // byte[] tbs = GostCertificateBuilder.create(params, subjectDn)
    //         .publicKey(kp.getPublic())
    //         .notBefore("20260101120000Z").notAfter("21060101120000Z")
    //         .buildTbs();
    // GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

В production загружайте сертификат и ключ из PKCS#12 через
`GostPkcs12Loader` (см. раздел [???](#PKCS#12)).

## GostCertificate — загрузка и верификация X.509

Загружаем и проверяем сертификат, созданный в [Быстром
старте](#Быстрый старт). `GostCertificate` — минимальный парсер X.509
для ГОСТ Р 34.10-2012: извлекает открытый ключ, подпись, срок действия,
расширения, DN, SAN, AIA, CDP.

### Загрузка из PEM / DER

    import org.rssys.gost.pkix.cert.GostCertificate;

    // Из PEM (автоопределение формата)
    GostCertificate cert = GostCertificate.fromPemOrDer(certPemBytes);

    // Из DER
    GostCertificate cert = GostCertificate.fromDer(derBytes);

    // Чтение цепочки из PEM (несколько блоков подряд)
    List<GostCertificate> chain = GostCertificate.listFromPem(chainPemBytes);

### Проверка подписи и срока

    import org.rssys.gost.signature.PublicKeyParameters;

    PublicKeyParameters caPubKey = cert.getPublicKey();
    // Для самоподписанного — верифицируем собственным публичным ключом
    boolean signatureOk = cert.verifySignature(caPubKey);

    boolean expired = cert.isExpired();
    boolean validNow = cert.isValidAt(Instant.now());

    // Отдельно: notBefore / notAfter
    Instant notBefore = cert.getNotBefore();
    Instant notAfter  = cert.getNotAfter();

### Проверка атрибутов

    // Subject / Issuer Distinguished Name
    String subject = cert.getSubjectDn();   // "CN=Demo Cert, O=MyOrg, C=RU"
    String issuer  = cert.getIssuerDn();

    // Самоподписанный?
    boolean selfSigned = cert.isSelfSigned();

    // CA-атрибуты
    boolean isCA = cert.isCA();
    int pathLen = cert.getPathLen();

    // SERIAL NUMBER
    BigInteger serial = cert.getSerialNumberBigInt();

    // Algorithm identifier подписи
    String sigAlg = cert.getSignatureAlgorithmOid();

### Hostname verification — сверка SAN (Subject Alternative Name)

    // Сверка с DNS-именем из SAN
    boolean hostMatch = cert.verifyHostname("gost.example.com");

    // Сверка с IP-адресом из SAN
    boolean ipMatch = cert.verifyAddress("192.168.1.1");

### Экспорт

    String pem = cert.toPem();
    byte[] der = cert.getEncoded();

    // Экспорт цепочки в PEM
    String chainPem = GostCertificate.chainToPem(chain);

## PKCS#12 — хранение ключей и сертификатов

PKCS#12 (PFX) — контейнер, объединяющий закрытый ключ, сертификат и
цепочку CA в одном защищённом паролем файле. Библиотека поддерживает
нативную схему ГОСТ PBE: PBKDF2-HMAC-Streebog + Кузнечик CTR-ACPKM.

Закрытый ключ внутри PFX зашифрован на пароле (PBES2). Пароль —
единственный секрет; знающий пароль владеет ключом. PFX-файл можно
передавать по сети — без пароля он бесполезен.

### Построение PFX — `GostPkcs12Builder`

    import org.rssys.gost.pkix.cert.GostPkcs12Builder;
    import org.rssys.gost.pkix.GostOids;

    // PFX можно сохранить в файл и передать по сети.
    // Закрытый ключ внутри зашифрован — без пароля расшифровать невозможно.
    byte[] pfx = GostPkcs12Builder.create()
            .key(kp.getPrivate())
            .certificate(cert)
            .password("changeit".toCharArray())
            .friendlyName("my-server-cert")
            .build();

    // Опционально: настроить число итераций PBKDF2 (по умолчанию 2000)
    byte[] pfxCustom = GostPkcs12Builder.create()
            .key(kp.getPrivate())
            .certificate(cert)
            .password("changeit".toCharArray())
            .iterations(50_000)
            .friendlyName("my-server-cert")
            .build();

### Загрузка PFX — `GostPkcs12Loader`

    import org.rssys.gost.pkix.cert.GostPkcs12Loader;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import java.nio.file.Files;
    import java.nio.file.Path;
    import java.util.List;

    GostPkcs12Loader.Result result = GostPkcs12Loader.load(
            Files.readAllBytes(Path.of("keystore.pfx")),
            "changeit".toCharArray(), true);

    PrivateKeyParameters key = result.getPrivateKey();
    List<GostCertificate> chain = result.getCertificateChain();
    GostCertificate leaf = chain.get(0);

## CSR (PKCS#10) — запрос сертификата

`GostCsrBuilder` строит PKCS#10 CertificationRequest (RFC 2986 §4.1).
`GostCsrParser` разбирает и верифицирует CSR: извлечение DN, SPKI,
проверка proof-of-possession, расширения extensionRequest.

### Построение CSR

CSR содержит открытый ключ заявителя, DN и подпись
(proof-of-possession). Атрибуты пока не поддерживаются — запрос всегда с
пустым SET.

CSR не содержит закрытого ключа — его можно свободно передавать по сети.
Подпись (proof-of-possession) доказывает владение закрытым ключом, не
раскрывая его.

    import org.rssys.gost.pkix.cert.GostCsrBuilder;

    ECParameters params = ECParameters.tc26a256();
    var kp = KeyGenerator.generateKeyPair(params);

    byte[] csrDer = GostCsrBuilder.buildCsr(
            kp.getPrivate(), kp.getPublic(),
            "CN=myserver.example.com,O=MyOrg,C=RU");

### Разбор и верификация CSR

    import org.rssys.gost.pkix.cert.GostCsrParser;

    // Из DER или PEM
    GostCsrParser csr = GostCsrParser.fromPemOrDer(csrBytes);

    // DN
    String dn = csr.getSubjectDn();               // "CN=myserver.example.com, O=MyOrg, C=RU"
    String[] cn = csr.getSubjectDnField("2.5.4.3"); // ["myserver.example.com"]

    // Публичный ключ и алгоритм
    PublicKeyParameters pubKey = csr.getPublicKey();
    String sigAlg = csr.getSignatureAlgorithmOid();

    // Proof-of-possession
    if (csr.verifySelf()) {
        // CSR подписан ключом из SPKI — запрос валиден
    }

    // Расширения из extensionRequest (если есть)
    if (csr.hasExtensions()) {
        var ext = csr.getExtensions();
        String[] san = ext.sanDnsNames;  // запрошенные SAN
    }

    // PEM-сериализация
    String pem = csr.toPem();  // ----BEGIN CERTIFICATE REQUEST-----

## Цепочки сертификатов — ChainValidator

Валидация цепочки доверия по RFC 5280: подписи, DN-связность, CA-флаги,
pathLen, сроки действия. Не содержит TLS-специфики — все ошибки через
`PkixException`.

    import org.rssys.gost.pkix.cert.ChainValidator;
    import org.rssys.gost.signature.PublicKeyParameters;
    import java.util.List;

    // Цепочка leaf-first: конечный сертификат → промежуточный CA
    // В production цепочка загружается из PKCS#12 или собирается из PEM
    List<GostCertificate> chain = List.of(leafCert, intermediateCaCert);

    // Доверенный публичный ключ корневого CA
    PublicKeyParameters rootKey = rootCaCert.getPublicKey();
    List<PublicKeyParameters> trustedKeys = List.of(rootKey);

    // Валидация: PkixException если цепочка невалидна
    ChainValidator.validateChain(chain, trustedKeys);

Возможные причины ошибки: `EXPIRED`, `SIGNATURE_INVALID`,
`NOT_YET_VALID`, `DN_MISMATCH`, `NOT_CA`, `PATH_LEN_EXCEEDED`.

## CRL — списки отзыва сертификатов

Построение и проверка CRL (Certificate Revocation List, RFC 5280 §5).

CRL — публичный документ, распространяемый через CDP (CRL Distribution
Point). Для проверки нужен только открытый ключ CA.

### Построение CRL — `GostCrlBuilder`

    import org.rssys.gost.pkix.cert.GostCrlBuilder;
    import org.rssys.gost.pkix.cert.RevokedEntry;
    import org.rssys.gost.pkix.cert.ReasonCode;
    import org.rssys.gost.pkix.cert.GostDnParser;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;

    byte[] issuerDn = GostDnParser.encodeDn("CN=My CA,O=MyOrg,C=RU");
    RevokedEntry entry = new RevokedEntry(
            cert.getSerialNumberBigInt().toByteArray(),
            "260701120000Z",
            ReasonCode.KEY_COMPROMISE,
            null,  // invalidityDate
            null   // certificateIssuer (для indirect CRL)
    );

    // Строим CRL с одним отозванным сертификатом
    byte[] crlDer = GostCrlBuilder.create(caPrivateKey, issuerDn)
            .withCrlNumber(1)          // монотонный номер CRL (RFC 5280 §5.2.3)
            .nextUpdate("270601120000Z")
            .addRevoked(entry)
            .build();

### Проверка CRL — `CrlVerifier`

    import org.rssys.gost.pkix.cert.CrlVerifier;
    import java.time.Instant;

    // PkixException если сертификат отозван или CRL невалиден
    CrlVerifier.verify(crlDer,
            cert.getSerialNumberBigInt().toByteArray(),
            caPublicKey);

    // Проверить дату следующего обновления CRL
    Instant nextUpdate = CrlVerifier.extractNextUpdate(crlDer);

### Delta CRL — частичные списки отзыва (RFC 5280 §5.2.4)

Delta CRL содержит только изменения относительно базового CRL. При
проверке верификатор склеивает оба списка: запись в delta перекрывает
запись в base. Если delta удаляет сертификат (reasonCode =
`REMOVE_FROM_CRL`) — он больше не считается отозванным.

    import org.rssys.gost.pkix.cert.CrlVerifier;

    // 1. Базовый CRL (полный список отозванных)
    byte[] baseCrl = GostCrlBuilder.create(caPrivateKey, issuerDn)
            .withCrlNumber(1)
            .nextUpdate("270601120000Z")
            .addRevoked(entry)
            .build();

    // 2. Delta CRL — только изменения. Ссылается на cRLNumber базового.
    //    deltaCRLIndicator — CRITICAL-расширение, требуемое по RFC 5280.
    byte[] deltaCrl = GostCrlBuilder.create(caPrivateKey, issuerDn)
            .withCrlNumber(2)
            .withDeltaCrlIndicator(1)   // ссылается на base cRLNumber = 1
            .addRevoked(removedSerial, "260801120000Z",
                    ReasonCode.REMOVE_FROM_CRL)  // удалить из base
            .build();

    // 3. Проверка через base + delta
    //    crlNumber base и deltaCRLIndicator delta должны совпадать.
    //    thisUpdate delta должен быть >= thisUpdate base.
    CrlVerifier.verify(baseCrl, deltaCrl,
            cert.getSerialNumberBigInt().toByteArray(), caPublicKey);

    // 4. Base CRL может указывать URI для получения delta CRL
    //    через расширение freshestCRL (структура = CDP, RFC 5280 §5.2.6)
    byte[] baseWithFreshest = GostCrlBuilder.create(caPrivateKey, issuerDn)
            .withCrlNumber(3)
            .withFreshestCrl("http://ca.example/delta.crl")
            .nextUpdate("270601120000Z")
            .build();

Delta CRL нельзя верифицировать изолированно. При попытке
`crl.verify(caKey)` на delta CRL верификатор бросает `PkixException` с
сообщением «delta CRL not supported», требуя использования
`CrlVerifier.verify(base, delta, ...)`.

### Разбор CRL — `GostCrl`

`GostCrl` — парсинг CRL отдельно от верификации. Позволяет прочитать
структуру (issuer, даты, отозванные сертификаты) без проверки подписи.
Полная верификация — через `CrlVerifier.verify()` или
`crl.verify(caKey)`.

    import org.rssys.gost.pkix.cert.GostCrl;
    import org.rssys.gost.pkix.cert.RevokedEntry;
    import java.time.Instant;

    GostCrl crl = GostCrl.fromDer(crlDer);

    // Метаданные CRL
    String issuer = crl.getIssuerDn();           // "CN=My CA, O=MyOrg, C=RU"
    Instant thisUpdate = crl.getThisUpdate();
    Instant nextUpdate = crl.getNextUpdate();    // может быть null

    // Верификация подписи + парсинг revoked-списка (порядок обязателен)
    crl.verify(caPublicKey);                     // бросит PkixException при невалидной подписи

    // Проверка отзыва конкретного сертификата
    if (crl.isRevoked(cert.getSerialNumber())) {
        System.err.println("Сертификат отозван");
    }

    // Список всех отозванных — с причиной (если есть)
    for (RevokedEntry e : crl.getRevokedCertificates()) {
        System.out.println("Отозван: " + e.revocationDate() + " причина: " + e.reason());
    }

    // CRL-расширения (доступны после verify)
    BigInteger crlNum = crl.getCrlNumber();        // cRLNumber из расширения
    ReasonCode code = crl.getReason(serial);        // причина отзыва конкретного сертификата
    boolean isDelta = crl.isDelta();                // true если CRL — delta

    // Экспорт в PEM
    String crlPem = crl.toPem();

## OCSP — онлайн-проверка статуса сертификата

Online Certificate Status Protocol (RFC 6960) — альтернатива CRL для
проверки отзыва в реальном времени.

OCSP-ответ — публичный документ, подписанный CA. Для проверки нужен
только открытый ключ CA. Допустима передача по незащищённому каналу.

### Построение OCSP-ответа — `GostOcspResponseBuilder`

    import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
    import org.rssys.gost.pkix.cert.GostDnParser;

    byte[] caSubjectDer = GostDnParser.encodeDn("CN=My CA,O=MyOrg,C=RU");
    byte[] ocspResp = GostOcspResponseBuilder.create(cert.getSerialNumberBigInt().toByteArray())
            .signer(caPrivateKey, caPublicKey)
            .issuerDn(caSubjectDer)
            .build();

### Проверка OCSP-ответа — `OcspVerifier`

    import org.rssys.gost.pkix.cert.OcspVerifier;

    // PkixException если сертификат отозван или ответ невалиден
    OcspVerifier.verify(ocspResp,
            cert.getSerialNumberBigInt().toByteArray(),
            caPublicKey);

### Разбор OCSP-ответа — `GostOcspResponse`

`GostOcspResponse` — доменный объект для разбора OCSP-ответа без ключа
CA. Позволяет извлечь статус, даты, серийные номера и делегированные
сертификаты.

    import org.rssys.gost.pkix.cert.GostOcspResponse;
    import org.rssys.gost.pkix.cert.SingleOcspResponse;
    import java.time.Instant;
    import java.util.List;

    GostOcspResponse ocsp = GostOcspResponse.fromDer(ocspResp);

    // Статус ответа (0 = успех)
    boolean ok = ocsp.isSuccessful();

    // Все ответы по сертификатам
    for (SingleOcspResponse sr : ocsp.getResponses()) {
        if (sr.isGood()) {
            Instant thisUpdate = sr.thisUpdate();
            Instant nextUpdate = sr.nextUpdate();  // может быть null
        }
    }

    // Делегированные сертификаты responder'а (RFC 6960 §4.2.2.2)
    List<byte[]> delegated = ocsp.getDelegatedCertificates();

    // Проверка подписи
    ocsp.verify(caPublicKey);
    boolean verified = ocsp.isSignatureVerified();

### Построение OCSP-запроса — `GostOcspRequestBuilder`

`GostOcspRequestBuilder` строит OCSPRequest (RFC 6960 §4.1) с
автоматическим nonce (RFC 8954) и опциональной подписью запроса (RFC
9215).

    import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
    import org.rssys.gost.pkix.GostOids;

    // Базовый запрос: один сертификат
    GostOcspRequestBuilder builder = GostOcspRequestBuilder.create()
            .targetCert(cert.getEncoded())
            .issuerCert(caCert.getEncoded());

    byte[] requestDer = builder.build();
    byte[] nonce = builder.getNonce();       // автоматически сгенерирован

    // Multi-cert: запрос статуса нескольких сертификатов
    byte[] multiDer = GostOcspRequestBuilder.create()
            .targetCert(cert1.getEncoded()).issuerCert(caCert.getEncoded())
            .addRequest(cert2.getEncoded(), caCert.getEncoded())
            .hashLen(GostOids.STREEBOG_512_HASH_LEN)
            .build();

    // С подписью запроса (RFC 9215 §4.2)
    byte[] signedDer = GostOcspRequestBuilder.create()
            .targetCert(cert.getEncoded())
            .issuerCert(caCert.getEncoded())
            .signKey(requestorPriv)
            .params(ecParams)
            .build();

### Разбор OCSP-запроса — `GostOcspRequest`

`GostOcspRequest` разбирает полученный OCSPRequest в структурированный
объект.

    import org.rssys.gost.pkix.cert.GostOcspRequest;
    import org.rssys.gost.pkix.cert.CertId;

    GostOcspRequest request = GostOcspRequest.fromDer(requestDer);

    // Список сертификатов из запроса
    for (CertId cid : request.getCertIds()) {
        byte[] sn = cid.serialNumber();           // серийный номер
        byte[] nameHash = cid.issuerNameHash();   // хэш имени издателя
        byte[] keyHash = cid.issuerKeyHash();     // хэш ключа издателя
    }

    // Nonce (RFC 8954)
    byte[] nonce = request.getNonce();

    // Проверка подписи запроса (RFC 9215)
    if (request.isSigned()) {
        request.verifySignature(requestorPubKey);
        boolean ok = request.isSignatureVerified();
    }

## CMS SignedData — подпись и верификация

`CmsSignedDataBuilder` формирует SignedData DER-байты по RFC 5652 §5 с
ГОСТ-подписью. Без параметров подпись инкапсулированная — данные
включаются внутрь CMS-сообщения.

Подпись не раскрывает закрытый ключ. Результат `build()` — DER-байты,
которые можно свободно передавать по сети или хранить в файле.
Верификатору нужен только открытый ключ (из сертификата подписанта).

### Подпись с инкапсулированными данными

    import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
    import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;

    byte[] data = "Документ для подписи".getBytes(StandardCharsets.UTF_8);

    // Подпись
    byte[] signedData = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(privateKey, cert)
            .build();

    // Верификация
    VerifiedSignedData result =
            CmsSignedDataVerifier.verifyAny(signedData, cert);

    byte[] extracted = result.data(); // == data
    GostCertificate signer = result.signerCertificate();

`verify()` возвращает первого валидного подписанта (OR-семантика). Если
нужна гарантия, что **все** подписанты прошли проверку, используйте
`verifyAll()` — он вернёт `MultiSignerVerifiedData` со списком всех
подписантов, либо бросит `PkixException` с указанием, какой именно
подписант не прошёл верификацию.

### Detached подпись

Данные не включаются в CMS — подпись и документ хранятся отдельно.
Верификатор не извлекает данные — приложение проверяет их
самостоятельно. Подпись можно передавать открыто, данные — по
необходимости.

    byte[] data = "Внешний документ".getBytes(StandardCharsets.UTF_8);

    // detached: данные не упаковываются в CMS
    byte[] signedData = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(privateKey, cert)
            .detached(true)
            .build();

    // Верификация
    VerifiedSignedData result =
            CmsSignedDataVerifier.verifyAny(signedData, cert);

    assert result.data() == null; // detached — данных в CMS нет

### Дополнительные сертификаты в цепочке

Промежуточные CA-сертификаты добавляются через `addCertificate()`.
Верификатор найдёт сертификат подписанта среди встроенных.

    byte[] signedData = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(leafKey, leafCert)
            .addCertificate(intermediateCaCert)   // промежуточный CA
            .addCertificate(rootCaCert)           // корневой CA (опционально)
            .build();

    VerifiedSignedData result =
            CmsSignedDataVerifier.verifyAny(signedData, rootCaCert);

### Пользовательские signed-атрибуты

К стандартным атрибутам (contentType, messageDigest) можно добавить свои
— например, signingTime.

    import org.rssys.gost.pkix.GostOids;
    import org.rssys.gost.util.DerCodec;

    byte[] signedData = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(privateKey, cert)
            .addSignedAttribute(GostOids.ATTR_SIGNING_TIME,
                    DerCodec.encodeTime("260101120000Z"))
            .build();

## CAdES — долговременная электронная подпись

### Что такое CAdES и зачем нужен TSP

**CAdES** (CMS Advanced Electronic Signatures, ETSI EN 319 122) —
стандарт долговременной электронной подписи. Расширяет CMS SignedData
стандартными signed- и unsigned-атрибутами, позволяющими проверять
подпись спустя годы после истечения сертификата.

**Проблема.** ГОСТ-сертификат выпускается на 12–15 месяцев. Если подпись
проверяют после истечения срока сертификата, формально она «повисает» —
невозможно установить момент подписания. ФЗ-63 ст.11 требует достоверно
установленного момента создания подписи.

**Решение.** CAdES-T (уровень T — Timestamp) добавляет метку времени от
доверенного центра TSA (Time-Stamp Authority по RFC 3161) в
unsigned-атрибуты SignerInfo. Метка криптографически доказывает, что
подпись существовала на момент `genTime` — сертификат подписанта
проверяется относительно этого момента, а не текущего.

**Уровни CAdES:** - **CAdES-BES** — базовая подпись: SignedData +
`signingCertificateV2` (связка подписи с сертификатом). - **CAdES-T** —
BES + метка времени `signature-time-stamp` в unsigned-атрибутах.

### CAdES-BES — базовая электронная подпись

CAdES-BES добавляет signed-атрибут `signingCertificateV2` (ESS, RFC 5035
§3), который содержит хэш DER-кодирования сертификата подписанта и его
IssuerSerial. Это надёжно связывает подпись с конкретным сертификатом.

Создать CAdES-BES — вызвать `.withCAdES()` на построителе SignedData.
Атрибут `signingCertificateV2` добавляется автоматически, для каждого
подписанта. Подпись остаётся инкапсулированной (данные внутри) или
detached — как обычно. Результат `.build()` — обычный CMS SignedData
DER, без метки времени. Его можно свободно передавать по сети.

Создание CAdES-BES

    import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
    import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
    import org.rssys.gost.pkix.cms.VerifiedSignedData;

    byte[] data = "Документ для долговременной подписи".getBytes(StandardCharsets.UTF_8);

    // Создание CAdES-BES — signingCertificateV2 добавляется автоматически
    byte[] cadesBes = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(privateKey, cert)
            .withCAdES()                        // 
            .build();

    // Верификация CAdES-BES — стандартная CMS-проверка
    VerifiedSignedData result =
            CmsSignedDataVerifier.verifyAny(cadesBes, cert);

    byte[] originalData = result.data();
    GostCertificate signer = result.signerCertificate();

- Автоматически добавляет `signingCertificateV2` для каждого подписанта
  в signedAttrs. Хэш вычисляется от DER сертификата: Стрибог-256 для
  256-битных ключей, Стрибог-512 для 512-битных.

Для полной верификации CAdES-BES (включая `signingCertificateV2`)
используйте `CAdESExtender.verifyCAdESBES()`. Для CAdES-T с метками —
`CAdESExtender.verifyCAdEST()`. Эти методы проверяют все подписанты
(AND-семантика) и `signingCertificateV2` (fail-closed).

### TSP-клиент — запрос меток времени

Протокол TSP (Time-Stamp Protocol, RFC 3161) — стандарт IETF для
получения криптографических меток времени от службы TSA.

**Принцип работы:** . Приложение вычисляет хэш данных (signature
подписанта) и отправляет `TimeStampReq`. . TSA подписывает
`TimeStampToken` (CMS SignedData с `TSTInfo` внутри) и возвращает
`TimeStampResp`. . Приложение проверяет подпись TSA и совпадение хэша —
метка действительна.

TSP-ответ — публичный документ. Его можно проверить с открытым ключом
TSA. Передача по незащищённому каналу допустима.

#### Построение TimeStampReq

    import org.rssys.gost.pkix.tsp.TspRequestBuilder;
    import org.rssys.gost.pkix.GostOids;
    import org.rssys.gost.api.Digest;

    byte[] data = "данные для метки".getBytes(StandardCharsets.UTF_8);
    byte[] hash = Digest.digest256(data);       // Стрибог-256

    // Строим запрос: обязательно messageImprint, + nonce (автоматически), + запрос сертификата TSA
    byte[] tspReq = TspRequestBuilder.create()
            .messageImprint(hash, GostOids.DIGEST_256) // 
            .certReq(true)                             // 
            .build();                                  // 

- `messageImprint` — хэш данных, для которых запрашивается штамп. Для
  CAdES-T это хэш подписи (см. раздел CAdES-T).

- `certReq(true)` — TSA пришлёт сертификат в ответе.

- `build()` автоматически генерирует `nonce` (8 байт, `CryptoRandom`)
  если не задан явно.

#### Отправка запроса и разбор ответа

    import org.rssys.gost.pkix.tsp.JdkHttpTspTransport;
    import org.rssys.gost.pkix.tsp.TspResponse;
    import org.rssys.gost.pkix.tsp.TspTransport;

    // Дефолтный HTTP-транспорт (JDK 11+, совместим с virtual threads)
    TspTransport transport = new JdkHttpTspTransport();

    // Отправляем запрос на TSA
    byte[] tspRespDer = transport.send(tspReq, "http://tsa.example.com/tsa");

    // Разбираем ответ
    TspResponse tspResponse = TspResponse.parse(tspRespDer);

    // Проверяем статус
    if (tspResponse.status() != GostOids.PKI_STATUS_GRANTED) {
        throw new SecurityException("TSA rejected request: " + tspResponse.statusString());
    }

    // Верифицируем: хэш, алгоритм, время, nonce, подпись TSA, цепочку
    tspResponse.verify(hash, GostOids.DIGEST_256, null, tsaTrustedCert);

    // Извлекаем информацию о штампе
    System.out.println("GenTime: " + tspResponse.tstInfo().genTime());        // YYYYMMDDHHMMSSZ
    System.out.println("Serial: " + tspResponse.tstInfo().serialNumber());   // BigInteger

`TspResponse.verify()` проверяет: . `messageImprint` — совпадает ли хэш
в ответе с ожидаемым (constant-time через `MessageDigest.isEqual`). .
`genTime` — не в будущем (с допуском ±5 минут). . nonce — если передан в
запросе, должен совпадать. . **Подпись TSA** на TimeStampToken (CMS
SignedData). . **Цепочку сертификатов TSA** через `ChainValidator`.

Для кастомного HTTP-клиента (прокси, mTLS) реализуйте интерфейс
`TspTransport` самостоятельно и передайте в методы `CAdESExtender` или
ваш код.

#### Кастомный HTTP-транспорт

Дефолтный `JdkHttpTspTransport` принимает URL и выполняет HTTP POST.
Если требуется прокси, аутентификация mTLS или другой HTTP-клиент —
реализуйте интерфейс `TspTransport`:

    import org.rssys.gost.pkix.tsp.TspTransport;

    TspTransport myTransport = (requestDer, url) -> {
        // ваш HTTP POST на url, Content-Type: application/timestamp-query
        // вернуть тело ответа как byte[]
        return responseBody;
    };

#### Построение TSP-ответа — `TspResponseBuilder`

Генерация штампов на стороне TSA: разбор входящего запроса, проверка
алгоритма, построение TimeStampResp, отклонение с сообщением.

    import org.rssys.gost.pkix.tsp.TspRequest;
    import org.rssys.gost.pkix.tsp.TspResponseBuilder;
    import org.rssys.gost.pkix.GostOids;
    import java.math.BigInteger;

    byte[] requestDer = ...;  // тело HTTP POST от клиента

    // 1. Разбираем запрос
    TspRequest request = TspRequest.parse(requestDer);

    // 2. Проверяем алгоритм хэширования
    if (!GostOids.DIGEST_256.equals(request.messageImprintAlgOid())) {
        byte[] rejection = TspResponseBuilder.buildRejected(
                "Unsupported hash algorithm");
        // ... отправляем rejection обратно ...
        return;
    }

    // 3. Строим granted-ответ
    byte[] responseDer = TspResponseBuilder.create(request)
            .signer(tsaPrivateKey, tsaCertificate)
            .policyOid("1.3.6.1.4.1.4146.1.2.1")           // 
            .serialNumber(BigInteger.valueOf(counter.getAndIncrement())) // 
            .accuracy(1, 500)                                // 
            .buildGranted();

    // 4. Отправляем DER-байты клиенту
    //    Content-Type: application/timestamp-reply

- `policyOid` — OID политики TSA, идентифицирует службу. Обязателен.

- `serialNumber` — серийный номер штампа, обязан быть глобально
  уникальным (RFC 3161 §2.4.2). Вызывающий обеспечивает уникальность сам
  (AtomicLong, БД). Обязателен.

- `accuracy` — точность часов TSA: 1 секунда ± 500 миллисекунд.
  Опционально.

Алгоритм хэширования определяется автоматически по размеру ключа TSA:
256-битный → Streebog-256, 512-битный → Streebog-512.

#### Отклонение, grantedWithMods и расширенные атрибуты

    // Отклонение — без подписи, только PKIStatusInfo
    byte[] rejectionDer = TspResponseBuilder.buildRejected("Unknown policy OID");

    // Без сообщения, с кодом причины (RFC 4210 §D.2)
    byte[] noMsgRej = TspResponseBuilder.buildRejected(GostOids.PKI_FAIL_BAD_ALG);

    // С сообщением и кодом причины
    byte[] rej = TspResponseBuilder.buildRejected("System error",
            GostOids.PKI_FAIL_SYSTEM_FAILURE);

    // grantedWithMods (PKIStatus=1) — статус «с модификациями»
    byte[] withModsDer = TspResponseBuilder.create(request)
            .signer(tsaPrivateKey, tsaCertificate)
            .policyOid("1.3.6.1.4.1.4146.1.2.1")
            .serialNumber(BigInteger.valueOf(counter.getAndIncrement()))
            .buildGrantedWithMods();

    // CAdES-атрибуты и цепочка сертификатов
    byte[] cadesDer = TspResponseBuilder.create(request)
            .signer(tsaPrivateKey, tsaCertificate)
            .policyOid("1.3.6.1.4.1.4146.1.2.1")
            .serialNumber(BigInteger.valueOf(counter.getAndIncrement()))
            .withCAdES()                                    // 
            .addChainCert(intermediateCaCert)                // 
            .ordering(true)                                  // 
            .buildGranted();

- `withCAdES()` — добавляет `signingCertificateV2` в TimeStampToken. По
  умолчанию атрибуты не добавляются.

- `addChainCert()` — включает промежуточные сертификаты TSA в ответ.
  Сертификат подписанта включается автоматически.

- `ordering(true)` — флаг упорядоченности штампов (RFC 3161 §2.4.2). По
  умолчанию `false`.

### CAdES-T — подпись с меткой времени

CAdES-T — CAdES-BES с встроенной меткой времени `signature-time-stamp` в
unsigned-атрибутах. При верификации сертификат подписанта проверяется на
момент `genTime` метки, а не на текущую дату.

Метка добавляется **после** подписания документа — это отдельный шаг,
требующий доступ к TSA по сети.

#### Полный цикл: создание CAdES-T

`CAdESExtender.addTimestamp()` выполняет все шаги автоматически:
извлекает подпись из SignedData, отправляет TSP-запрос, встраивает
метку.

Подпись не содержит закрытых ключей. Результат — DER-байты CAdES-T,
которые можно свободно хранить или передавать по сети.

    import org.rssys.gost.pkix.cms.CAdESExtender;
    import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
    import org.rssys.gost.pkix.tsp.JdkHttpTspTransport;

    // Шаг 1. Создаём CAdES-BES
    byte[] cadesBes = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(privateKey, cert)
            .withCAdES()
            .build();

    // Шаг 2. Добавляем метку времени — один вызов
    TspTransport transport = new JdkHttpTspTransport();
    byte[] cadesT = CAdESExtender.addTimestamp(
            cadesBes,
            "http://tsa.example.com/tsa",
            transport,
            tsaTrustedCert);            // 

- `tsaTrustedCert` — доверенный корневой сертификат TSA (или
  промежуточный CA). Для верификации подписи TSA.

#### Несколько подписантов — каждому своя метка

Если документ подписывают несколько человек, `CAdESExtender` запрашивает
отдельную метку времени для каждого. При верификации проверяются все.

    // Два подписанта: директор и главбух
    byte[] cadesBes = CmsSignedDataBuilder.create()
            .data(contract)
            .addSigner(dirKey, dirCert)          // 
            .addSigner(chiefKey, chiefCert)      // 
            .withCAdES()
            .build();

    // Один вызов — метки для обоих
    byte[] cadesT = CAdESExtender.addTimestamp(
            cadesBes, "http://tsa.example.com/tsa",
            transport, tsaTrustedCert);

    // Оба подписанта проверены
    VerifiedCAdESData result = CAdESExtender.verifyCAdEST(cadesT, tsaTrustedCert);
    assert result.signers().size() == 2;         // директор + главбух

    for (CAdESSignerResult sr : result.signers()) {
        System.out.println("Подписант: " + sr.signerCertificate().getSubjectDn());
        System.out.println("Меток: " + sr.timestamps().size());
    }

- Директор — его ключ и сертификат.

- Главбух — его ключ и сертификат.

#### Верификация CAdES-T

`CAdESExtender.verifyCAdEST()` проверяет подпись целиком: подпись
подписанта, `signingCertificateV2`, метку времени, цепочки подписанта и
TSA, валидность сертификата подписанта на момент `genTime` метки.

    import org.rssys.gost.pkix.cms.CAdESExtender;
    import org.rssys.gost.pkix.cms.VerifiedCAdESData;

    // trustedCerts — общий массив: корневые сертификаты подписанта и TSA
    VerifiedCAdESData result =
            CAdESExtender.verifyCAdEST(cadesT, rootCaCert, tsaTrustedCert);

    byte[] originalData = result.data();              // 
    CAdESSignerResult firstSigner = result.signers().get(0);
    GostCertificate signer = firstSigner.signerCertificate();
    List<TstInfo> stamps = firstSigner.timestamps();  // 

    for (TstInfo t : stamps) {
        System.out.println("Метка времени: " + t.genTime());
        System.out.println("TSA политика: " + t.policyOid());
    }

- Для detached — `null`. Приложение проверяет данные самостоятельно.

- Список меток из unsigned-атрибутов. Каждая — проверена:
  `messageImprint` совпадает с хэшем подписи подписанта, подпись TSA
  валидна.

Если любая из проверок не проходит — `PkixException` (fail-closed).

#### Ручное встраивание метки (DER-операция, без сети)

Если TimeStampToken уже получен (например, из файла или базы данных),
встроить его можно без сетевых вызовов:

    byte[] cadesT = CAdESExtender.embedTimestamp(cadesBesDer, timeStampTokenDer);

Для нескольких подписантов с заранее полученными токенами —
`embedTimestamps()` (один токен на подписанта, в порядке чтения):

    byte[] cadesT = CAdESExtender.embedTimestamps(cadesBesDer, List.of(token1, token2));

## CMS EnvelopedData — шифрование

CmsEnvelopedDataBuilder — шифрует данные по RFC 5652 §6:

- Генерирует случайный CEK (Content Encryption Key, 32 байта) и IV (8
  байт).

- Шифрует данные на CEK через Кузнечик CTR-ACPKM.

- Для каждого получателя вычисляет KEK через VKO ГОСТ Р 34.10-2012,
  оборачивает CEK через KExp15 (RFC 9189 §8.2.1).

- CEK и IV затираются сразу после использования.

\+ Результат `build()` — DER-байты, содержащие зашифрованные данные и
обёрнутый CEK. Можно свободно передавать по сети: без закрытого ключа
получателя расшифровать невозможно. CEK не попадает в результат в
открытом виде.

`CmsEnvelopedDataDecryptor` расшифровывает: находит свой
RecipientEncryptedKey, вычисляет KEK через VKO, разворачивает CEK через
KImp15, расшифровывает данные.

`CmsKeyWrap` (пакет `org.rssys.gost.pkix.cms`) — stateless-абстракция
алгоритма обёртывания ключа: содержит только методы `wrap()` /
`unwrap()` и `algorithmOid()`. В DER-структуру EnvelopedData
встраивается только OID алгоритма — сам объект `CmsKeyWrap` не
передаётся. Отправитель и получатель независимо создают одинаковый
`CmsKeyWrap` (по умолчанию `Kexp15CmsKeyWrap`).

### Шифрование и расшифровка

    import org.rssys.gost.pkix.cms.*;

    byte[] data = "Конфиденциальный документ".getBytes(StandardCharsets.UTF_8);
    // Stateless-объект алгоритма — не содержит секретов, не передаётся.
    // В DER встраивается только OID ("1.2.643.7.1.1.7.2.1").
    CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();

    // Шифрование — передаём открытый ключ через сертификат получателя
    byte[] envelopedData = CmsEnvelopedDataBuilder.create()
            .data(data)
            .addRecipient(recipientCert)   // сертификат получателя
            .keyWrap(keyWrap)
            .build();

    // Расшифрование — получатель использует свой закрытый ключ.
    // keyWrap создаётся независимо, не извлекается из EnvelopedData.
    byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(
            envelopedData, recipientPrivateKey, recipientCert, keyWrap);

    assert Arrays.equals(data, decrypted);

### Несколько получателей

Один CEK оборачивается для каждого получателя независимо. Данные
шифруются один раз — все получатели расшифровывают их своим ключом.

    byte[] envelopedData = CmsEnvelopedDataBuilder.create()
            .data(data)
            .addRecipient(aliceCert)       // Алиса
            .addRecipient(bobCert)         // Боб
            .keyWrap(keyWrap)
            .build();

    // Алиса расшифровывает своим ключом
    byte[] aliceData = CmsEnvelopedDataDecryptor.decrypt(
            envelopedData, aliceKey, aliceCert, keyWrap);

    // Боб — своим
    byte[] bobData = CmsEnvelopedDataDecryptor.decrypt(
            envelopedData, bobKey, bobCert, keyWrap);

## CMS Sign+Encrypt — совмещённая подпись и шифрование

CmsSignedAndEnvelopedData — хелпер для вложения (nesting) одного CMS
ContentInfo

в другой по RFC 5652.

Два порядка вложенности:

- **sign-then-encrypt** — SignedData внутри EnvelopedData. Подпись
  скрыта от внешнего наблюдателя: чтобы узнать подписанта, нужно
  расшифровать.

- **encrypt-then-sign** — EnvelopedData внутри SignedData. Подпись видна
  снаружи: можно проверить авторство без расшифрования (аудируемость).

Обе операции — stateless. Ключевой материал не сохраняется в объекте,
хелпер содержит только static-методы.

### sign-then-encrypt: подпись, затем шифрование

    import org.rssys.gost.pkix.cms.CmsSignedAndEnvelopedData;

    byte[] data = "Конфиденциальный подписанный документ".getBytes();

    // Подписать и зашифровать для получателя
    byte[] combined = CmsSignedAndEnvelopedData.signThenEncrypt(
            data, signerKey, signerCert, recipientCert);

    // Получатель расшифровывает и проверяет подпись
    VerifiedSignedData result =
            CmsSignedAndEnvelopedData.decryptAndVerify(
                    combined, recipientKey, recipientCert, signerCert);

    byte[] original = result.data();
    GostCertificate signer = result.signerCertificate();

### encrypt-then-sign: шифрование, затем подпись

    byte[] data = "Аудируемый зашифрованный документ".getBytes();

    // Зашифровать для получателя и подписать
    byte[] combined = CmsSignedAndEnvelopedData.encryptThenSign(
            data, signerKey, signerCert, recipientCert);

    // Проверить подпись (без расшифрования) и расшифровать
    VerifiedSignedData result =
            CmsSignedAndEnvelopedData.verifyAndDecrypt(
                    combined, recipientKey, recipientCert, signerCert);

    assert Arrays.equals(data, result.data());

### Несколько получателей

Для sign-then-encrypt работает стандартный механизм EnvelopedData: один
CEK оборачивается для каждого получателя независимо.

    byte[] combined = CmsSignedAndEnvelopedData.signThenEncrypt(
            data, signerKey, signerCert,
            aliceCert,    // Алиса
            bobCert);     // Боб

    // Алиса расшифровывает
    VerifiedSignedData aliceResult =
            CmsSignedAndEnvelopedData.decryptAndVerify(
                    combined, aliceKey, aliceCert, signerCert);

    // Боб расшифровывает
    VerifiedSignedData bobResult =
            CmsSignedAndEnvelopedData.decryptAndVerify(
                    combined, bobKey, bobCert, signerCert);

## GostOids — реестр OID

Единый класс `org.rssys.gost.pkix.GostOids` регистрирует все OID
проекта.

    import org.rssys.gost.pkix.GostOids;

    // CMS
    String contentType = GostOids.CMS_SIGNED_DATA;   // 1.2.840.113549.1.7.2
    String enveloped    = GostOids.CMS_ENVELOPED_DATA; // 1.2.840.113549.1.7.3

    // Signed-атрибуты (PKCS#9)
    String attrType     = GostOids.ATTR_CONTENT_TYPE;   // 1.2.840.113549.1.9.3
    String attrDigest   = GostOids.ATTR_MESSAGE_DIGEST; // 1.2.840.113549.1.9.4
    String attrTime     = GostOids.ATTR_SIGNING_TIME;   // 1.2.840.113549.1.9.5

    // CAdES (ETSI EN 319 122)
    String tstInfo          = GostOids.TST_INFO;             // 1.2.840.113549.1.9.16.1.4
    String signingCertV2    = GostOids.SIGNING_CERTIFICATE_V2; // 1.2.840.113549.1.9.16.2.47
    String sigPolicyId       = GostOids.SIGNATURE_POLICY_ID;   // 1.2.840.113549.1.9.16.2.15
    String sigTimeStamp     = GostOids.SIGNATURE_TIME_STAMP;   // 1.2.840.113549.1.9.16.2.14

    // TSP (RFC 3161)
    String adTimeStamp  = GostOids.AD_TIME_STAMPING;    // 1.3.6.1.5.5.7.48.3
    int statusGranted   = GostOids.PKI_STATUS_GRANTED;  // 0
    int statusRejected  = GostOids.PKI_STATUS_REJECTED; // 2

    // Key wrap / agreement
    String vko       = GostOids.AGREEMENT_VKO_256;       // 1.2.643.7.1.1.6.1
    String wrapKexp15 = GostOids.WRAP_KUZNYECHIK_KEXP15; // 1.2.643.7.1.1.7.2.1

Доступны через javadoc: кривые ГОСТ, алгоритмы подписи и хэширования,
расширения X.509 (Basic Constraints, Key Usage, EKU, SAN), OCSP, TSP,
CAdES, PKCS#12.

## Вспомогательные классы

Классы, используемые совместно с основным API.

### Построение цепочки из неупорядоченного пула — `CertChainBuilder`

`CertChainBuilder` собирает цепочку leaf→root по совпадению
subject/issuer DN и проверяет подписи на каждом шаге. Используется в
`CmsSignedDataVerifier` для построения цепочки из сертификатов внутри
CMS.

    import org.rssys.gost.pkix.cms.CertChainBuilder;

    // pool — промежуточные сертификаты (из CMS или PEM)
    // trustedRoots — доверенные корневые сертификаты
    List<GostCertificate> chain = CertChainBuilder.buildChain(
            leafCert, intermediatePool, trustedRoots);

    // Результат leaf-first: [leaf, inter, root]
    GostCertificate root = chain.get(chain.size() - 1);

Возможные ошибки: `INCOMPLETE_CHAIN` (не найден issuer), `CHAIN_LOOP`
(зацикливание DN), `CHAIN_TOO_LONG` (превышена глубина),
`ROOT_NOT_TRUSTED`.

### Хеширование CertID для OCSP — `CertIdHasher`

Вычисляет `issuerNameHash` и `issuerKeyHash` для записей CertID в
OCSP-запросах и ответах (RFC 6960 §4.1.1).

    import org.rssys.gost.pkix.cert.CertIdHasher;
    import org.rssys.gost.pkix.GostOids;

    // Из DER сертификата издателя
    byte[] nameHash = CertIdHasher.hashIssuerName(issuerCertDer);
    byte[] keyHash  = CertIdHasher.hashIssuerPublicKey(issuerCertDer);

    // Из объекта GostCertificate — по размеру ключа (256/512)
    int hlen = caCert.getKeySize() == 512
            ? GostOids.STREEBOG_512_HASH_LEN
            : GostOids.STREEBOG_256_HASH_LEN;
    byte[] nameHash2 = CertIdHasher.hashIssuerName(caCert, hlen);
    byte[] keyHash2  = CertIdHasher.hashIssuerPublicKey(caCert, hlen);

### Кодирование GeneralNames — `GeneralNameCodec`

Кодирует DNS-имена, IP-адреса и DN в DER GeneralName (RFC 5280
§4.2.1.6). Используется в `GostCertificateBuilder` (SAN) и
`GostCrlBuilder` (certificateIssuer).

    import org.rssys.gost.pkix.cert.GeneralNameCodec;

    // DNS-имя
    byte[] dnsName = GeneralNameCodec.encodeDnsName("example.com");

    // IP-адрес
    byte[] ipAddr = GeneralNameCodec.encodeIpAddress("192.168.1.1");

    // Distinguished Name
    byte[] issuerDn = GostDnParser.encodeDn("CN=My CA,O=MyOrg,C=RU");
    byte[] dirName = GeneralNameCodec.encodeDirectoryName(issuerDn);

    // Собрать SEQUENCE OF GeneralName (например, для certificateIssuer в CRL)
    byte[] generalNames = GeneralNameCodec.encodeGeneralNames(dnsName, ipAddr, dirName);

### Типизированные причины ошибок — `PkixException.Reason`

`PkixException` — checked-исключение с перечислением `Reason` для
межмодульного маппинга. Все методы верификации бросают его при ошибке
(fail-closed). TLS-слой преобразует `Reason` в alert-код без разбора
текста сообщения.

<table>
<caption>Перечень причин:</caption>
<colgroup>
<col style="width: 28%" />
<col style="width: 71%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p><code>EXPIRED</code></p></td>
<td style="text-align: left;"><p>Сертификат просрочен</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ROOT_NOT_SIGNED</code></p></td>
<td style="text-align: left;"><p>Корневой сертификат не
самоподписан</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>DN_MISMATCH</code></p></td>
<td style="text-align: left;"><p>Несовпадение subject/issuer DN в
цепочке</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>NOT_CA</code></p></td>
<td style="text-align: left;"><p>Сертификат не является CA</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>MISSING_KEY_CERT_SIGN</code></p></td>
<td style="text-align: left;"><p>Отсутствует флаг keyCertSign</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>PATH_LEN_EXCEEDED</code></p></td>
<td style="text-align: left;"><p>Превышена длина пути
pathLenConstraint</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ALG_MISMATCH</code></p></td>
<td style="text-align: left;"><p>Несовместимость алгоритмов</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>UNKNOWN_CRITICAL_EXTENSION</code></p></td>
<td style="text-align: left;"><p>Неизвестное критическое
расширение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>SIGNATURE_INVALID</code></p></td>
<td style="text-align: left;"><p>Недействительная подпись</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>PARSE_ERROR</code></p></td>
<td style="text-align: left;"><p>Ошибка разбора DER / ASN.1</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>THIS_UPDATE_FUTURE</code></p></td>
<td style="text-align: left;"><p>thisUpdate в будущем
(CRL/OCSP)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>IDP_NOT_SUPPORTED</code></p></td>
<td style="text-align: left;"><p>Неподдерживаемый
issuingDistributionPoint</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>REVOKED</code></p></td>
<td style="text-align: left;"><p>Сертификат отозван</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>INCOMPLETE_CHAIN</code></p></td>
<td style="text-align: left;"><p>Не найден issuer в пуле
сертификатов</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>CHAIN_LOOP</code></p></td>
<td style="text-align: left;"><p>Зацикливание DN в цепочке</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>CHAIN_TOO_LONG</code></p></td>
<td style="text-align: left;"><p>Превышена максимальная глубина
цепочки</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ROOT_NOT_TRUSTED</code></p></td>
<td style="text-align: left;"><p>Корень не в списке доверенных</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>OTHER</code></p></td>
<td style="text-align: left;"><p>Прочие ошибки</p></td>
</tr>
</tbody>
</table>

Обработка ошибок — см. раздел [Типовые
сценарии](#Обработка ошибок верификации).

## Типовые сценарии

Сквозные примеры для распространённых задач — от начала до конца. Все
переменные (`cert`, `caCert`, `caPrivateKey` и др.) создаются как в
[Быстром старте](#Быстрый старт).

### Создание инфраструктуры CA

Полный цикл: root CA → промежуточный CA → конечный сертификат.

    import org.rssys.gost.pkix.cert.GostCertificateBuilder;
    import org.rssys.gost.pkix.cert.ChainValidator;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.signature.ECParameters;
    import java.math.BigInteger;
    import java.util.List;

    ECParameters params = ECParameters.tc26a256();

    // 1. Корневой CA (самоподписанный)
    var rootKp = KeyGenerator.generateKeyPair(params);
    GostCertificate rootCert = GostCertificateBuilder.create(params, "CN=Root CA,O=MyOrg,C=RU")
            .publicKey(rootKp.getPublic())
            .notBefore("20260101000000Z")
            .notAfter("20460101000000Z")
            .basicConstraints(true, null)          // CA без ограничения pathLen
            .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                      GostCertificateBuilder.KeyUsage.CRL_SIGN)
            .serial(BigInteger.ONE)
            .assembleCert(rootKp.getPrivate());

    // 2. Промежуточный CA
    var interKp = KeyGenerator.generateKeyPair(params);
    GostCertificate interCert = GostCertificateBuilder.create(params, "CN=Intermediate CA,O=MyOrg,C=RU")
            .publicKey(interKp.getPublic())
            .issuerDn("CN=Root CA,O=MyOrg,C=RU")   // 
            .notBefore("20260101000000Z")
            .notAfter("20360101000000Z")
            .basicConstraints(true, 0)             // CA, pathLen=0
            .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                      GostCertificateBuilder.KeyUsage.CRL_SIGN)
            .serial(BigInteger.valueOf(2))
            .assembleCert(rootKp.getPrivate());     // подписан корневым CA

    // 3. Конечный сертификат (end-entity)
    var leafKp = KeyGenerator.generateKeyPair(params);
    GostCertificate leafCert = GostCertificateBuilder.create(params, "CN=server.example.com,O=MyOrg,C=RU")
            .publicKey(leafKp.getPublic())
            .issuerDn("CN=Intermediate CA,O=MyOrg,C=RU")
            .notBefore("20260101000000Z")
            .notAfter("20270101000000Z")
            .sanDns("server.example.com", "www.example.com")
            .basicConstraints(false, null)         // не CA
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
            .serial(BigInteger.valueOf(3))
            .assembleCert(interKp.getPrivate());    // подписан промежуточным CA

    // 4. Валидация цепочки
    List<GostCertificate> chain = List.of(leafCert, interCert);
    ChainValidator.validateChain(chain, List.of(rootCert.getPublicKey()));

- `issuerDn(String)` — String-перегрузка, не требует
  `GostDnParser.encodeDn()`.

### Полный цикл OCSP

Построение запроса, разбор ответа, проверка nonce.

    import org.rssys.gost.pkix.cert.*;

    // 1. Строим OCSP-запрос
    GostOcspRequestBuilder reqBuilder = GostOcspRequestBuilder.create()
            .targetCert(leafCert.getEncoded())
            .issuerCert(interCert.getEncoded());
    byte[] requestDer = reqBuilder.build();
    byte[] expectedNonce = reqBuilder.getNonce();

    // 2. ... передача requestDer на OCSP-responder по HTTP ...

    // 3. Строим OCSP-ответ (на стороне CA)
    byte[] ocspDer = GostOcspResponseBuilder.create(leafCert.getSerialNumber())
            .signer(caPrivateKey, caPublicKey)
            .issuerDn("CN=Intermediate CA,O=MyOrg,C=RU")
            .nonce(expectedNonce)                    // вернём nonce из запроса
            .good()
            .build();

    // 4. Проверяем ответ
    OcspVerifier.verify(ocspDer, leafCert.getSerialNumber(), interCert.getPublicKey());
    OcspVerifier.verifyNonce(ocspDer, expectedNonce, true);  // strict

    // 5. Разбираем ответ для деталей
    GostOcspResponse response = GostOcspResponse.fromDer(ocspDer);
    System.out.println("Produced at: " + response.getProducedAt());
    for (SingleOcspResponse sr : response.getResponses()) {
        System.out.println("Status: " + (sr.isGood() ? "good" : sr.isRevoked() ? "revoked" : "unknown"));
    }

### Безопасная передача ключей через PKCS#12

Создание PFX-контейнера, сохранение, передача и загрузка.

    import org.rssys.gost.pkix.cert.GostPkcs12Builder;
    import org.rssys.gost.pkix.cert.GostPkcs12Loader;
    import java.nio.file.Path;

    // 1. Создать и сразу записать в файл (один вызов)
    GostPkcs12Builder.create()
            .key(leafKp.getPrivate())
            .certificate(leafCert)
            .caCertificate(interCert)
            .caCertificate(rootCert)
            .password("changeit".toCharArray())
            .friendlyName("server-key")
            .iterations(100_000)
            .buildAndWriteTo(Path.of("keystore.pfx"));  // 

    // Альтернатива: получить byte[] и распорядиться самостоятельно
    byte[] pfx = GostPkcs12Builder.create()
            .key(leafKp.getPrivate())
            .certificate(leafCert)
            .password("changeit".toCharArray())
            .build();

    // 2. Загрузка на другой стороне
    GostPkcs12Loader.Result result = GostPkcs12Loader.load(
            pfx,
            "changeit".toCharArray(), true);

    PrivateKeyParameters loadedKey = result.getPrivateKey();
    List<GostCertificate> chain = result.getCertificateChain();
    // chain.get(0) — конечный сертификат, chain.get(1) — inter, chain.get(2) — root

- `buildAndWriteTo()` — записывает PFX напрямую в файл, без
  промежуточного `byte[]`. PFX можно передавать по сети — без пароля
  бесполезен.

### Конфиденциальный документооборот

Подписать и зашифровать документ, отправить, расшифровать и проверить
подпись.

    import org.rssys.gost.pkix.cms.CmsSignedAndEnvelopedData;
    import java.nio.charset.StandardCharsets;
    import java.util.Arrays;

    byte[] document = "Секретный приказ".getBytes(StandardCharsets.UTF_8);

    // Отправитель: подписать и зашифровать для получателя
    byte[] envelope = CmsSignedAndEnvelopedData.signThenEncrypt(
            document,
            signerPrivateKey, signerCert,     // подписант
            recipientCert);                    // получатель

    // ... передача envelope по сети ...

    // Получатель: расшифровать и проверить подпись
    VerifiedSignedData result =
            CmsSignedAndEnvelopedData.decryptAndVerify(
                    envelope,
                    recipientPrivateKey, recipientCert,
                    signerCert);              // доверенный сертификат подписанта

    assert Arrays.equals(document, result.data());
    System.out.println("Подписал: " + result.signerCertificate().getSubjectDn());

### Долговременная подпись CAdES-T

Полный цикл: подписать с CAdES-BES, запросить метку времени у TSA,
проверить.

    import org.rssys.gost.pkix.cms.CAdESExtender;
    import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
    import org.rssys.gost.pkix.tsp.JdkHttpTspTransport;

    byte[] data = "Годовой отчёт".getBytes(StandardCharsets.UTF_8);

    // 1. Создаём CAdES-BES
    byte[] cadesBes = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(signerPrivateKey, signerCert)
            .withCAdES()
            .build();

    // 2. Добавляем метку времени от TSA
    byte[] cadesT = CAdESExtender.addTimestamp(
            cadesBes,
            "http://tsa.example.com/tsa",
            new JdkHttpTspTransport(),
            tsaTrustedCert);

    // 3. Сохраняем cadesT. Проверить можно через месяц или год:
    VerifiedCAdESData verified = CAdESExtender.verifyCAdEST(cadesT, tsaTrustedCert);

    byte[] originalData = verified.data();
    CAdESSignerResult signer = verified.signers().get(0);
    System.out.println("Подписант: " + signer.signerCertificate().getSubjectDn());
    System.out.println("Меток времени: " + signer.timestamps().size());
    for (TstInfo t : signer.timestamps()) {
        System.out.println("  Время метки: " + t.genTime());
    }

Если TSA недоступен, но токен уже получен — используйте
`embedTimestamp()`:

    byte[] cadesT = CAdESExtender.embedTimestamp(cadesBesDer, timeStampTokenDer);

### Обработка ошибок верификации

Все методы верификации бросают `PkixException` (checked). Рекомендуемый
паттерн обработки:

    import org.rssys.gost.pkix.cert.PkixException;

    try {
        ChainValidator.validateChain(chain, trustedKeys);
        // цепочка валидна
    } catch (PkixException e) {
        switch (e.reason()) {
            case EXPIRED -> log.warn("Сертификат просрочен: {}", e.getMessage());
            case REVOKED -> log.error("Сертификат отозван: {}", e.getMessage());
            case SIGNATURE_INVALID -> log.error("Подпись недействительна: {}", e.getMessage());
            case NOT_CA -> log.error("Сертификат не является CA: {}", e.getMessage());
            case INCOMPLETE_CHAIN -> log.warn("Не удалось построить цепочку: {}", e.getMessage());
            default -> log.error("Ошибка верификации: {}", e.getMessage());
        }
        throw e; // fail-closed — дальше не идём
    }

## Кросс-валидация

Для модуля `crypto-gost-pkix` выполнена кросс-валидация:

**SignedData — с КриптоПРО:** подпись, созданная `CmsSignedDataBuilder`,
успешно верифицируется cryptcp (`[ErrorCode: 0x00000000]`). Подпись,
созданная cryptcp, успешно верифицируется `CmsSignedDataVerifier`
(`valid: true`). Двусторонняя совместимость подтверждена.

**CAdES-T — с BouncyCastle:** CAdES-T подпись, созданная библиотекой,
успешно верифицируется BouncyCastle. TimeStampResp, созданный
`TspResponseBuilder`, разбирается и верифицируется BouncyCastle
(nonce-echo, rejected, детекция неверного imprint). Двусторонняя
совместимость подтверждена.

**CSR (PKCS#10) — с OpenSSL:** CSR, созданный библиотекой, успешно
верифицируется `openssl req -verify`. CSR, созданный `openssl req -new`,
успешно разбирается и верифицируется `GostCsrParser`
(proof-of-possession). Двусторонняя совместимость подтверждена.

**EnvelopedData:** КриптоПРО использует KeyTransRecipientInfo с ГОСТ
28147-89. Наш формат — KeyAgreeRecipientInfo с VKO + KExp15 + Кузнечик
CTR-ACPKM. Несовместимы по дизайну.

Диагностические тесты:

    # CMS (КриптоПРО)
    mvn -Pcrossval -pl x-validation-tests/cms -am test -Dexec.skip=true

    # CAdES-T (BouncyCastle)
    mvn -Pcrossval -pl x-validation-tests/cadest -am test -Dexec.skip=true

    # CSR (OpenSSL)
    mvn -Pcrossval -pl x-validation-tests/csr -am test -Dexec.skip=true

## Поддержать проект

Если проект оказался полезным, вы можете поддержать проект на
[**Boosty**](https://boosty.to/mike_ananev/donate)

## Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
