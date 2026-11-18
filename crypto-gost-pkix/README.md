# PKIX-инфраструктура с ГОСТ-криптографией — crypto-gost-pkix

Модуль `crypto-gost-pkix` работает с сертификатами, списками отзыва,
OCSP, подписью и шифрованием документов на ГОСТ Р 34.10-2012 и Стрибоге.
Вся криптография выполняется модулем `crypto-gost-core`; других
зависимостей у модуля нет. Совместим с Java 21 и Android 14+.

Что внутри:

- **Сертификаты и запросы:** `GostCertificate` (разбор и проверка),
  `GostCertificateBuilder` (выпуск), `GostCsrBuilder` и `GostCsrParser`
  (PKCS#10), `GostPkcs12Builder` и `GostPkcs12Loader` (PFX по RFC 9548).

- **Доверие:** `TrustAnchors` и `ChainValidator` (цепочка по RFC 5280).

- **Отзыв:** `GostCrlBuilder`, `CrlVerifier`, `GostCrl` (RFC 5280),
  `GostOcspResponseBuilder`, `OcspVerifier`, `GostOcspRequestBuilder`
  (RFC 6960, Р 1323565.1.059-2024).

- **CMS:** `CmsSignedDataBuilder` и `CmsSignedDataVerifier` (RFC 5652,
  RFC 4490), `CmsEnvelopedDataBuilder` и `CmsEnvelopedDataDecryptor`,
  `CmsSignedAndEnvelopedData`, `GostPkcs7` (.p7b).

- **Долговременная подпись:** CAdES-BES, CAdES-T, CAdES-C, CAdES-X Long
  Type 1 и контрподпись (`CAdESExtender`, `CAdESVerifier`), клиент и
  сервер меток времени TSP (RFC 3161).

- **Справочное:** `GostOids` (реестр OID), `PkixException.Reason`
  (типизированные причины отказа).

Низкоуровневые помощники: `GostDnParser.encodeDn` (сборка DER DN по
атрибутам), DER-кодеки (включая BER indefinite-length),
`GostPkcs12Parser` (разбор структуры PFX без расшифровки ключа).
`ExtensionsAccumulator` собирает общие расширения сертификата и CSR, но
публичного пути подключения к строителям не имеет: используйте
fluent-методы `GostCertificateBuilder` и `GostCsrBuilder`.

## Как читать примеры

Примеры показывают суть приёма, а не готовую программу: без `main`,
объявлений и обработки исключений. Импорты указаны только там, где пакет
класса не угадать. Во всех примерах подразумеваются условные
обозначения:

<table>
<colgroup>
<col style="width: 28%" />
<col style="width: 71%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p><code>params</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.tc26a256()</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>kp</code>, <code>leafKp</code>,
<code>interKp</code>, <code>rootKp</code></p></td>
<td style="text-align: left;"><p>ключевая пара
(<code>getPublic()</code>, <code>getPrivate()</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>caKey</code>,
<code>signerKey</code>, <code>leafKey</code>, <code>tsaKey</code> и
другие <code>...Key</code></p></td>
<td
style="text-align: left;"><p><code>PrivateKeyParameters</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>cert</code>, <code>caCert</code>,
<code>leafCert</code>, <code>interCert</code>, <code>rootCert</code>,
<code>signerCert</code>, <code>recipientCert</code>,
<code>tsaCert</code> и другие <code>...Cert</code></p></td>
<td style="text-align: left;"><p><code>GostCertificate</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>chain</code></p></td>
<td
style="text-align: left;"><p><code>List&lt;GostCertificate&gt;</code>,
от конечного сертификата к издателям</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>anchors</code></p></td>
<td style="text-align: left;"><p><code>TrustAnchors</code>; если не
сказано иное, с корнем <code>rootCert</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>data</code></p></td>
<td style="text-align: left;"><p><code>byte[]</code> с
документом</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>signatureBytes</code></p></td>
<td style="text-align: left;"><p>значение подписи, для которой
запрашивается метка времени</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>signingTime</code></p></td>
<td style="text-align: left;"><p><code>Instant</code>, момент
подписи</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>revokedCert</code></p></td>
<td style="text-align: left;"><p><code>GostCertificate</code>,
сертификат, который УЦ отозвал (в примерах CRL)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>entry</code></p></td>
<td style="text-align: left;"><p><code>RevokedEntry</code>, запись об
отзыве (сертификат, дата, причина)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>crl</code></p></td>
<td style="text-align: left;"><p><code>GostCrl</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>crlDer</code>,
<code>ocspDer</code>, <code>csrDer</code> и другие
<code>...Der</code></p></td>
<td style="text-align: left;"><p>DER-байты соответствующего
объекта</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>leafCrl</code>,
<code>interCrl</code></p></td>
<td style="text-align: left;"><p><code>GostCrl</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>serial</code></p></td>
<td style="text-align: left;"><p>серийный номер проверяемого
сертификата, <code>cert.getSerialNumber()</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>password</code></p></td>
<td style="text-align: left;"><p><code>char[]</code>, введённый
пользователем: в примерах никогда не литерал, затирается после
использования</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>requestorCert</code></p></td>
<td style="text-align: left;"><p><code>GostCertificate</code>,
сертификат подписанта OCSP-запроса</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>transport</code></p></td>
<td style="text-align: left;"><p><code>TspTransport</code> (клиент
службы меток времени)</p></td>
</tr>
</tbody>
</table>

Строка `byte[] requestDer = ...;` и подобные означают внешний вход
(файл, тело HTTP-запроса). Время задаётся через `Instant` и методы
`...Now()`: жёсткие даты в примерах устаревают. Строковая форма осталась
там, где её требует API (`RevokedEntry`, атрибут `signingTime`).

### Что выбрать

<table>
<colgroup>
<col style="width: 30%" />
<col style="width: 30%" />
<col style="width: 40%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Задача</th>
<th style="text-align: left;">Класс</th>
<th style="text-align: left;">Чего избегать</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Выпустить сертификат</p></td>
<td
style="text-align: left;"><p><code>GostCertificateBuilder</code></p></td>
<td style="text-align: left;"><p>собирать TBS вручную, подписывать без
проверки результата</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Проверить цепочку</p></td>
<td
style="text-align: left;"><p><code>ChainValidator.validateChain</code> с
<code>TrustAnchors</code></p></td>
<td style="text-align: left;"><p>доверять сертификату по совпадению
открытого ключа</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Узнать, не отозван ли
сертификат</p></td>
<td style="text-align: left;"><p><code>CrlVerifier.verify</code>,
<code>OcspVerifier.verify</code></p></td>
<td style="text-align: left;"><p><code>GostCrl.verify</code> и
<code>isRevoked</code>: область CRL не проверяется</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Подписать документ</p></td>
<td
style="text-align: left;"><p><code>CmsSignedDataBuilder</code></p></td>
<td style="text-align: left;"><p>подпись без проверки цепочки
(<code>VerifyOptions.signatureOnly</code>)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Проверить подпись</p></td>
<td
style="text-align: left;"><p><code>CmsSignedDataVerifier.verify</code> с
<code>VerifyOptions.trusting</code></p></td>
<td style="text-align: left;"><p><code>Revocation.none()</code> там, где
отзыв важен</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Зашифровать документ</p></td>
<td
style="text-align: left;"><p><code>CmsEnvelopedDataBuilder</code></p></td>
<td style="text-align: left;"><p><code>withoutIntegrity()</code> без
явной причины</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Подпись, которая переживёт
сертификат</p></td>
<td style="text-align: left;"><p>CAdES-T, CAdES-X Long</p></td>
<td style="text-align: left;"><p>метка времени без проверки подписи
TSA</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Хранить ключ и сертификат</p></td>
<td style="text-align: left;"><p><code>GostPkcs12Builder</code></p></td>
<td style="text-align: left;"><p><code>allowJdkFallback = true</code>,
пароль-литерал в коде</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Подписывать ключом в HSM</p></td>
<td style="text-align: left;"><p><code>GostSigner</code></p></td>
<td style="text-align: left;"><p>извлекать закрытый ключ в память
JVM</p></td>
</tr>
</tbody>
</table>

## Быстрый старт

Ключ, самоподписанный сертификат, подпись документа и шифрование для
получателя.

    import org.rssys.gost.pkix.cert.*;
    import org.rssys.gost.pkix.cms.*;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.signature.ECParameters;

    ECParameters params = ECParameters.tc26a256();
    var kp = KeyGenerator.generateKeyPair(params);

    // Для самоподписанного сертификата issuerDn не нужен: берётся subject
    GostCertificate cert = GostCertificateBuilder.create(params, "CN=Demo,O=MyOrg,C=RU")
            .publicKey(kp.getPublic())
            .notBeforeNow().validForDays(365)
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .randomSerial()
            .sign(kp.getPrivate());

    // Подпись и проверка. Якорь доверия -- сам сертификат; отзыв в демо не проверяется
    byte[] signed = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(kp.getPrivate(), cert)
            .build();
    VerifiedSignedData verified = CmsSignedDataVerifier.verify(signed,
            VerifyOptions.trusting(TrustAnchors.ofCertificates(cert),
                    SignerSelection.ANY, Revocation.none()));   // отзыв не проверяется: см. «Безопасность»
    byte[] original = verified.data();

    // Шифрование для получателя и расшифрование
    byte[] enveloped = CmsEnvelopedDataBuilder.create().data(data).addRecipient(cert).build();
    byte[] plain = CmsEnvelopedDataDecryptor.decrypt(enveloped, kp.getPrivate(), cert);

Сертификат и подпись — публичные данные, их можно передавать по сети.
Закрытый ключ хранится в PKCS#12 (раздел «PKCS#12 — хранение ключей и
сертификатов»). В боевой проверке отзыв задаётся явно (раздел «Отзыв
сертификатов»).

## Сертификаты

### Чтение и проверка — `GostCertificate`

    GostCertificate cert = GostCertificate.fromPemOrDer(bytes);   // формат определяется сам
    GostCertificate fromDer = GostCertificate.fromDer(derBytes);
    List<GostCertificate> chain = GostCertificate.listFromPem(pemBytes);

    boolean selfSignedOk = cert.verifySignature(cert.getPublicKey());  // подпись ключом издателя
    boolean validNow = cert.isValidAt(Instant.now());                  // срок действия
    boolean expired = cert.isExpired();
    Instant notBefore = cert.getNotBefore();
    Instant notAfter = cert.getNotAfter();

    String subject = cert.getSubjectDn();      // "CN=Demo, O=MyOrg, C=RU"
    String issuer = cert.getIssuerDn();
    boolean selfSigned = cert.isSelfSigned();
    boolean isCa = cert.isCA();
    int pathLen = cert.getPathLen();           // -1, если ограничения pathLenConstraint нет
    String sigAlg = cert.getSignatureAlgorithmOid();
    byte[] serial = cert.getSerialNumber();
    BigInteger serialNumber = cert.getSerialNumberBigInt();

Сверка имени узла (RFC 6125) использует `dNSName` и `iPAddress` из SAN;
остальные виды имён (`rfc822Name`, URI, `directoryName`, `otherName` с
UPN) читаются отдельно. Unicode-имя приводится к A-label внутри
`verifyHostname`; для SNI то же даёт `GostDnsName.toAsciiHostname`.

    boolean hostOk = cert.verifyHostname("gost.example.com");
    boolean ipOk = cert.verifyAddress("192.168.1.1");

    String[] emails = cert.getSanRfc822Names();
    String[] uris = cert.getSanUris();
    byte[][] dirNames = cert.getSanDirectoryNames();
    OtherNameEntry[] otherNames = cert.getSanOtherNames();

    String sni = GostDnsName.toAsciiHostname("пример.рф");   // punycode для SNI

Расширения читаются одним объектом
`GostExtensionParser.ExtensionsResult`: так оператор УЦ видит всё, что
было в сертификате, и сам решает, что переносить при перевыпуске.

    if (cert.hasExtensions()) {
        GostExtensionParser.ExtensionsResult ext = cert.getExtensions();   // независимая копия
        String[] san = ext.sanDnsNames;
        String[] ian = ext.ianDnsNames;
        String[] ocspUris = ext.ocspUris;
        int keyUsageBits = ext.keyUsageBits;
        boolean ca = ext.isCA;
        int extPathLen = ext.pathLen;
        Set<String> present = ext.presentExtensionOids;
    }
    byte[] raw = cert.getExtensionValue("2.5.29.15");   // содержимое extnValue или null
    boolean mine = cert.matchesPrivateKey(privateKey);  // ключ действительно к этому сертификату
    boolean canSign = cert.isKeyUsageValidForSigning(); // digitalSignature или nonRepudiation

Экспорт: `cert.toPem()`, `cert.getEncoded()`,
`GostCertificate.chainToPem(chain)`.

### Выпуск — `GostCertificateBuilder`

Серийный номер обязателен (`randomSerial()` даёт 128 случайных бит).
Срок задаётся от текущего момента: `validForDays`, `validForMonths` и
`validForYears` вызываются после `notBeforeNow()`. Для воспроизводимых
сертификатов есть `notBefore(Instant)` и `notAfter(Instant)`.

    GostCertificate leaf = GostCertificateBuilder.create(params, "CN=server.example.com,O=MyOrg,C=RU")
            .publicKey(leafKp.getPublic())
            .issuerDn(interCert.getSubjectDnBytes())     // байты subject издателя, а не строка
            .notBeforeNow().validForDays(365)
            .sanDns("server.example.com", "www.example.com")
            .sanIp("192.168.1.10")
            .basicConstraints(false, null)
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
            .ocspResponder("http://ocsp.example.com")    // AIA
            .caIssuer("http://ca.example.com/ca.p7c")
            .crlDistributionPoints("http://crl.example.com/ca.crl")
            .freshestCrl("http://crl.example.com/delta.crl")
            .aki(interCert.getPublicKey())               // идентификатор ключа издателя
            .randomSerial()
            .sign(interKp.getPrivate());

Остальные расширения: `sanRfc822Name`, `sanUri`, `sanDirectoryName`,
`sanUpn`, `sanOtherName`, `ianDns` и родственные, `ski()`, `aki(...)`,
`nameConstraints(...)`, `additionalExtensions(...)`.

Политики сертификата (RFC 5280 §4.2.1.4) с необязательной ссылкой на
регламент:

    builder.certificatePolicies(GostOids.POLICY_KC1, GostOids.POLICY_KC2);
    // с CPS-квалификатором -- только так:
    builder.certificatePolicyInfos(
            new CertificatePolicy(GostOids.POLICY_KC1, "https://ca.example.com/cps.html"),
            new CertificatePolicy(GostOids.POLICY_KC2));

    CertificatePolicy[] infos = cert.getCertificatePolicyInfos();   // policyOid(), cpsUri() (может быть null)

### Сквозной пример: корневой УЦ, промежуточный УЦ, конечный сертификат

    ECParameters params = ECParameters.tc26a256();

    var rootKp = KeyGenerator.generateKeyPair(params);
    GostCertificate rootCert = GostCertificateBuilder.create(params, "CN=Root CA,O=MyOrg,C=RU")
            .publicKey(rootKp.getPublic())
            .notBeforeNow().validForYears(20)
            .basicConstraints(true, null)
            .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                      GostCertificateBuilder.KeyUsage.CRL_SIGN)
            .ski()                                        // идентификатор ключа обязателен у УЦ (RFC 5280 §4.2.1.2)
            .randomSerial()
            .sign(rootKp.getPrivate());

    var interKp = KeyGenerator.generateKeyPair(params);
    GostCertificate interCert = GostCertificateBuilder.create(params, "CN=Intermediate CA,O=MyOrg,C=RU")
            .publicKey(interKp.getPublic())
            .issuerDn(rootCert.getSubjectDnBytes())
            .notBeforeNow().validForYears(10)
            .basicConstraints(true, 0)                    // ниже только конечные сертификаты
            .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                      GostCertificateBuilder.KeyUsage.CRL_SIGN)
            .ski()
            .randomSerial()
            .sign(rootKp.getPrivate());

    var leafKp = KeyGenerator.generateKeyPair(params);
    GostCertificate leafCert = GostCertificateBuilder.create(params, "CN=server.example.com,O=MyOrg,C=RU")
            .publicKey(leafKp.getPublic())
            .issuerDn(interCert.getSubjectDnBytes())
            .notBeforeNow().validForDays(365)
            .sanDns("server.example.com")
            .basicConstraints(false, null)
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
            .randomSerial()
            .sign(interKp.getPrivate());

    // Проверка: корень в якорях, промежуточный прислан вместе с конечным сертификатом
    List<GostCertificate> effective = ChainValidator.validateChain(
            List.of(leafCert, interCert), TrustAnchors.ofCertificate(rootCert));
    // effective: [leafCert, interCert, rootCert]

Переменные этого примера (`rootCert`, `interCert`, `leafCert`, `rootKp`,
`interKp`, `leafKp`) подразумеваются в остальных разделах. `caCert` и
`caKey` — это УЦ, выпустивший `leafCert`, то есть промежуточный
(`interCert` и `interKp.getPrivate()`): именно он подписывает CRL и
OCSP-ответы для листа, и именно его сертификат передают проверяющим
методам. `signerCert` и `signerKey` — подписант документа (в примерах
CMS это конечный сертификат с `digitalSignature`). Строку
`issuerDn(String)` для существующего УЦ не используют: она кодирует имя
заново и может не совпасть с `issuer` ранее выпущенных сертификатов.

### CSR (PKCS#10)

CSR содержит открытый ключ заявителя, имя и подпись, которая доказывает
владение закрытым ключом. Это публичный документ.

    byte[] csrDer = GostCsrBuilder.create("CN=myserver.example.com,O=MyOrg,C=RU", kp.getPublic())
            .sanDns("myserver.example.com")
            .sanIp("192.168.1.10")
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
            .basicConstraints(false, null)
            .certificatePolicies(GostOids.POLICY_KC1)
            .ski()
            .sign(kp.getPrivate());

`extensionRequest` — просьба заявителя, а не полномочие. УЦ обязан
проверить запрошенное (владение доменом для SAN) и никогда не выпускать
`CA=TRUE` по запросу без процедуры выпуска подчинённого УЦ.

`challengePassword` (PKCS#9, в EST — RFC 7030 §3.5) — секрет одного
выпуска, поэтому он передаётся на подписи, а не хранится в строителе.
Произвольные атрибуты добавляет `attribute(oid, valuesDer...)`.

    byte[] csrDer = GostCsrBuilder.create("CN=device-1,O=MyOrg,C=RU", kp.getPublic())
            .attribute("1.2.840.113549.1.9.2", DerCodec.encodeUTF8String("device-1"))
            .sign(kp.getPrivate(), password);   // массив не изменяется и не затирается библиотекой

Пароль: от 1 до 255 знаков и не более 255 байт в закодированном виде,
без управляющих знаков и одиночных суррогатов; кодируется как
`PrintableString` или `UTF8String`. Готовый CSR содержит пароль всегда,
хранить его нужно как секрет до выпуска сертификата.

Разбор строгий: повтор атрибута, пустой набор значений, хвостовые байты
и некорректный пароль отвергают CSR целиком.

    GostCsrParser csr = GostCsrParser.fromPemOrDer(csrBytes);
    if (!csr.verifySelf()) {                         // доказательство владения ключом
        throw new SecurityException("CSR signature is invalid");
    }
    String dn = csr.getSubjectDn();
    String[] cn = csr.getSubjectDnField("2.5.4.3");  // значения CN
    byte[] subjectDnDer = csr.getSubjectDnDer();     // байты имени без перекодировки
    var csrKey = csr.getPublicKey();                 // открытый ключ заявителя
    String csrSigAlg = csr.getSignatureAlgorithmOid();
    GostExtensionParser.ExtensionsResult ext = csr.getExtensions();   // запрошенные расширения
    Optional<char[]> pwd = csr.getChallengePassword();                // затирает вызывающий
    String csrPem = csr.toPem();                     // -----BEGIN CERTIFICATE REQUEST-----

### Выпуск по CSR и перевыпуск

`fromCsrIdentity` проверяет подпись CSR и переносит имя и ключ;
расширения УЦ переносит сам, осознанно. `fromCertificate` делает то же
для перевыпуска: берёт имя и ключ существующего сертификата.

    GostCertificateBuilder builder = GostCertificateBuilder.fromCsrIdentity(csr, params);  // PkixException, если подпись CSR неверна
    GostExtensionParser.ExtensionsResult ext = csr.getExtensions();
    if (ext.sanDnsNames != null) {
        builder.sanDns(ext.sanDnsNames);              // владение доменом проверено вне библиотеки
    }
    if (ext.keyUsageBits != 0
            && GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.isSetIn(ext.keyUsageBits)) {
        builder.keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
    }
    if (ext.isCA) {
        builder.basicConstraints(true, ext.pathLen >= 0 ? ext.pathLen : null);
    }
    GostCertificate issued = builder
            .issuerDn(caCert.getSubjectDnBytes())
            .notBeforeNow().validForDays(365)
            .randomSerial()
            .sign(caKey);

    // Перевыпуск: те же имя и ключ, новые срок и серийный номер.
    // Расширения снова читаем и переносим выборочно.
    GostExtensionParser.ExtensionsResult oldExt = issued.getExtensions();
    GostCertificateBuilder renewal = GostCertificateBuilder.fromCertificate(issued, params);
    if (oldExt.sanDnsNames != null) {
        renewal.sanDns(oldExt.sanDnsNames);
    }
    if (oldExt.keyUsageBits != 0
            && GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.isSetIn(oldExt.keyUsageBits)) {
        renewal.keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
    }
    if (oldExt.isCA) {
        renewal.basicConstraints(true, oldExt.pathLen >= 0 ? oldExt.pathLen : null);
    }
    GostCertificate renewed = renewal
            .issuerDn(caCert.getSubjectDnBytes())
            .notBeforeNow().validForDays(365)
            .randomSerial()
            .sign(caKey);

Расширения при перевыпуске не копируются автоматически: короткий срок
сертификата нужен именно для повторной проверки полномочий (SAN, EKU,
статуса УЦ). Читайте их через `getExtensions()` и переносите выборочно.

## PKCS#12 — хранение ключей и сертификатов

PFX объединяет закрытый ключ, сертификат и цепочку в одном файле,
защищённом паролем. Ключ зашифрован по PBES2 (PBKDF2-HMAC-Стрибог,
Кузнечик CTR-ACPKM), целостность — MAC по RFC 9548 §7 (HMAC-Стрибог-512,
соль 32 байта). Пароль — единственный секрет: без него файл бесполезен и
его можно передавать по сети.

    byte[] pfx = GostPkcs12Builder.create()
            .key(kp.getPrivate())
            .certificate(leafCert)
            .caCertificate(interCert)
            .password(password)                 // билдер копирует пароль и затирает свою копию
            .friendlyName("server")
            .iterations(100_000)                // по умолчанию 2000; загрузчик требует не меньше 1000
            .build();                           // одноразовый: второй вызов -> IllegalStateException
    // либо сразу в файл: .buildAndWriteTo(Path.of("server.pfx"))

    GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, password, false);
    PrivateKeyParameters key = result.getPrivateKey();
    List<GostCertificate> chain = result.getCertificateChain();   // конечный сертификат первым

Нижняя граница итераций — 1000: файл с меньшим числом строитель соберёт,
но загрузчик отвергнет (`MacData iterations too low`). Третий аргумент
`load` (`allowJdkFallback`) разрешает откат на JDK `KeyStore` для
контейнеров не на ГОСТ; в ГОСТ-проектах он `false`. Для legacy-файлов из
доверенного источника порог задаётся явно:
`load(pfx, password, false, minPbkdf2Iterations)`; политику MAC
принимает перегрузка
`load(pfx, password, allowJdkFallback, minPbkdf2Iterations, MacPolicy)`.
Структуру PFX без расшифровки ключа читает
`GostPkcs12Parser.parsePfx(pfx)`.

Загрузчик выбирает закрытый ключ по совпадению с первым звеном цепочки,
а не по порядку записей. Сертификаты, не связанные с ним по `issuer`,
`subject` и подписи, в `getCertificateChain()` не попадают; их число
даёт `getDroppedCertificateCount()`, все
кандидаты — `getAllCertificates()`.

Зашифрованный ключ отдельно (PKCS#8, PBES2); пароль затирается после
последнего использования:

    byte[] passwordBytes = PasswordUtf8.encode(password);       // org.rssys.gost.util, строгий UTF-8
    byte[] encrypted = GostPbes2.encryptKey(key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, 100_000);
    Arrays.fill(passwordBytes, (byte) 0);

    PrivateKeyParameters restored = GostPkcs12Loader.decryptPrivateKey(encrypted, password);
    Arrays.fill(password, '\0');                            // пароль больше не нужен

Контейнер без `MacData` отклоняется. Для контейнера из доверенного
источника есть явный режим `GostPkcs12Loader.MacPolicy.ALLOW_MISSING` и
настраиваемый порог итераций, но целостность в нём не гарантируется:
пара «ключ + сертификат» может быть самосогласованной у любого, кто
знает открытый ключ. Аутентичность тогда обеспечивает только внешний
якорь или закрепление сертификата.

PFX, созданные версиями 0.6.0—0.7.1 и промежуточными сборками 0.8.0,
содержат в `MacData` OID HMAC (`1.2.643.7.1.1.4.2` вместо хэша
`1.2.643.7.1.1.2.3`) и не соответствуют RFC 9548. Их не читают КриптоПро
и OpenSSL, а `GostPkcs12Loader` отвергает их с просьбой перевыпустить
контейнер. Две версии библиотеки в одном приложении не уживутся (пакеты
совпадают), поэтому перевыпуск идёт в два шага. Прежней версией
загрузите PFX и выгрузите ключ в зашифрованный PKCS#8
(`GostPbes2.encryptKey`), а сертификат в PEM
(`GostCertificate.toPem()`). Затем новой версией расшифруйте ключ
(`GostPkcs12Loader.decryptPrivateKey`), прочитайте сертификат
(`GostCertificate.fromPemOrDer`) и соберите PFX через
`GostPkcs12Builder`.

## Доверие: `TrustAnchors` и `ChainValidator`

Цепочка проверяется по RFC 5280: подписи, согласованность имён,
`BasicConstraints`, `pathLen`, `KeyUsage`, сроки, `NameConstraints`.
Результат ошибки — `PkixException` с причиной `Reason`. TLS-специфики в
`ChainValidator` нет: преобразование причины в alert делает вызывающий
слой.

    TrustAnchors anchors = TrustAnchors.ofCertificates(rootCert);     // можно несколько, можно промежуточный

    // Метод возвращает эффективную цепочку: [leaf, ..., якорь]
    List<GostCertificate> effective = ChainValidator.validateChain(peerChain, anchors);

    // Дополнительно: сертификат leaf обязан содержать политику (или anyPolicy)
    List<GostCertificate> withPolicy =
            ChainValidator.validateChain(peerChain, anchors, GostOids.POLICY_KC1);

Какую фабрику брать: `TrustAnchors.ofCertificate(root)` для одного якоря
(самый частый случай), `ofCertificates(a, b)` для нескольких известных
заранее, `ofCertificates(list)` для списка, собранного в коде, например
из хранилища. Результат у всех трёх одинаков.

Верхний сертификат присланной цепочки считается якорем только при
побайтовом равенстве DER сертификату из `TrustAnchors`: совпадения
открытого ключа недостаточно. Иначе он обязан быть выпущен локальным
якорем. Всё, что пир прислал выше якоря, игнорируется; сохранённый
сертификат якоря добавляется в конец. Поэтому перевыпущенный корень с
тем же ключом и другим DER не ломает проверку, а `pathLen` и
`NameConstraints` корня действуют, даже если пир корень не прислал.
Закреплять можно и промежуточный УЦ, и конечный сертификат. Пустой набор
якорей — ошибка вызова (`IllegalArgumentException`).

Срок якоря при нескольких сертификатах в цепочке задаётся политикой
набора:

    TrustAnchors strict = anchors.withExpiryPolicy(AnchorExpiryPolicy.REJECT);

- `DEFAULT` — решает потребитель: общая проверка цепочки и TLS трактуют
  как `WARN`, CMS и CAdES —  как `REJECT`.

- `WARN` — срок якоря не проверяется (RFC 5280 §6.1), истёкший якорь
  даёт предупреждение в журнал.

- `REJECT` — истёкший якорь отклоняется (`Reason.EXPIRED`).

Если якорь — единственный сертификат (закреплённый конечный), его срок
проверяется как у обычного при любой политике.
`anchors.fingerprint()` — стабильный отпечаток набора (используется для
привязки PSK-билетов в TLS).

`CertificatePolicies` проверяются только у конечного сертификата, без
`PolicyMappings`, `PolicyConstraints` и `InhibitAnyPolicy`: для полной
обработки по RFC 5280 §6.1 нужен внешний валидатор. `directoryName` в
`NameConstraints` сравнивается по префиксу RDN, полный RFC 4518 не
выполняется.

Сборка цепочки из неупорядоченного пула и разбор неполных присланных
цепочек:

    List<GostCertificate> chain = CertChainBuilder.buildChain(
            leafCert, intermediatePool, List.of(rootCert));       // [leaf, inter, root]

Причины отказа: `INCOMPLETE_CHAIN`, `CHAIN_LOOP`, `CHAIN_TOO_LONG`,
`ROOT_NOT_TRUSTED`, `ROOT_NOT_SIGNED` и остальные из справочника причин
отказа в конце документа.

## Отзыв сертификатов

Статус сертификата определяют CRL (списки отзыва) или OCSP. Оба
документа публичные: нужен только сертификат УЦ. Решение «не отозван»
принимайте через `CrlVerifier.verify` и `OcspVerifier.verify`: они
проверяют подпись, срок, издателя и **область** списка. Разбор `GostCrl`
без них область не проверяет.

### CRL: выпуск

`nextUpdate` обязателен: CRL без него не устаревает и проверяющая
сторона его не примет (`NEXT_UPDATE_MISSING`); выпуск без него разрешает
только явный `withoutNextUpdate()`. Методы `nextUpdateDays`,
`nextUpdateMonths` и `nextUpdateYears` отсчитывают от `thisUpdate`,
поэтому вызываются после него.

    // Дата отзыва -- строка GeneralizedTime (момент в прошлом)
    RevokedEntry entry = new RevokedEntry(revokedCert.getSerialNumber(),
            "20260701120000Z", ReasonCode.KEY_COMPROMISE,
            null,   // invalidityDate
            null);  // certificateIssuer (для indirect CRL)

    byte[] crlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
            .thisUpdateNow().nextUpdateDays(7)
            .withCrlNumber(1)                  // монотонный номер (RFC 5280 §5.2.3)
            .withAki(caCert.getSubjectKeyIdentifier())   // SKI сертификата УЦ
            .addRevoked(entry)
            .sign(caKey);

Прочее: `withIdpExtension(onlyUser, onlyCa)` — область
(`IssuingDistributionPoint`), `withFreshestCrl(uri)` — адрес delta CRL,
`withAki(PublicKeyParameters)` — идентификатор ключа подписанта.
Значение берётся из SKI сертификата УЦ, поэтому УЦ выпускают с `.ski()`:
у сертификата без этого расширения `getSubjectKeyIdentifier()` даёт
`null`, а `withAki(null)` расширение молча не пишет. Если сертификата УЦ
под рукой нет, AKI считается из ключа: `withAki(caPublicKey)`.

`thisUpdateNow()` отодвигает `thisUpdate` на 5 минут назад (запас на
расхождение часов). Для CRL, который войдёт в CAdES-X Long и должен быть
не старше подписи, задавайте `thisUpdate(Instant.now())`.

### CRL: проверка

    // PkixException, если сертификат отозван, CRL невалиден или не покрывает сертификат
    CrlVerifier.verify(crlDer, leafCert, caCert);         // leafCert в списке нет: проверка проходит
    CrlVerifier.verify(crlDer, revokedCert, caCert);      // PkixException, причина REVOKED

    // Защита от отката: cRLNumber не ниже ранее принятого (здесь у crlDer номер 1). Если номер
    // ниже, PkixException ("cRLNumber downgrade")
    CrlVerifier.verify(crlDer, leafCert, caCert, BigInteger.ONE);

Метод принимает сертификат издателя `caCert`, а не его ключ: оттуда
берутся и ключ проверки подписи, и право подписывать CRL. Если у
издателя есть `KeyUsage`, в нём обязан быть бит `cRLSign`, иначе
`MISSING_CRL_SIGN` — на всех путях проверки. Область CRL
(`IssuingDistributionPoint`, RFC 5280 §5.2.5):

- `onlyContainsUserCerts` покрывает только не-УЦ сертификат,
  `onlyContainsCACerts` — только УЦ;

- `distributionPoint` обязан совпасть точной строкой с `CDP`
  сертификата;

- `onlySomeReasons`, `onlyContainsAttributeCerts`,
  `nameRelativeToCRLIssuer` и indirect CRL не поддерживаются:
  `IDP_NOT_SUPPORTED`;

- запись об отзыве в подписанном CRL определяет `REVOKED` независимо от
  области;

- пустой `IssuingDistributionPoint` означает полный CRL.

Неизвестное critical-расширение, повтор расширения, хвост данных и
кривое значение известного расширения дают отказ. `cRLNumber`
неотрицателен и занимает до 20 октетов.

### Делегированный CRL-подписант

УЦ может доверить подпись CRL отдельному ключу: сертификат подписанта
выпускается с `cRLSign` в `KeyUsage` (отсутствие `KeyUsage` для
делегата — не разрешение). CRL подписывается ключом подписанта, а
проверяющему передаются сертификаты подписантов как DER-байты:

    byte[] delegatedCrlDer = GostCrlBuilder.create(caCert.getSubjectDnBytes())
            .thisUpdateNow().nextUpdateDays(7).withCrlNumber(7)
            .sign(crlSignerKey);

    CrlVerifier.verifyDelegated(delegatedCrlDer, leafCert, caCert,
            List.of(crlSignerCert.getEncoded()));

`crlDer` в остальных примерах — CRL, выпущенный самим УЦ (`caKey`);
`CrlVerifier.verify` и `authenticate` отвергнут CRL, подписанный
делегатом (`signature verification failed`), только `verifyDelegated`
принимает.

Список подписантов должен быть доверенным. Метод не связывает `subject`
подписанта с издателем CRL и не проверяет отзыв самого подписанта: это
остаётся на вызывающем. Такая схема не равна indirect CRL по RFC 5280
§5.1.2.3.

### Delta CRL

Delta CRL содержит изменения относительно базового. При проверке списки
склеиваются: запись delta перекрывает запись base, а `REMOVE_FROM_CRL`
снимает отзыв.

    byte[] baseCrl = GostCrlBuilder.create(caCert.getSubjectDnBytes())
            .thisUpdateNow().nextUpdateDays(30).withCrlNumber(1)
            .addRevoked(entry)
            .sign(caKey);

    byte[] deltaCrl = GostCrlBuilder.create(caCert.getSubjectDnBytes())
            .thisUpdateNow().nextUpdateDays(1)
            .withCrlNumber(2)
            .withDeltaCrlIndicator(1)          // номер базового CRL; delta снимает отзыв revokedCert
            .addRevoked(new RevokedEntry(revokedCert.getSerialNumber(), "20260801120000Z",
                    ReasonCode.REMOVE_FROM_CRL, null, null))
            .sign(caKey);

    CrlVerifier.verify(baseCrl, deltaCrl, revokedCert, caCert);   // отзыв снят: проверка проходит

Номер базового CRL должен совпасть с `deltaCRLIndicator`, `thisUpdate`
delta не раньше `thisUpdate` base, область и `IDP` у обоих совпадают.
Delta CRL нельзя проверять изолированно (`DELTA_CRL_NOT_SUPPORTED`).

### Один разбор CRL на много сертификатов: `authenticate`

Для CRL крупного УЦ подпись и разбор записей дороги. `authenticate`
делает их один раз и возвращает неизменяемый `VerifiedCrl`; каждая
проверка сертификата идёт по готовому объекту (прямой полный CRL).

    VerifiedCrl verifiedCrl = CrlVerifier.authenticate(crlDer, caCert, CrlLimits.DEFAULT);

    // Для каждого проверяемого сертификата: срок CRL, издатель, номер, запись об отзыве, область
    verifiedCrl.verifyFor(leafCert, caCert, null);       // null -- нижней границы номера нет
    long retained = verifiedCrl.getEstimatedBytes();     // оценка удерживаемой памяти для кэша

### Разбор — `GostCrl`

`GostCrl` читает структуру без решений о доверии. Данные записей
(`getRevokedCertificates`, `isRevoked`, `getReason`) доступны только
после `verify(caKey)` и до него бросают `IllegalStateException`.
Расширения (`getCrlNumber`, `getAuthorityKeyIdentifier`, `isIdp`,
`isFreshestCrl`) до `verify` молча возвращают `null` или `false`,
поэтому `isIdp() == false` до проверки ничего не значит.

    GostCrl crl = GostCrl.fromPemOrDer(bytes);
    Instant nextUpdate = crl.getNextUpdate();         // доступно сразу
    Instant thisUpdate = crl.getThisUpdate();

    crl.verify(caCert.getPublicKey());                // подпись, срок, форма; PkixException при ошибке
    BigInteger number = crl.getCrlNumber();
    boolean delta = crl.isDelta();
    String[] deltaUris = crl.getFreshestCrlUris();
    for (RevokedEntry e : crl.getRevokedCertificates()) {
        System.out.println(e.revocationDate() + " " + e.reason());
    }

Прочие геттеры: `getAuthorityKeyIdentifier()`, `isIdp()`,
`isOnlyContainsUserCerts()`, `isOnlyContainsCACerts()`,
`isIndirectCrl()`, `getReason(serial)`, `toPem()`. Без разбора всего
списка: `CrlVerifier.extractNextUpdate(crlDer)` и
`CrlVerifier.extractCrlNumber(crlDer)`.

Пределы — неизменяемый `CrlLimits(maxSize, maxRevokedEntries)` (по
умолчанию 64 МиБ и 1 000 000 записей). Один и тот же объект принимают
`GostCrl`, `CrlVerifier`, `ChainValidator`,
`VerifyOptions.crlLimits(...)` и CAdES-X Long. Превышение даёт
`CRL_LIMIT_EXCEEDED`: это отказ для всех сертификатов УЦ, а не «адрес
недоступен». CRL ФНС (829 548 записей, 38,9 МиБ) занимает 83% предела по
записям; крупный CRL требует кучи порядка 825 МБ при разборе.

    CrlLimits limits = CrlLimits.DEFAULT.withMaxRevokedEntries(2_000_000).withMaxSize(128 << 20);
    CrlVerifier.verify(crlDer, leafCert, caCert, null, limits);

Для TLS пределы задаются в `GostSslBuilder` (см. README модуля
`crypto-gost-jsse`).

### OCSP: ответ и проверка

    byte[] ocspDer = GostOcspResponseBuilder.create(leafCert.getSerialNumber())
            .issuerDn(caCert.getSubjectDnBytes())
            .good()
            .sign(caKey);                      // nextUpdate по умолчанию -- через 3 года

    // Статусы: .good(), .revoked("20260701120000Z", ReasonCode.KEY_COMPROMISE), .unknown()
    // Без nextUpdate: .noNextUpdate() -- тогда свежесть задаёт maxOcspAgeMs проверяющего

    OcspVerifier.verify(ocspDer, leafCert.getSerialNumber(), caCert);   // PkixException при отзыве

CertID (`issuerNameHash`, `issuerKeyHash`) вычисляется из сертификата УЦ
автоматически. Длина хэша берётся из самой записи ответа (Стрибог-256
или Стрибог-512) и не обязана совпадать с размером ключа УЦ;
`certIdHashLen(32|64)` в строителе задаёт её явно. Идентификатор
респондера: `withResponderByKey()` (хэш ключа, компактнее) вместо
принятого по умолчанию `byName`; для 512-битного
ключа — `withResponderByKey(GostOids.STREEBOG_512_HASH_LEN)`.

Свежесть и защита от повтора:

    // Запрос с nonce, ответ обязан его вернуть
    GostOcspRequestBuilder reqBuilder = GostOcspRequestBuilder.create()
            .targetCert(leafCert.getEncoded())
            .issuerCert(caCert.getEncoded());
    byte[] requestDer = reqBuilder.build();
    byte[] nonce = reqBuilder.getNonce();

    // ... запрос уходит респондеру, ответ приходит обратно ...
    byte[] ocspDer = GostOcspResponseBuilder.create(leafCert.getSerialNumber())
            .issuerDn(caCert.getSubjectDnBytes())
            .nonce(nonce)
            .good()
            .sign(caKey);

    // Nonce и предел возраста thisUpdate (Р 1323565.1.059-2024, п. 5.3)
    OcspVerifier.verify(ocspDer, leafCert.getSerialNumber(), caCert,
            nonce, GostOids.MAX_OCSP_AGE_MS, Duration.ofDays(7));

Nonce — от 1 до 32 байт (RFC 8954); ответ без nonce при запрошенном
nonce отвергается. Предел `maxThisUpdateAge` необязателен (значение
`null` выключает его); он действует на все ответы, без
`nextUpdate` — меньший из него и `maxOcspAgeMs`.

### Делегированный OCSP-респондер

Если ответы подписывает не сам УЦ, сертификат респондера выпускается с
EKU `id-kp-OCSPSigning` и расширением `id-pkix-ocsp-nocheck` (RFC 6960
§4.2.2.2.1): проверяющий не проверяет отзыв самого респондера, иначе
возникла бы циклическая зависимость.

    GostCertificate responderCert = GostCertificateBuilder.create(params, "CN=OCSP Responder,O=MyOrg,C=RU")
            .publicKey(responderKp.getPublic())
            .issuerDn(caCert.getSubjectDnBytes())
            .notBeforeNow().validForDays(2)                   // короткий срок
            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
            .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)      // обязательно вместе с nocheck
            .ocspNoCheck()
            .randomSerial()
            .sign(caKey);

    // Ответ подписан ключом респондера, но CertID считается по ключу УЦ
    byte[] delegatedOcspDer = GostOcspResponseBuilder.create(leafCert.getSerialNumber())
            .issuerDn(caCert.getSubjectDnBytes())
            .caPublicKey(caCert.getPublicKey())               // без него CertID не совпадёт
            .withDelegatedCerts(responderCert.getEncoded())
            .good()
            .sign(responderKey);

    OcspVerifier.verify(delegatedOcspDer, leafCert.getSerialNumber(), caCert);

Сертификат с `ocspNoCheck` практически нельзя отозвать (клиенты его
отзыв не проверяют), поэтому выдают его на сутки-двое. Без
`.caPublicKey(...)` ответ делегата получит неверный `issuerKeyHash` и
будет отвергнут.

Для редких сценариев (смена ключа УЦ с действующим кросс-сертификатом)
перегрузки
`OcspVerifier.verify(..., certIdIssuer, responderAuthority, ...)`
разделяют роли: источник CertID и authority подписи ответа. Authority
обязан цепляться к истинному издателю листа криптографически.

### OCSP: разбор ответа и запроса

    GostOcspResponse ocsp = GostOcspResponse.fromDer(ocspDer);
    boolean ok = ocsp.isSuccessful();
    Instant producedAt = ocsp.getProducedAt();
    Instant nextUpdate = ocsp.getNextUpdate();
    byte[] responseNonce = ocsp.getNonce();
    for (SingleOcspResponse sr : ocsp.getResponses()) {
        Instant thisUpdate = sr.thisUpdate();
        Instant responseNextUpdate = sr.nextUpdate();      // может быть null
        String status = sr.isGood() ? "good" : sr.isRevoked() ? "revoked" : "unknown";
    }
    List<byte[]> delegated = ocsp.getDelegatedCertificates();
    if (ocsp.getResponderIdType() == GostOcspResponse.ResponderIdType.BY_KEY) {
        byte[] keyHash = ocsp.getResponderKeyHash();       // Стрибог-хэш SPKI подписанта
    }
    ocsp.verify(caCert.getPublicKey());      // подпись ответа УЦ; ответ делегата -- ключом responderCert
    boolean signatureVerified = ocsp.isSignatureVerified();

    GostOcspRequest request = GostOcspRequest.fromDer(requestDer);
    for (CertId id : request.getCertIds()) {
        byte[] requested = id.serialNumber();
        byte[] nameHash = id.issuerNameHash();
        byte[] keyHash = id.issuerKeyHash();
    }
    byte[] requestNonce = request.getNonce();
    if (request.isSigned()) {
        request.verifySignature(requestorCert.getPublicKey());
        boolean requestSignatureVerified = request.isSignatureVerified();
    }

Несколько сертификатов в одном запросе: `addRequest(target, issuer)`;
хэш Стрибог-512 — `hashLen(64)`; подпись запроса (RFC
9215) — `signKey(requestorKey).params(params)`.

### Соответствие Р 1323565.1.059-2024 и ограничения

Алгоритм хэша CertID берётся из записи ответа; запись выбирается по
серийному номеру и полному CertID. Статус ответа (допустимы 0, 1, 2, 3,
5, 6) и версия запроса и ответа (только v1) проверяются строго. Любой
искажённый ответ даёт только `PkixException`. Ограничения:

- `ResponderID` byKey: библиотека строит и сверяет хэш Стрибог-256 или
  Стрибог-512, а норма (п. 7.3.3.3) требует SHA-1. Ответы сторонних
  служб с 20-байтным byKey принимаются без сверки (подпись проверяется
  раньше конкретным ключом, `ResponderID` доверия не создаёт); остальные
  длины отвергаются. Построитель SHA-1 не выпускает.

- `byName` с подписантом не сверяется.

- Ответ со старым `thisUpdate` и далёким `nextUpdate` принимается, пока
  не задан `maxThisUpdateAge`.

- `signatureAlgorithm` и неизвестные critical-расширения не проверяются;
  `UTCTime` в `thisUpdate` проверяется нестрого.

- `issuerNameHash` считается от subject издателя; `hashAlgorithm`
  запроса пишется с параметром NULL.

- Построитель ответа выпускает одну запись и не строит ответы-ошибки и
  extended-revoke.

### Цепочка вместе с отзывом

`validateChainWithRevocation` проверяет цепочку и статус отзыва её
сертификатов за один вызов. Данные отзыва идут параллельно присланной
цепочке: на каждый сертификат — `CertRevocationData` с OCSP-ответом
(приоритет по RFC 5280) или CRL. Для якоря данные не нужны.

    // Якорь -- издатель листа (промежуточный УЦ); присланная цепочка без якоря: один сертификат -- одна запись.
    // Якорь-корень потребовал бы прислать и промежуточный УЦ (и данные отзыва для него)
    TrustAnchors issuerAnchor = TrustAnchors.ofCertificate(interCert);
    ChainValidator.validateChainWithRevocation(
            List.of(leafCert), issuerAnchor,
            List.of(new CertRevocationData(ocspDer, null)));      // либо (null, crlDer)

Метод принимает ответ делегированного OCSP-респондера (сертификат
читается из ответа), но не поддерживает делегированного подписанта CRL,
delta CRL и проверку nonce: для них используйте `CrlVerifier` и
`OcspVerifier` напрямую.

`null` вместо записи пропускает проверку отзыва для этого сертификата (в
журнал пишется предупреждение, ошибки нет). Не используйте `null`, если
сертификат не якорь.

Для CAdES-X Long доказательства проверяет
`validateChainWithRevocationEvidence`: каждому сертификату ниже якоря
нужно хотя бы одно доказательство (`CertRevocationEvidence` с CRL и
OCSP-ответами), отзыв или `unknown` в любом из них отклоняет подпись, а
свежесть считается в окне
`RevocationEvidenceWindow(signingTime, collectionTime)` по политике
`RevocationFreshnessPolicy`: `STRICT` (по умолчанию) требует, чтобы
`thisUpdate` был не раньше подписи с допуском 5 минут на расхождение
часов, `ETSI_DEFAULT` — свежести на момент сбора. Метод возвращает
доказательства, реально прошедшие проверку.

    // peerChain = [leafCert], якорь -- его издатель (interCert); доказательства параллельны цепочке;
    // crlDer -- CRL самого УЦ, не делегата; signingTime -- момент подписи (Instant). При STRICT
    // thisUpdate не раньше подписи с допуском 5 минут: CRL с thisUpdateNow() (на 5 минут назад)
    // не пройдёт при signingTime = сейчас, но пройдёт при signingTime на минуту раньше
    List<CertRevocationEvidence> checked = ChainValidator.validateChainWithRevocationEvidence(
            List.of(leafCert), TrustAnchors.ofCertificate(interCert),
            List.of(new CertRevocationEvidence(List.of(crlDer), List.of())),
            new RevocationEvidenceWindow(signingTime, Instant.now()),
            RevocationFreshnessPolicy.STRICT,
            List.of());                      // недоверенные кандидаты в респондеры

## CMS SignedData — подпись и проверка

Подпись не раскрывает закрытый ключ, результат `build()` — DER-байты, их
можно свободно передавать.

    byte[] signed = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(signerKey, signerCert)
            .addCertificate(interCert)             // встроить промежуточные сертификаты
            .build();

    VerifiedSignedData result = CmsSignedDataVerifier.verify(signed,
            VerifyOptions.trusting(TrustAnchors.ofCertificates(rootCert),
                    SignerSelection.ANY, Revocation.none()));   // отзыв не проверяется: см. «Безопасность»
    byte[] original = result.data();
    GostCertificate signer = result.signerCertificate();

Здесь и в примерах ниже `Revocation.none()` оставлен ради краткости: в
боевой проверке отзыв задаётся явно (разделы «Отзыв сертификатов»,
«Проверка отзыва подписанта» и «Безопасность и небезопасные пути»).

Все варианты проверки задаёт `VerifyOptions`; единственный входной
метод — `CmsSignedDataVerifier.verify(der, options)`.

- `VerifyOptions.trusting(anchors, signers, revocation)` — подпись,
  цепочка до якорей, срок и отзыв по политике; выбор подписантов и
  политику отзыва забыть нельзя. Якорем может быть закреплённый конечный
  сертификат, промежуточный или корневой; корень без промежуточного в
  контейнере даёт `INCOMPLETE_CHAIN`.

- `SignerSelection.ANY` — хотя бы один валидный подписант (подписант с
  битой подписью, недоверенной цепочкой или отзывом пропускается);
  `ALL` — проверку должны пройти все.

- `.detached(content)` — проверка detached-подписи;
  `.untrustedCandidates(certs)` — пул недоверенных сертификатов для
  поиска подписанта; `.crlLimits(limits)` — пределы CRL.

- Для единственного подписанта удобны `signer()`, `signerCertificate()`,
  `unsignedAttributes()`; при нескольких подписантах они бросают
  `IllegalStateException`, и надо брать `signers()`.

Если у сертификата подписанта задан `KeyUsage`, он обязан содержать
`digitalSignature` или `nonRepudiation`, иначе проверка завершается
`POLICY_VIOLATION`. Ключом УЦ с `keyCertSign` и `cRLSign` документы
поэтому не подписывают.

Срок якоря: `DEFAULT` в `TrustAnchors` в CMS трактуется как `REJECT`;
явная политика (`WARN`) сохраняется.

### Detached-подпись

Данные хранятся отдельно от подписи. Режимы не смешиваются:
attached-подпись с `.detached(...)` и detached-подпись без него
отвергаются.

    byte[] signed = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(signerKey, signerCert)
            .detached(true)
            .build();

    VerifiedSignedData result = CmsSignedDataVerifier.verify(signed,
            VerifyOptions.trusting(anchors, SignerSelection.ANY, Revocation.none())   // см. «Безопасность»
                    .detached(data));

### Проверка отзыва подписанта — `Revocation`

Политика задаётся третьим аргументом `VerifyOptions.trusting`. CRL
берутся из контейнера и из переданного списка; проверка идёт через
`CrlVerifier`.

    // Подписант -- leafCert от промежуточного УЦ; якорь -- промежуточный УЦ, поэтому CRL нужен только
    // для листа. При якоре-корне CRL нужен и для промежуточного УЦ (его выпускает корень).
    TrustAnchors anchors = TrustAnchors.ofCertificates(interCert);

    byte[] signed = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(leafKey, leafCert)
            .addCrl(GostCrl.fromDer(crlDer))       // встроить CRL: проверка офлайн
            .build();

    // Обязательна: нет подходящего CRL -> PkixException(REVOCATION_STATUS_UNKNOWN)
    VerifyOptions required = VerifyOptions.trusting(anchors, SignerSelection.ANY,
            Revocation.required(List.of()));       // List.of(): только встроенные CRL

    // Внешние CRL, например из кэша
    VerifyOptions external = VerifyOptions.trusting(anchors, SignerSelection.ANY,
            Revocation.required(List.of(GostCrl.fromDer(cachedCrlDer))));

    // Лучшее из возможного: нет CRL -> предупреждение в журнал, подписант проходит
    VerifyOptions soft = VerifyOptions.trusting(anchors, SignerSelection.ANY,
            Revocation.ifAvailable(List.of()));

Политики: `none()` — отзыв не проверяется; `required(crls)` — для
каждого сертификата ниже якоря должен найтись подходящий CRL;
`ifAvailable(crls)` — проверка выполняется, если CRL найден. Режим
«лучшее из возможного» выбирается только явно. CRL с совпавшим issuer
ищется сначала среди встроенных, потом среди внешних; найденный, но
невалидный (просрочен, битая подпись) — отказ. Delta CRL, CRL с
неизвестным critical-расширением и CRL, не покрывающий сертификат,
пропускаются, ищется следующий. При `ANY` отозванный подписант
отбрасывается и пробуется следующий, при `ALL` отзыв — отказ. Размер
встроенного CRL и их число ограничены (`MAX_EMBEDDED_CRLS`,
`MAX_EMBEDDED_CRLS_TOTAL_SIZE` в `CmsConstants`); полный CRL крупного УЦ
передают как внешний. Встроенные CRL доступны и после проверки:

    VerifiedSignedData verified = CmsSignedDataVerifier.verify(signed, required);
    List<GostCrl> embedded = verified.embeddedCrls();

Поддерживается только выбор `crl` из `RevocationInfoChoice`; OCSP-ответы
в `other` не принимаются.

### Атрибуты и параметры подписи

    byte[] signed = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(signerKey, signerCert)
            // До 2049 года включительно время подписи -- UTCTime (RFC 5652 §11.3): 12 цифр года-месяца-...
            // и 'Z'. DerCodec.encodeTime выбирает тег по длине строки, поэтому формат "yyMMddHHmmss'Z'"
            .addSignedAttribute(GostOids.ATTR_SIGNING_TIME,
                    DerCodec.encodeTime(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")
                            .withZone(ZoneOffset.UTC).format(Instant.now())))
            .build();

Дополнительно: `digestAlgorithm(oid)`, `contentType(oid)`,
`addUnsignedAttribute(oid, value)`. Для EnvelopedData тип содержимого
меняет `CmsEnvelopedDataBuilder.encryptedContentType(oid)`.

### Контейнеры сертификатов .p7b — `GostPkcs7`

`.p7b` — SignedData без подписантов, только сертификаты (и CRL): способ
обмена цепочками. Эквивалентная сборка вручную:
`CmsSignedDataBuilder.create().certsOnly().addCertificate(...).build()`.

    byte[] p7b = GostPkcs7.buildCertsOnly(leafCert, interCert, rootCert);
    byte[] withCrl = GostPkcs7.buildCertsOnly(List.of(crl), leafCert, interCert);

    List<GostCertificate> certs = GostPkcs7.extractCertificates(p7b);       // DER или PEM
    List<GostCertificate> few = GostPkcs7.extractCertificates(p7b, 16);     // свой потолок числа

    String report = GostPkcs7.formatText(p7b);                              // отчёт для человека
    String certReport = CertificateTextFormatter.format(cert);

`extractCertificates` только разбирает DER: подпись, цепочка, срок и
отзыв не проверяются. Потолки `MAX_P7B_CERTS` (256) и `MAX_P7B_SIZE` (10
МиБ) защищают от чрезмерного входа. Порядок сертификатов не сохраняется
(DER `SET OF` сортируется). Вывод `formatText` предназначен для экрана;
`toString()` компактен и безопасен для журналов.

## CMS EnvelopedData — шифрование

Данные шифруются на случайном ключе (Кузнечик CTR-ACPKM), ключ для
каждого получателя вычисляется через VKO ГОСТ Р 34.10-2012 и
оборачивается KExp15 (RFC 9189 §8.2.1). По умолчанию
формат — `KeyTransRecipientInfo` (ТК26 §8.2.1, совместим с КриптоПро
5.0), содержимое защищено имитовставкой (OMAC, атрибут `content-mac`).
Ключ шифрования и IV затираются сразу после использования. Обёртывание
ключа фиксировано `KExp15`; `CmsKeyWrap`/`Kexp15CmsKeyWrap` — внутренняя
деталь, а не точка расширения: метода `.keyWrap()` в строителе нет.

    byte[] enveloped = CmsEnvelopedDataBuilder.create()
            .data(data)
            .addRecipient(aliceCert)
            .addRecipient(bobCert)             // данные шифруются один раз, ключ -- для каждого получателя
            .build();

    // Каждый расшифровывает своим ключом; MAC проверяется автоматически
    byte[] plain = CmsEnvelopedDataDecryptor.decrypt(enveloped, aliceKey, aliceCert);

Контейнер, изменённый после шифрования, не проходит проверку
имитовставки: `PkixException`. Для `KeyAgreeRecipientInfo` (ТК26 §8.2.2)
есть фабрика `CmsEnvelopedDataBuilder.createKari()`; остальные методы те
же.

Назначение ключа получателя проверяется при `addRecipient`. Сертификат
без KeyUsage допускается; если KeyUsage есть, в нём должен быть
`keyEncipherment`, `keyAgreement` или `dataEncipherment` (в
`KeyTransRecipientInfo` и в `KeyAgreeRecipientInfo` одинаково), как у
КриптоПро CSP 5.0. Сертификат только для подписи отвергается с
`IllegalArgumentException`, в тексте которой только серийный номер, без
DN. Это мягче RFC 5652 §6.2, где бит привязан к типу `RecipientInfo`: в
ГОСТ оба режима построены на VKO, а выпускаемые УЦ сертификаты часто
несут `keyEncipherment` без `keyAgreement`. Заранее проверить сертификат
можно через `GostCertificate.isKeyUsageValidForEncryption()`. В
`CmsSignedAndEnvelopedData` получатели проверяются до подписи, поэтому
отказ не тратит обращение к ключу подписанта.

Шифр содержимого проверяется до обращения к закрытому ключу; допустимы
только `kuznyechik-ctracpkm-omac` и `kuznyechik-ctracpkm`. Контейнеры с
`originatorInfo` не поддерживаются. `decrypt` отказывает контейнеру без
имитовставки (`INTEGRITY_REQUIRED`): иначе замена OID шифра с удалением
`content-mac` превратилась бы в успешную расшифровку с мусором.

Режим без имитовставки нужен только для обмена с узлами, которые её не
принимают. Контейнеры 0.7.x (по умолчанию без имитовставки) читаются в
0.8.0 только так:

    byte[] enveloped = CmsEnvelopedDataBuilder.create().data(data)
            .addRecipient(recipientCert).withoutIntegrity().build();
    byte[] plain = CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(enveloped, key, recipientCert);

### Подпись и шифрование вместе — `CmsSignedAndEnvelopedData`

- **sign-then-encrypt** — подпись внутри конверта: подписант скрыт от
  внешнего наблюдателя.

- **encrypt-then-sign** — конверт внутри подписи: авторство проверяется
  без расшифрования.

Обе операции stateless: ключевой материал не сохраняется, хелпер
содержит только статические методы.

    byte[] combined = CmsSignedAndEnvelopedData.signThenEncrypt(
            data, signerKey, signerCert, aliceCert, bobCert);          // несколько получателей

    VerifiedSignedData result = CmsSignedAndEnvelopedData.decryptAndVerify(
            combined, aliceKey, aliceCert, signerCert);                // signerCert -- доверенный подписант

    byte[] sealed = CmsSignedAndEnvelopedData.encryptThenSign(data, signerKey, signerCert, aliceCert);
    VerifiedSignedData opened = CmsSignedAndEnvelopedData.verifyAndDecrypt(
            sealed, aliceKey, aliceCert, signerCert);

В этих методах отзыв сертификата подписанта не проверяется (зашито
`Revocation.none()`), а контейнер без имитовставки принимается:
целостность обеспечивает подпись. Если отзыв важен, подписывайте и
шифруйте отдельно: `CmsSignedDataBuilder`, затем
`CmsEnvelopedDataBuilder`, и проверяйте через
`VerifyOptions.trusting(..., Revocation.required(...))`.

## CAdES — долговременная подпись

**CAdES** (CMS Advanced Electronic Signatures, ETSI EN 319 122)
расширяет CMS стандартными атрибутами, чтобы подпись можно было
проверить спустя годы.

Сертификат ГОСТ выпускается на 12—15 месяцев. Если подпись проверяют
после истечения срока, момент подписания формально неизвестен, а ФЗ-63
ст. 11 требует достоверно установленного момента. Метка времени TSA (RFC
3161) доказывает, что подпись существовала на момент `genTime`;
сертификат подписанта проверяется на этот момент, а не на текущую дату.

Лестница уровней:

- **CAdES-BES** — SignedData плюс `signingCertificateV2`: подпись
  связана с конкретным сертификатом, но момент подписания ещё не
  доказан.

- **CAdES-T** — BES плюс метка времени `signature-time-stamp` от службы
  TSA (RFC 3161): доказывает существование подписи на `genTime`.

- **CAdES-C** — T плюс `complete-certificate-references` и
  `complete-revocation-references`: фиксирует, что нужно для полной
  проверки, но не встраивает значения и не проверяет отзыв.

- **CAdES-X Long Type 1** — C плюс встроенные значения сертификатов и
  отзыва и метка `escTimeStamp`: проверка без внешних источников,
  отозванный сертификат отклоняется.

### CAdES-BES

    byte[] cadesBes = CmsSignedDataBuilder.create()
            .data(data)
            .addSigner(signerKey, signerCert)
            .withCAdES()                       // signingCertificateV2: Стрибог-256 или -512 по ключу
            .build();

    VerifiedCAdESData result = CAdESVerifier.verifyBES(cadesBes, anchors);   // все подписанты; detached: verifyBESDetached

`verifyBES` и `verifyT` проверяют всех подписантов и
`signingCertificateV2` (отказ при несоответствии). Проверка уровня не
оценивает атрибуты старших уровней: подпись, к которой позже добавили
метку, по-прежнему проходит `verifyBES`, а список меток в результате
пуст.

Все методы `CAdESVerifier` принимают `TrustAnchors`; пустой
набор — `IllegalArgumentException`. Политика срока `DEFAULT` трактуется
как `REJECT`, явная (`WARN`) действует для подписи и цепочек значений.
Цепочка TSA всегда проверяется со строгим `REJECT`: доказательство
времени не ослабляется.

### TSP: метки времени

Приложение вычисляет хэш подписи и отправляет `TimeStampReq`; служба TSA
возвращает `TimeStampResp` с подписанной меткой. Ответ — публичный
документ.

    TspRequestBuilder reqBuilder = TspRequestBuilder.create()
            .messageImprint(Digest.digest256(signatureBytes), GostOids.DIGEST_256)
            .certReq(true);                    // TSA пришлёт свой сертификат
    byte[] tspReq = reqBuilder.build();        // nonce (8 байт) создаётся автоматически
    BigInteger nonce = reqBuilder.getNonce();

    TspTransport transport = new JdkHttpTspTransport();     // Android: UrlConnectionTspTransport
    byte[] tspRespDer = transport.send(tspReq, "http://tsa.example.com/tsa");

    TspResponse response = TspResponse.fromDer(tspRespDer);   // отказ TSA -> PkixException (failInfo())
    // status() -- 0 (granted) или 1 (grantedWithMods): оба случая дают действительный токен
    // Хэш, алгоритм, время, nonce, подпись TSA и её цепочка
    response.verify(Digest.digest256(signatureBytes), GostOids.DIGEST_256, nonce, tsaCert);

    String genTime = response.tstInfo().genTime();             // GeneralizedTime
    BigInteger stampSerial = response.tstInfo().serialNumber();

Отказ службы (статус rejection) приходит из `fromDer` исключением
`PkixException` с `failInfo()` и текстом; `grantedWithMods` отказом не
считается: токен действителен, `status()` равен 1.

`verify` сверяет `messageImprint` за постоянное время, `genTime` (не в
будущем, допуск ±5 минут), nonce, подпись TSA и цепочку сертификатов
TSA. Передавайте nonce из запроса: `null` отключает эту сверку и защиту
от повтора ответа.

Оба транспорта держат один общий срок на запрос (по умолчанию 30 секунд;
`new JdkHttpTspTransport(Duration.ofSeconds(10))`, от 1 мс до 10 минут),
принимают ответ не больше 1 МБ с типом `application/timestamp-reply` и
сами выполняют перенаправления: `POST` следует только за 307 и 308, не
более 5 переходов, схема и внутренние адреса проверяются на каждом
переходе. Клиент, переданный в `JdkHttpTspTransport(HttpClient)`, должен
быть создан с `Redirect.NEVER`. Для прокси или mTLS реализуйте
`TspTransport`:

    TspTransport custom = (requestDer, url) -> {
        // POST на url, Content-Type: application/timestamp-query; вернуть тело ответа
        return responseBody;                    // схема
    };

### TSP: служба меток (сторона TSA)

    // В обработчике HTTP POST; requestDer -- тело запроса (схема)
    TspRequest request = TspRequest.fromDer(requestDer);
    if (!GostOids.DIGEST_256.equals(request.messageImprintAlgOid())) {
        return TspResponseBuilder.buildRejected(GostOids.PKI_FAIL_BAD_ALG);   // ответ без подписи
    }
    byte[] granted = TspResponseBuilder.create(request)
            .signer(tsaKey, tsaCert)
            .policyOid("1.3.6.1.4.1.4146.1.2.1")          // политика TSA, обязательна
            .serialNumber(BigInteger.valueOf(counter.getAndIncrement()))   // глобально уникальный
            .accuracy(1, 500)                              // 1 с и 500 мс
            .withCAdES()                                   // signingCertificateV2 в токене
            .addChainCert(interCert)                       // промежуточные сертификаты TSA
            .buildGranted();                               // отдавать как application/timestamp-reply

Есть `buildGrantedWithMods()`, `ordering(true)` и отклонения с
сообщением и кодом причины
`buildRejected("text", GostOids.PKI_FAIL_SYSTEM_FAILURE)`. Алгоритм хэша
выбирается по размеру ключа TSA.

### CAdES-T

Метка добавляется после подписания отдельным шагом (нужна сеть). Для
каждого подписанта запрашивается своя метка.

    byte[] cadesT = CAdESExtender.addTimestamp(
            cadesBes, "http://tsa.example.com/tsa", transport, tsaCert);   // tsaCert: доверенный сертификат TSA

    VerifiedCAdESData result = CAdESVerifier.verifyT(cadesT,
            TrustAnchors.ofCertificates(rootCert, tsaCert));   // якоря подписанта и TSA вместе
    for (CAdESSignerResult signer : result.signers()) {
        for (TstInfo stamp : signer.timestamps()) {
            System.out.println(signer.signerCertificate().getSubjectDn() + " " + stamp.genTime());
        }
    }

Проверяются подпись, `signingCertificateV2`, метка, цепочки подписанта и
TSA, валидность сертификата подписанта на момент `genTime`;
detached — `verifyTDetached`. Любая неудача — `PkixException`. Если
токен уже получен, метка встраивается без сети:

    byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, timeStampTokenDer);
    byte[] cadesT2 = CAdESExtender.embedTimestamps(cadesBes, List.of(token1, token2));   // по подписантам

### Контрподпись (RFC 5652 §11.4)

Третье лицо (нотариус) подписывает не документ, а подпись автора:
изменение документа ломает подпись автора, но не контрподпись, и
наоборот. Контрподпись обязательна для `verifyCountersignature` и
добавляется как к CAdES-BES, так и к CAdES-T.

    byte[] countersigned = CAdESExtender.embedCountersignature(cadesBes, notaryKey, notaryCert);

    VerifiedCAdESData result = CAdESVerifier.verifyCountersignature(countersigned, anchors);
    SignerResult notary = result.signers().get(0).countersignatures().get(0);
    GostCertificate notaryCertificate = notary.signerCertificate();

### CAdES-C

CAdES-C фиксирует **что именно** нужно для полной проверки:
`complete-certificate-references` (хэш и `IssuerSerial` каждого
сертификата цепочки, кроме подписанта и доверенного корня) и
`complete-revocation-references` (хэш CRL или OCSP-ответа и
идентификатор). Сами значения в контейнер не встраиваются, фактический
статус отзыва не проверяется.

    // chain = [подписант, промежуточный УЦ, корень] (CertChainBuilder.buildChain). Данные отзыва
    // параллельны цепочке: CRL каждого сертификата выпускает его издатель, запись корня (якоря) -- null,
    // потому что отзыв якоря не проверяется
    byte[] cadesC = CAdESExtender.embedCompleteRefs(
            cadesT, chain,
            Arrays.asList(leafCrl, interCrl, null),     // GostCrl
            Arrays.asList(null, null, null));           // GostOcspResponse, здесь их нет

    // То же через CertRevocationData
    byte[] cadesC2 = CAdESExtender.embedCompleteRefs(cadesT, chain,
            Arrays.asList(new CertRevocationData(null, leafCrlDer),
                    new CertRevocationData(null, interCrlDer), null));

    VerifiedCAdESData result = CAdESVerifier.verifyC(cadesC, anchors);
    List<CAdESCompleteData.OtherCertID> certRefs = result.signers().get(0).completeCertRefs();

`embedCompleteRefs` принимает CAdES-T или CAdES-C; CAdES-BES без метки
отклоняется. `verifyC` проверяет подпись, `signingCertificateV2`,
обязательную метку, хэши ссылок на сертификаты по встроенным и структуру
ссылок на отзыв. Сертификаты переданной цепочки автоматически
добавляются в поле `certificates` SignedData (дедупликация по DER). Он
не проверяет статус отзыва (отозванный сертификат проходит `verifyC`) и
не проверяет `escTimeStamp`: метка `escTimeStamp` (OID
`1.2.840.113549.1.9.16.2.25`) — требование уровня X Long.

### CAdES-X Long Type 1

X Long встраивает значения: `certificate-values` (сертификаты цепочки),
`revocation-values` (CRL и OCSP-ответы) и обязательную метку
`escTimeStamp` (RFC 5126 §6.3.5), которая покрывает значение подписи,
метки подписи и все ссылки. Статус отзыва проверяется при проверке
подписи, без внешних источников.

    // CRL выпущены не раньше подписи: thisUpdate(Instant.now()), а не thisUpdateNow()
    byte[] leafCrlDer = GostCrlBuilder.create(interCert.getSubjectDnBytes())
            .thisUpdate(Instant.now()).nextUpdateDays(30).withCrlNumber(1)
            .sign(interKp.getPrivate());
    byte[] interCrlDer = GostCrlBuilder.create(rootCert.getSubjectDnBytes())
            .thisUpdate(Instant.now()).nextUpdateDays(30).withCrlNumber(1)
            .sign(rootKp.getPrivate());

    // chain = [подписант, промежуточный УЦ, корень]; списки параллельны цепочке, запись корня -- null
    byte[] cadesXLong = CAdESExtender.embedXLongType1(
            cadesBes, chain,
            Arrays.asList(GostCrl.fromDer(leafCrlDer), GostCrl.fromDer(interCrlDer), null),
            Arrays.asList(null, null, null),                 // OCSP-ответы (GostOcspResponse)
            "http://tsa.example.com/tsa", transport, tsaCert);

    VerifiedCAdESData result = CAdESVerifier.verifyXLong(cadesXLong,
            TrustAnchors.ofCertificates(rootCert, tsaCert));
    // Совместимость с КриптоПро: доказательства, выпущенные до подписи
    VerifiedCAdESData lenient = CAdESVerifier.verifyXLong(cadesXLong,
            RevocationFreshnessPolicy.ETSI_DEFAULT, TrustAnchors.ofCertificates(rootCert, tsaCert));

    CAdESSignerResult signer = result.signers().get(0);
    List<GostCertificate> embeddedCerts = signer.certificateValues();
    int crlCount = signer.revocationValues().crls().size();

`embedXLongType1` принимает CAdES-BES, CAdES-T или CAdES-C: недостающие
уровни (метка, C-ссылки, `escTimeStamp`) достраиваются; для
`escTimeStamp` нужен TSP URL и транспорт. Если метка уже есть, второй
раз она не запрашивается. Существующие ссылки и значения заменяются
переданными. `contentTimestamp(url, transport, tsaCert)` в
`CmsSignedDataBuilder` добавляет метку на содержимое.

Политика свежести `STRICT` (по умолчанию) требует, чтобы доказательство
было выпущено не раньше подписи (`thisUpdate >= t_sig` с допуском 5
минут на расхождение часов); `ETSI_DEFAULT` — только свежести на момент
`escTimeStamp`. Файл КриптоПро, где промежуточный УЦ проверяется по CRL,
выпущенному до подписи, в `STRICT` отвергается
(`REVOCATION_EVIDENCE_OUT_OF_WINDOW`); для совместимости явно задайте
`ETSI_DEFAULT`. Это локальная политика библиотеки, а не требование ГОСТ
или ETSI. Пределы CRL: `verifyXLong(der, policy, anchors, limits)`.

Что проверяется и что нет:

- Обязательны `signature-time-stamp` и `escTimeStamp`; отзыв считается в
  окне между самой ранней меткой подписи и самой ранней `escTimeStamp`.

- Сертификаты из `certificate-values` и токенов меток служат только
  недоверенными кандидатами (подписанты, промежуточные УЦ TSA,
  делегированные OCSP-респондеры); якорями остаются только переданные
  сертификаты. Сертификат TSA, найденный лишь среди кандидатов, обязан
  быть назван в `signingCertificateV2` токена.

- Токен с пустым полем `certificates` и сертификатом TSA во вложенном
  `certificate-values` (форма КриптоПро) принимается; нечитаемый
  вложенный `certificate-values` приводит к отказу.

- CRL без `nextUpdate`, OCSP без `ocspRepHash`, delta и indirect CRL не
  принимаются; частичный CRL проверяется по сертификату; `revoked` или
  `unknown` в любом доказательстве отклоняет подпись.

- Не реализованы архивные метки (CAdES-A) и Type 2
  (`time-stamped-certs-crls-references`). Исторической проверки сроков
  на `genTime` нет: цепочка проверяется на текущее время. Отзыв,
  случившийся после сбора доказательств, и поздний `good`-CRL после
  снятия `certificateHold` не обнаруживаются.

- Сертификат подписанта, DER-равный якорю или покрытый ссылкой CAdES-C,
  допустим в `certificate-values`; доверенный сертификат с тем же
  ключом, но другим DER, без ссылки отклоняется.

## Продвинутое

### Подпись внешним модулем — `GostSigner` (HSM, PKCS#11)

Строители и методы подписи (`GostCertificateBuilder`, `GostCrlBuilder`,
`GostCsrBuilder`, `CmsSignedDataBuilder`, `GostOcspResponseBuilder`,
`TspResponseBuilder`, `CAdESExtender.embedCountersignature`) принимают
абстракцию подписанта `GostSigner` из `crypto-gost-core` (пакет
`org.rssys.gost.api`): строитель считает хэш и передаёт его в
`signHash(hash)`, закрытый ключ остаётся в аппаратном модуле и не
попадает в память JVM. Перегрузки с `PrivateKeyParameters` есть рядом и
делегируют через `GostSigner.of(priv)`.

    GostSigner signer = GostSigner.of(caKey);        // ключ в памяти; для HSM -- ваша реализация

    GostCertificate cert = GostCertificateBuilder.create(params, "CN=Demo,O=MyOrg,C=RU")
            .publicKey(kp.getPublic())
            .issuerDn(caCert.getSubjectDnBytes())
            .notBeforeNow().validForDays(365)
            .randomSerial()
            .sign(signer);

    byte[] crl = GostCrlBuilder.create(caCert.getSubjectDnBytes())
            .thisUpdateNow().nextUpdateDays(7).sign(signer);
    byte[] signed = CmsSignedDataBuilder.create().data(data).addSigner(signer, signerCert).build();

    // OCSP, TSP и контрподпись принимают того же подписанта:
    byte[] ocsp = GostOcspResponseBuilder.create(serial)
            .issuerDn(caCert.getSubjectDnBytes()).good().sign(signer);
    // TspResponseBuilder.create(requestDer).signer(signer, tsaCert).buildGranted();
    // CountersignatureBuilder.buildCountersignature(parentSig, signer, notaryCert, digestOid);
    byte[] countersigned = CAdESExtender.embedCountersignature(cadesDer, signer, notaryCert);

Двухшаговая сборка (хэш TBS отдельно, для кросс-проверки): `buildTbs()`
и `GostCertificateBuilder.sign(tbs, signer)`. После подписи строитель
делает проверку результата (длина и проверка открытым ключом
подписанта): неисправный адаптер HSM приводит к исключению, а не к
выпуску сертификата с невалидной подписью. Описание интерфейса — в
README модуля `crypto-gost-core`.

### Сетевые пределы

Транспорты TSP используют общие средства `org.rssys.gost.pkix.util`:
`Deadline` (один срок на весь запрос, от 1 мс до `MAX_FETCH_TIMEOUT` =
10 минут), `BoundedBodyReader` (чтение тела с пределом размера и
проверкой срока), `SsrfGuard` (отказ в адресах внутренней сети после
разрешения имени, на каждом переходе). Нарушения дают
`DeadlineExceededException` и `BodyTooLargeException` (наследники
`IOException`). Ответ службы всё равно проверяется по подписи;
остаточный риск смены ответа DNS между проверкой адреса и соединением
описан в Javadoc `SsrfGuard`.

### Кодирование GeneralNames и хэш CertID

    byte[] dnsName = GeneralNameCodec.encodeDnsName("example.com");
    byte[] ipAddr = GeneralNameCodec.encodeIpAddress("192.168.1.1");
    byte[] email = GeneralNameCodec.encodeRfc822Name("admin@example.com");
    byte[] uri = GeneralNameCodec.encodeUri("https://example.com");
    byte[] dirName = GeneralNameCodec.encodeDirectoryName(caCert.getSubjectDnBytes());
    byte[] upn = GeneralNameCodec.encodeOtherNameUpn("user@domain.ru");
    byte[] names = GeneralNameCodec.encodeGeneralNames(dnsName, ipAddr, email, uri, dirName, upn);

    byte[] nameHash = CertIdHasher.hashIssuerName(caCert, GostOids.STREEBOG_256_HASH_LEN);
    byte[] keyHash = CertIdHasher.hashIssuerPublicKey(caCert, GostOids.STREEBOG_256_HASH_LEN);

Остальные кодеки: `GostDnParser.encodeDn("CN=...,O=...,C=RU")`,
статические `build*Extension` в `GostCertificateBuilder` (для
`additionalExtensions`).

## Безопасность и небезопасные пути

- **Отказ при неоднозначности.** Любая ошибка проверки — `PkixException`
  (проверяемое исключение). Входные данные, выходящие за границы или
  предел, отвергаются, а не обрезаются.

- **Доверие только через якоря.** Подпись проверяется вместе с цепочкой
  до `TrustAnchors`; сертификат принимается по побайтовому равенству
  DER, а не по совпадению ключа.

- **Подписи.** Каждый строитель после подписи проверяет результат;
  проверка всех подписей опирается на результат `false` из ядра, без
  исключений для управления потоком.

- **Секреты.** Закрытые ключи и пароли в сообщения исключений не
  попадают. Пароль `char[]` затирайте сами
  (`Arrays.fill(password, '\0')`) после использования: библиотека
  затирает только свои копии.

- **Внешний вход.** Размеры и числа ограничены (CRL: `CrlLimits`;
  встроенные CRL: 8 штук и 32 МиБ суммарно; `.p7b`: 256 сертификатов и
  10 МиБ; ответ TSA: 1 МБ).

Режимы, которые ослабляют проверку, называются явно и в боевом коде
нужны редко:

<table>
<colgroup>
<col style="width: 42%" />
<col style="width: 57%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Вызов</th>
<th style="text-align: left;">Что ослаблено</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>VerifyOptions.signatureOnly(signers)</code></p></td>
<td style="text-align: left;"><p>проверяется только подпись: ни цепочки,
ни срока, ни отзыва</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>Revocation.none()</code>,
<code>ifAvailable(...)</code></p></td>
<td style="text-align: left;"><p>отзыв не проверяется либо проверяется
«если нашёлся CRL»</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>GostCrl.verify</code> с
<code>isRevoked</code></p></td>
<td style="text-align: left;"><p>область CRL не проверяется: «не
отозван» по ним ничего не доказывает</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>CmsEnvelopedDataBuilder.withoutIntegrity()</code>,
<code>decryptAllowingNoIntegrity</code></p></td>
<td style="text-align: left;"><p>целостность шифртекста не защищена
имитовставкой</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>CmsSignedAndEnvelopedData</code></p></td>
<td style="text-align: left;"><p>отзыв подписанта не проверяется,
контейнер без имитовставки принимается</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>GostPkcs12Loader.MacPolicy.ALLOW_MISSING</code></p></td>
<td style="text-align: left;"><p>целостность контейнера не
гарантируется</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>GostPkcs12Loader.load(..., allowJdkFallback = true)</code></p></td>
<td style="text-align: left;"><p>откат на JDK <code>KeyStore</code> для
контейнеров не на ГОСТ</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>null</code> в
<code>validateChainWithRevocation</code></p></td>
<td style="text-align: left;"><p>пропуск проверки отзыва этого
сертификата</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>null</code> nonce в
<code>TspResponse.verify</code>,
<code>OcspVerifier.verify</code></p></td>
<td style="text-align: left;"><p>сверка nonce выключена</p></td>
</tr>
</tbody>
</table>

## Логирование

Модуль пишет в `java.util.logging` под `org.rssys.gost.pkix.*` через
обёртку `GostLogger` из `crypto-gost-core`. Уровни, включение,
соответствие уровням JUL и правила о том, что не попадает в журнал,
общие для всех модулей и описаны в разделе «Логирование» файла
`crypto-gost-core/README.adoc`. Движки сетевой загрузки (`JdkHttpFetch`,
`UrlConnectionFetch`) пишут отказ на `DEBUG`: причина отказа
возвращается вызывающему значением, и запись на `WARNING` делает тот,
кто знает сертификат или адрес службы.

`WARNING` включён по умолчанию, `DEBUG` и `TRACE` нужно включать явно.
Настройка — обычная для JUL:

    Logger.getLogger("org.rssys.gost.pkix").setLevel(Level.FINE);
    for (Handler h : Logger.getLogger("").getHandlers()) {
        h.setLevel(Level.FINE);       // обработчик тоже должен пропускать FINE
    }

То же через `logging.properties`: `org.rssys.gost.pkix.level = FINE` и
`java.util.logging.ConsoleHandler.level = FINE`. На Android записи JUL
попадают в `adb logcat`; для уровней ниже `INFO` может понадобиться
`adb shell setprop log.tag.<тег> DEBUG`.

Особенности модуля:

- Ход операций (подпись, проверка, шифрование, расшифрование, загрузка
  PFX, загрузка OCSP) пишется на `DEBUG`.

- `WARNING` пишется там, где библиотека продолжает работу с ослабленной
  проверкой и оператору есть что исправить: у части цепочки нет данных
  отзыва (одна запись на проверку: сколько сертификатов пропущено и
  серийный номер листа), истёк срок якоря доверия, PKCS12 без MAC,
  делегированный сертификат ответчика OCSP без `id-pkix-ocsp-nocheck`, в
  мягком режиме нет подходящего CRL, не прошла самопроверка подписи
  внешнего подписанта, не прошла проверка подписи запроса на сертификат
  (CSR) или у службы штампов времени нет `id-kp-timeStamping`.

- Отказ, который целиком описан в исключении (несовпадение хэша,
  алгоритма или nonce штампа времени), в журнал не дублируется.
  Особенности данных другой стороны, не требующие вмешательства
  (нестрогая кодировка CRL, ограничения имён, не относящиеся к
  сертификату, лишние сертификаты в PFX), пишутся на `DEBUG`.

- Пропуск кандидата на подписанта ответа OCSP или связанного сертификата
  CAdES пишется на `DEBUG` с серийным номером и причиной: итоговое
  исключение не говорит, какой из кандидатов отброшен.

- В записях `WARNING` вместо DN стоит идентификатор без персональных
  данных: серийный номер сертификата, а для запроса на сертификат (CSR)
  отпечаток открытого ключа (`publicKeyFingerprint`: первые 8 байт
  Стрибога-256 от DER `SubjectPublicKeyInfo` запроса в шестнадцатеричной
  записи; по нему запрос находят в журнале приёма). Усечённый DN пишется
  отдельной записью `DEBUG`.

- Серийные номера и размеры данных пишутся на `DEBUG`.

## Справочник причин отказа

`PkixException.reason()` даёт `PkixException.Reason`; TLS-слой переводит
его в alert-код, не разбирая текст сообщения.

<table>
<colgroup>
<col style="width: 37%" />
<col style="width: 62%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p><code>EXPIRED</code></p></td>
<td style="text-align: left;"><p>сертификат или якорь просрочен</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ROOT_NOT_SIGNED</code></p></td>
<td style="text-align: left;"><p>цепочка не достигла доверенного якоря
(корень не подписан якорем)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>DN_MISMATCH</code></p></td>
<td style="text-align: left;"><p>несовпадение subject и issuer в
цепочке</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>NOT_CA</code></p></td>
<td style="text-align: left;"><p>сертификат не является УЦ</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>MISSING_KEY_CERT_SIGN</code></p></td>
<td style="text-align: left;"><p>у УЦ нет бита
<code>keyCertSign</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>PATH_LEN_EXCEEDED</code></p></td>
<td style="text-align: left;"><p>превышена
<code>pathLenConstraint</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ALG_MISMATCH</code></p></td>
<td style="text-align: left;"><p>несовместимые алгоритмы</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>POLICY_VIOLATION</code></p></td>
<td style="text-align: left;"><p>нарушение политики
(<code>CertificatePolicies</code>, <code>KeyUsage</code>
подписанта)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>UNKNOWN_CRITICAL_EXTENSION</code></p></td>
<td style="text-align: left;"><p>неизвестное
critical-расширение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>SIGNATURE_INVALID</code></p></td>
<td style="text-align: left;"><p>подпись недействительна</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>PARSE_ERROR</code></p></td>
<td style="text-align: left;"><p>ошибка разбора DER или ASN.1</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>THIS_UPDATE_FUTURE</code></p></td>
<td style="text-align: left;"><p><code>thisUpdate</code> в будущем (CRL,
OCSP)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>IDP_NOT_SUPPORTED</code></p></td>
<td style="text-align: left;"><p>неподдерживаемый
<code>issuingDistributionPoint</code> или CRL не покрывает
сертификат</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>DELTA_CRL_NOT_SUPPORTED</code></p></td>
<td style="text-align: left;"><p>delta CRL без базового</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>REVOKED</code></p></td>
<td style="text-align: left;"><p>сертификат отозван</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>REVOCATION_EVIDENCE_OUT_OF_WINDOW</code></p></td>
<td style="text-align: left;"><p>доказательство отзыва вне окна свежести
(CAdES-X Long)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>INCOMPLETE_CHAIN</code></p></td>
<td style="text-align: left;"><p>не найден издатель в пуле
сертификатов</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>CHAIN_LOOP</code></p></td>
<td style="text-align: left;"><p>зацикливание имён в цепочке</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>CHAIN_TOO_LONG</code></p></td>
<td style="text-align: left;"><p>превышена глубина цепочки</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>ROOT_NOT_TRUSTED</code></p></td>
<td style="text-align: left;"><p>корень не в списке доверенных</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>REVOCATION_STATUS_UNKNOWN</code></p></td>
<td style="text-align: left;"><p>нет подходящего CRL при обязательной
проверке отзыва</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>CRL_LIMIT_EXCEEDED</code></p></td>
<td style="text-align: left;"><p>размер или число записей CRL больше
предела <code>CrlLimits</code></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>NEXT_UPDATE_MISSING</code></p></td>
<td style="text-align: left;"><p>в CRL нет
<code>nextUpdate</code></p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>INTEGRITY_REQUIRED</code></p></td>
<td style="text-align: left;"><p>контейнер не защищён имитовставкой, а
она требуется</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>MISSING_CRL_SIGN</code></p></td>
<td style="text-align: left;"><p>у издателя CRL есть
<code>KeyUsage</code>, но нет <code>cRLSign</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>OTHER</code></p></td>
<td style="text-align: left;"><p>прочие ошибки</p></td>
</tr>
</tbody>
</table>

    try {
        List<GostCertificate> effective = ChainValidator.validateChain(chain, anchors);
    } catch (PkixException e) {
        switch (e.reason()) {
            case EXPIRED -> log.warn("Сертификат просрочен: {}", e.getMessage());
            case REVOKED -> log.error("Сертификат отозван: {}", e.getMessage());
            case INCOMPLETE_CHAIN -> log.warn("Цепочка неполна: {}", e.getMessage());
            default -> log.error("Проверка не пройдена: {}", e.getMessage());
        }
        throw e;                                 // дальше не идём
    }

## GostOids — реестр OID

Класс `org.rssys.gost.pkix.GostOids` хранит все OID проекта:
ГОСТ-алгоритмы, кривые, CMS, атрибуты PKCS#9, CAdES, TSP, OCSP,
расширения X.509, PKCS#12.

    String signedData = GostOids.CMS_SIGNED_DATA;            // 1.2.840.113549.1.7.2
    String contentType = GostOids.ATTR_CONTENT_TYPE;         // 1.2.840.113549.1.9.3
    String messageDigest = GostOids.ATTR_MESSAGE_DIGEST;     // 1.2.840.113549.1.9.4
    String signingTime = GostOids.ATTR_SIGNING_TIME;         // 1.2.840.113549.1.9.5
    String signingCertV2 = GostOids.SIGNING_CERTIFICATE_V2;  // 1.2.840.113549.1.9.16.2.47
    String tstInfo = GostOids.TST_INFO;                      // 1.2.840.113549.1.9.16.1.4
    String sigPolicyId = GostOids.SIGNATURE_POLICY_ID;       // 1.2.840.113549.1.9.16.2.15
    String sigTimeStamp = GostOids.SIGNATURE_TIME_STAMP;     // 1.2.840.113549.1.9.16.2.14
    String adTimeStamping = GostOids.AD_TIME_STAMPING;       // 1.3.6.1.5.5.7.48.3
    String vko256 = GostOids.AGREEMENT_VKO_256;              // 1.2.643.7.1.1.6.1
    String kexp15 = GostOids.WRAP_KUZNYECHIK_KEXP15;         // 1.2.643.7.1.1.7.2.1
    int granted = GostOids.PKI_STATUS_GRANTED;               // 0
    int rejected = GostOids.PKI_STATUS_REJECTED;             // 2

## Кросс-валидация

Совместимость проверена на независимых реализациях; тесты лежат в
`x-validation-tests`.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Что проверено</th>
<th style="text-align: left;">С чем</th>
<th style="text-align: left;">Каталог</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>CMS SignedData, EnvelopedData (в том
числе OMAC), certs-only <code>.p7b</code></p></td>
<td style="text-align: left;"><p>OpenSSL с провайдером gostprov</p></td>
<td style="text-align: left;"><p><code>cms</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CMS и CAdES-BES, CAdES-T, CAdES-X Long,
собранные библиотекой</p></td>
<td style="text-align: left;"><p>КриптоПро
(<code>cryptcp</code>)</p></td>
<td style="text-align: left;"><p><code>cadest</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CAdES-BES, CAdES-T,
контрподпись</p></td>
<td style="text-align: left;"><p>BouncyCastle, OpenSSL</p></td>
<td style="text-align: left;"><p><code>cadest</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Метки времени TSP</p></td>
<td style="text-align: left;"><p>BouncyCastle</p></td>
<td style="text-align: left;"><p><code>cadest</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CAdES-C</p></td>
<td style="text-align: left;"><p>BouncyCastle, OpenSSL</p></td>
<td style="text-align: left;"><p><code>cadesc</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Сертификаты</p></td>
<td style="text-align: left;"><p>OpenSSL</p></td>
<td style="text-align: left;"><p><code>cert</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CRL</p></td>
<td style="text-align: left;"><p>OpenSSL, <code>certmgr</code>
(КриптоПро)</p></td>
<td style="text-align: left;"><p><code>crl</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>OCSP</p></td>
<td style="text-align: left;"><p>BouncyCastle, OpenSSL</p></td>
<td style="text-align: left;"><p><code>ocsp</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>CSR</p></td>
<td style="text-align: left;"><p>OpenSSL,
<code>cryptcp -createrqst</code> (КриптоПро)</p></td>
<td style="text-align: left;"><p><code>csr</code>,
<code>cryptopro</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>PKCS#12 (MAC, PBES2, PKCS#8)</p></td>
<td style="text-align: left;"><p>OpenSSL</p></td>
<td style="text-align: left;"><p><code>pkcs12</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>PKCS#12: наш файл импортирует
<code>certmgr</code>, ключ из него подписывает КриптоПро</p></td>
<td style="text-align: left;"><p>КриптоПро</p></td>
<td style="text-align: left;"><p><code>cryptopro</code></p></td>
</tr>
</tbody>
</table>

Для EnvelopedData сверка идёт в формате `KeyTransRecipientInfo` по ТК26
§8.2.1; контейнеров КриптоПро на ГОСТ 28147-89 в сверке нет. В
`CryptoproPkcs12InteropTest` отключён один тест: PFX, который
экспортирует КриптоПро, шифрует ключ схемой PBE с OID
`1.2.840.113549.1.12.1.80`, а `GostPkcs12Loader` её не читает.

Запуск:

    mvn -Pcrossval -pl x-validation-tests/cms -am test -Dexec.skip=true      # один каталог
    make crossval                                                            # все проверки
    make crossval-full                                                       # плюс контейнеры КриптоПро

Тесты, создающие контейнеры КриптоПро, по умолчанию пропускаются (датчик
случайных чисел требует движения мыши): их запускает
`make crossval-full`.

## Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
