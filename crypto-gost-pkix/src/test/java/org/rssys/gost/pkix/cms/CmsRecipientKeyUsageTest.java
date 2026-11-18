package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * CMS EnvelopedData: KeyUsage сертификата получателя проверяется при добавлении получателя.
 *
 * <p>Правило: KeyUsage нет - допускается; есть - нужен {@code keyEncipherment},
 * {@code keyAgreement} или {@code dataEncipherment}, одинаково для ktri и kari, критичность не
 * важна.
 */
@DisplayName("CMS: KeyUsage получателя EnvelopedData")
class CmsRecipientKeyUsageTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] DATA = "содержимое для шифрования".getBytes(StandardCharsets.UTF_8);

    /** Получатель с закрытым ключом, чтобы после шифрования можно было расшифровать. */
    private record Recipient(KeyPair keyPair, GostCertificate cert) {}

    private static GostCertificateBuilder baseBuilder(KeyPair kp, byte[] subjectDn) {
        return GostCertificateBuilder.create(PARAMS, subjectDn)
                .issuerDn(subjectDn)
                .publicKey(kp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForDays(30);
    }

    /** Самоподписанный получатель; {@code .keyUsage(...)} всегда пишет критичное расширение. */
    private static Recipient recipient(KeyUsage... usages) {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificateBuilder builder = baseBuilder(kp, CmsTestUtils.buildDn("CN=Recipient"));
        if (usages.length > 0) {
            builder.keyUsage(usages);
        }
        return new Recipient(kp, builder.sign(kp.getPrivate()));
    }

    /** Получатель с некритичным KeyUsage: собирается сырым расширением, а не fluent-методом. */
    private static Recipient recipientNonCritical(KeyUsage... usages) {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert =
                baseBuilder(kp, CmsTestUtils.buildDn("CN=Recipient"))
                        .additionalExtensions(
                                GostCertificateBuilder.buildKeyUsageExtension(false, usages))
                        .sign(kp.getPrivate());
        return new Recipient(kp, cert);
    }

    /**
     * Критичность KeyUsage читается из DER эвристикой, это не разбор расширений: публичного
     * признака у сертификата нет, а для проверки предусловия теста достаточно. Ищется первое
     * вхождение OID 2.5.29.15; у критичного расширения следом идёт BOOLEAN TRUE (01 01 FF), у
     * некритичного значение по умолчанию опускается, и следом сразу OCTET STRING.
     */
    private static boolean isKeyUsageCritical(GostCertificate cert) {
        byte[] der = cert.getEncoded();
        byte[] oid = {0x55, 0x1D, 0x0F};
        for (int i = 0; i + oid.length + 3 <= der.length; i++) {
            if (der[i] == oid[0] && der[i + 1] == oid[1] && der[i + 2] == oid[2]) {
                int next = i + oid.length;
                return der[next] == 0x01 && der[next + 1] == 0x01 && der[next + 2] == (byte) 0xFF;
            }
        }
        throw new AssertionError("В сертификате нет расширения KeyUsage");
    }

    private static CmsEnvelopedDataBuilder newBuilder(boolean kari) {
        return kari ? CmsEnvelopedDataBuilder.createKari() : CmsEnvelopedDataBuilder.create();
    }

    private static void assertRejected(Recipient r, boolean kari, String label) {
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> newBuilder(kari).data(DATA).addRecipient(r.cert()),
                        label + ": получатель без управления ключами должен быть отвергнут");
        assertTrue(e.getMessage().contains("KeyUsage"), "сообщение называет KeyUsage");
        assertTrue(
                e.getMessage().contains("keyEncipherment")
                        && e.getMessage().contains("keyAgreement")
                        && e.getMessage().contains("dataEncipherment"),
                "сообщение называет все допустимые биты");
    }

    private static void assertRoundTrip(Recipient r, boolean kari, String label)
            throws PkixException {
        byte[] enveloped = newBuilder(kari).data(DATA).addRecipient(r.cert()).build();
        assertArrayEquals(
                DATA,
                CmsEnvelopedDataDecryptor.decrypt(enveloped, r.keyPair().getPrivate(), r.cert()),
                label + ": расшифрованное содержимое должно совпасть с исходным");
    }

    // ========================================================================
    // Отказ
    // ========================================================================

    @Test
    @DisplayName("Только digitalSignature: отказ и в ktri, и в kari")
    void digitalSignatureOnlyRejected() {
        Recipient r = recipient(KeyUsage.DIGITAL_SIGNATURE);
        assertRejected(r, false, "ktri");
        assertRejected(r, true, "kari");
    }

    @Test
    @DisplayName("digitalSignature + nonRepudiation (профиль подписи RFC 4491 §3): отказ")
    void signatureProfileRejected() {
        Recipient r = recipient(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION);
        assertRejected(r, false, "ktri");
        assertRejected(r, true, "kari");
    }

    @Test
    @DisplayName("Некритичный KeyUsage тоже ограничивает: digitalSignature без критичности - отказ")
    void nonCriticalKeyUsageRejected() {
        Recipient r = recipientNonCritical(KeyUsage.DIGITAL_SIGNATURE);
        assertFalse(
                isKeyUsageCritical(r.cert()), "предпосылка теста: расширение KeyUsage некритичное");
        assertRejected(r, false, "ktri");
        assertRejected(r, true, "kari");
    }

    @Test
    @DisplayName("Сертификат УЦ (keyCertSign + cRLSign) как получатель: отказ")
    void caCertificateRejected() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate ca =
                baseBuilder(kp, CmsTestUtils.buildDn("CN=Recipient CA"))
                        .basicConstraints(true, null)
                        .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                        .sign(kp.getPrivate());
        Recipient r = new Recipient(kp, ca);
        assertRejected(r, false, "ktri");
        assertRejected(r, true, "kari");
    }

    @Test
    @DisplayName("EKU emailProtection не заменяет KeyUsage: подписной сертификат отвергается")
    void emailProtectionEkuDoesNotOverrideKeyUsage() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert =
                baseBuilder(kp, CmsTestUtils.buildDn("CN=Mail Signer"))
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION)
                        .extendedKeyUsage(GostOids.EXT_EMAIL_PROTECTION)
                        .sign(kp.getPrivate());
        Recipient r = new Recipient(kp, cert);
        assertRejected(r, false, "ktri");
        assertRejected(r, true, "kari");
    }

    // ========================================================================
    // Предикат GostCertificate.isKeyUsageValidForEncryption
    // ========================================================================

    @Test
    @DisplayName("Предикат: KeyUsage нет -> true")
    void predicateTrueWithoutKeyUsage() {
        assertTrue(
                recipient().cert().isKeyUsageValidForEncryption(), "без KeyUsage ограничений нет");
    }

    @Test
    @DisplayName("Предикат: каждый из keyEncipherment, keyAgreement, dataEncipherment -> true")
    void predicateTrueForEachEncryptionBit() {
        for (KeyUsage bit :
                new KeyUsage[] {
                    KeyUsage.KEY_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT, KeyUsage.DATA_ENCIPHERMENT
                }) {
            assertTrue(
                    recipient(bit).cert().isKeyUsageValidForEncryption(),
                    bit + ": одного бита достаточно");
        }
    }

    @Test
    @DisplayName("Предикат: подпись, неотрекаемость, УЦ, только encipherOnly -> false")
    void predicateFalseWithoutEncryptionBits() {
        assertFalse(
                recipient(KeyUsage.DIGITAL_SIGNATURE).cert().isKeyUsageValidForEncryption(),
                "только digitalSignature");
        assertFalse(
                recipient(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION)
                        .cert()
                        .isKeyUsageValidForEncryption(),
                "digitalSignature и nonRepudiation");
        assertFalse(
                recipient(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                        .cert()
                        .isKeyUsageValidForEncryption(),
                "keyCertSign и cRLSign");
        assertFalse(
                recipient(KeyUsage.ENCIPHER_ONLY).cert().isKeyUsageValidForEncryption(),
                "encipherOnly без keyAgreement не засчитывается");
        assertFalse(
                recipientNonCritical(KeyUsage.DIGITAL_SIGNATURE)
                        .cert()
                        .isKeyUsageValidForEncryption(),
                "некритичный KeyUsage ограничивает так же");
    }

    // ========================================================================
    // Приём
    // ========================================================================

    @Test
    @DisplayName("Без KeyUsage: принимается, полный цикл ktri и kari")
    void noKeyUsageAccepted() throws Exception {
        Recipient r = recipient();
        assertRoundTrip(r, false, "ktri");
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName("Только keyEncipherment: принимается в ktri и в kari")
    void keyEnciphermentAccepted() throws Exception {
        Recipient r = recipient(KeyUsage.KEY_ENCIPHERMENT);
        assertRoundTrip(r, false, "ktri");
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName("Только keyAgreement: принимается в ktri и в kari")
    void keyAgreementAccepted() throws Exception {
        Recipient r = recipient(KeyUsage.KEY_AGREEMENT);
        assertRoundTrip(r, false, "ktri");
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName("Только dataEncipherment: принимается, как у КриптоПро CSP 5.0")
    void dataEnciphermentOnlyAccepted() throws Exception {
        Recipient r = recipient(KeyUsage.DATA_ENCIPHERMENT);
        assertRoundTrip(r, false, "ktri");
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName("keyEncipherment + keyAgreement: принимается")
    void bothBitsAccepted() throws Exception {
        Recipient r = recipient(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT);
        assertRoundTrip(r, false, "ktri");
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName(
            "Профиль квалифицированного сертификата (подпись, неотрекаемость, шифрование"
                    + " ключей и данных, без keyAgreement): принимается, в том числе в kari")
    void qualifiedProfileWithoutKeyAgreementAccepted() throws Exception {
        Recipient r =
                recipient(
                        KeyUsage.DIGITAL_SIGNATURE,
                        KeyUsage.NON_REPUDIATION,
                        KeyUsage.KEY_ENCIPHERMENT,
                        KeyUsage.DATA_ENCIPHERMENT);
        assertTrue(
                isKeyUsageCritical(r.cert()),
                "предпосылка теста: KeyUsage критичный, как у реальных сертификатов");
        assertRoundTrip(r, false, "ktri");
        // Строгая привязка kari к keyAgreement отвергла бы такой сертификат, хотя контейнер
        // на него расшифровывается: в ГОСТ оба режима строятся на VKO
        assertRoundTrip(r, true, "kari");
    }

    @Test
    @DisplayName("Некритичный KeyUsage с keyEncipherment: принимается")
    void nonCriticalKeyEnciphermentAccepted() throws Exception {
        assertRoundTrip(recipientNonCritical(KeyUsage.KEY_ENCIPHERMENT), false, "ktri");
    }

    // ========================================================================
    // Аргументы и состояние построителя
    // ========================================================================

    @Test
    @DisplayName("addRecipient(null): NullPointerException")
    void nullRecipientRejected() {
        CmsEnvelopedDataBuilder builder = CmsEnvelopedDataBuilder.create().data(DATA);
        assertThrows(
                NullPointerException.class,
                () -> builder.addRecipient(null),
                "null вместо сертификата должен давать NullPointerException");
    }

    @Test
    @DisplayName("После отказа построитель рабочий; отвергнутый получатель в контейнер не попал")
    void builderUsableAfterRejection() throws Exception {
        Recipient bad = recipient(KeyUsage.DIGITAL_SIGNATURE);
        Recipient good = recipient(KeyUsage.KEY_ENCIPHERMENT);
        CmsEnvelopedDataBuilder builder = CmsEnvelopedDataBuilder.create().data(DATA);
        assertThrows(IllegalArgumentException.class, () -> builder.addRecipient(bad.cert()));
        byte[] enveloped = builder.addRecipient(good.cert()).build();
        assertArrayEquals(
                DATA,
                CmsEnvelopedDataDecryptor.decrypt(
                        enveloped, good.keyPair().getPrivate(), good.cert()),
                "после отказа построитель должен собрать контейнер для валидного получателя");
        assertThrows(
                PkixException.class,
                () ->
                        CmsEnvelopedDataDecryptor.decrypt(
                                enveloped, bad.keyPair().getPrivate(), bad.cert()),
                "отвергнутый получатель не должен быть в списке получателей контейнера");
    }

    @Test
    @DisplayName(
            "Прямое использование построителя без получателей: IllegalStateException из build()")
    void builderWithoutRecipientsKeepsIllegalState() {
        assertThrows(
                IllegalStateException.class,
                () -> CmsEnvelopedDataBuilder.create().data(DATA).build(),
                "build() без получателей сохраняет IllegalStateException");
    }

    @Test
    @DisplayName("Текст ошибки: серийный номер есть, ни одного RDN из subject и issuer нет")
    void messageHasNoPersonalData() {
        // Самоподписанный: issuer == subject, поэтому запрет на subject без запрета на issuer
        // ничего бы не давал
        KeyPair selfKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] personalDn = GostDnParser.encodeDn("CN=Иванов Иван Иванович,O=Личный Бизнес,C=RU");
        BigInteger selfSerial = BigInteger.valueOf(0x5EC0DEL);
        GostCertificate selfSigned =
                baseBuilder(selfKp, personalDn)
                        .serial(selfSerial)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .sign(selfKp.getPrivate());

        // Выпущенный УЦ: у издателя собственное имя
        KeyPair caKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn = GostDnParser.encodeDn("CN=Тестовый Издатель Секретный,O=Корень,C=RU");
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate issued =
                GostCertificateBuilder.create(
                                PARAMS,
                                GostDnParser.encodeDn("CN=Петров Пётр Петрович,O=ИП Петров,C=RU"))
                        .issuerDn(caDn)
                        .publicKey(leafKp.getPublic())
                        .serial(BigInteger.valueOf(0xABCDEFL))
                        .notBeforeNow()
                        .validForDays(30)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .sign(caKp.getPrivate());

        String selfMessage = rejectionMessage(selfSigned);
        String issuedMessage = rejectionMessage(issued);

        assertTrue(selfMessage.contains("5ec0de"), "серийный номер самоподписанного указан");
        assertTrue(issuedMessage.contains("abcdef"), "серийный номер выпущенного УЦ указан");
        for (String forbidden :
                new String[] {"Иванов", "Личный", "Петров", "Тестовый Издатель", "Корень"}) {
            assertFalse(selfMessage.contains(forbidden), "в тексте нет «" + forbidden + "»");
            assertFalse(issuedMessage.contains(forbidden), "в тексте нет «" + forbidden + "»");
        }
        assertFalse(selfMessage.contains("CN="), "в тексте нет имён в формате DN");
        assertFalse(issuedMessage.contains("CN="), "в тексте нет имён в формате DN");
    }

    private static String rejectionMessage(GostCertificate cert) {
        return assertThrows(
                        IllegalArgumentException.class,
                        () -> CmsEnvelopedDataBuilder.create().data(DATA).addRecipient(cert))
                .getMessage();
    }

    // ========================================================================
    // CmsSignedAndEnvelopedData: получатели проверяются до подписи
    // ========================================================================

    /** Подписант, считающий обращения к закрытому ключу. */
    private static final class CountingSigner implements GostSigner {
        private final GostSigner delegate;
        final AtomicInteger signCalls = new AtomicInteger();

        CountingSigner(KeyPair kp) {
            this.delegate = GostSigner.of(kp.getPrivate());
        }

        @Override
        public byte[] signHash(byte[] hash) {
            signCalls.incrementAndGet();
            return delegate.signHash(hash);
        }

        @Override
        public ECParameters getParams() {
            return delegate.getParams();
        }

        @Override
        public PublicKeyParameters getPublicKey() {
            return delegate.getPublicKey();
        }
    }

    /** Вызов одного из двух методов совмещённого режима. */
    private interface Combined {
        byte[] run(
                byte[] data,
                GostSigner signer,
                GostCertificate signerCert,
                GostCertificate... recipients);
    }

    private static void forBothOrders(BiConsumer<String, Combined> body) {
        body.accept("signThenEncrypt", CmsSignedAndEnvelopedData::signThenEncrypt);
        body.accept("encryptThenSign", CmsSignedAndEnvelopedData::encryptThenSign);
    }

    @Test
    @DisplayName("Неподходящий получатель: IllegalArgumentException, подпись не выполнялась")
    void badRecipientRejectedBeforeSigning() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        Recipient bad = recipient(KeyUsage.DIGITAL_SIGNATURE);
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> method.run(DATA, signer, signerCert, bad.cert()),
                            name + ": получатель только для подписи должен быть отвергнут");
                    assertEquals(
                            0,
                            signer.signCalls.get(),
                            name + ": к ключу подписанта обращений быть не должно");
                });
    }

    @Test
    @DisplayName("Смешанный список (валидный и невалидный): отказ, подпись не выполнялась")
    void mixedRecipientsRejectedBeforeSigning() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        Recipient good = recipient(KeyUsage.KEY_ENCIPHERMENT);
        Recipient bad = recipient(KeyUsage.DIGITAL_SIGNATURE);
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> method.run(DATA, signer, signerCert, good.cert(), bad.cert()),
                            name + ": один неверный получатель отвергает весь список");
                    assertEquals(0, signer.signCalls.get(), name + ": подписи не было");
                });
    }

    @Test
    @DisplayName("Пустой список получателей: IllegalArgumentException, подпись не выполнялась")
    void emptyRecipientsRejectedBeforeSigning() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> method.run(DATA, signer, signerCert),
                            name + ": пустой список получателей должен быть отвергнут");
                    assertEquals(0, signer.signCalls.get(), name + ": подписи не было");
                });
    }

    @Test
    @DisplayName("Массив получателей null: NullPointerException, подпись не выполнялась")
    void nullRecipientsArrayRejectedBeforeSigning() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    assertThrows(
                            NullPointerException.class,
                            () -> method.run(DATA, signer, signerCert, (GostCertificate[]) null),
                            name + ": null вместо массива должен давать NullPointerException");
                    assertEquals(0, signer.signCalls.get(), name + ": подписи не было");
                });
    }

    @Test
    @DisplayName("null внутри массива получателей: NullPointerException, подпись не выполнялась")
    void nullElementInRecipientsRejectedBeforeSigning() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        Recipient good = recipient(KeyUsage.KEY_ENCIPHERMENT);
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    assertThrows(
                            NullPointerException.class,
                            () -> method.run(DATA, signer, signerCert, good.cert(), null),
                            name + ": null среди получателей должен давать NullPointerException");
                    assertEquals(0, signer.signCalls.get(), name + ": подписи не было");
                });
    }

    @Test
    @DisplayName("Валидный получатель: ровно одно обращение к ключу подписанта")
    void validRecipientSignsExactlyOnce() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        Recipient good = recipient(KeyUsage.KEY_ENCIPHERMENT);
        forBothOrders(
                (name, method) -> {
                    CountingSigner signer = new CountingSigner(signerKp);
                    byte[] result =
                            assertDoesNotThrow(
                                    () -> method.run(DATA, signer, signerCert, good.cert()),
                                    name + ": валидный получатель должен приниматься");
                    assertTrue(result.length > 0, name + ": контейнер не пуст");
                    assertEquals(
                            1,
                            signer.signCalls.get(),
                            name + ": подпись выполняется ровно один раз");
                });
    }

    @Test
    @DisplayName("Перегрузка с закрытым ключом тоже отвергает неверного получателя")
    void privateKeyOverloadsRejectBadRecipient() {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        Recipient bad = recipient(KeyUsage.DIGITAL_SIGNATURE);
        Supplier<byte[]> signThenEncrypt =
                () ->
                        CmsSignedAndEnvelopedData.signThenEncrypt(
                                DATA, signerKp.getPrivate(), signerCert, bad.cert());
        Supplier<byte[]> encryptThenSign =
                () ->
                        CmsSignedAndEnvelopedData.encryptThenSign(
                                DATA, signerKp.getPrivate(), signerCert, bad.cert());
        assertThrows(IllegalArgumentException.class, signThenEncrypt::get, "signThenEncrypt");
        assertThrows(IllegalArgumentException.class, encryptThenSign::get, "encryptThenSign");
    }
}
