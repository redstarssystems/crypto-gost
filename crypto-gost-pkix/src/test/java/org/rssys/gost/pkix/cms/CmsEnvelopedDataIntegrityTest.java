package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CMS EnvelopedData: режим шифра содержимого и политика целостности")
class CmsEnvelopedDataIntegrityTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] DATA = "Конфиденциальное содержимое для проверки режима".getBytes();
    private static final String UNKNOWN_OID = "1.2.3.4";

    private static PrivateKeyParameters privateKey;
    private static GostCertificate cert;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        privateKey = kp.getPrivate();
        cert = CmsTestUtils.createSelfSignedCert(kp.getPrivate(), kp.getPublic());
    }

    private static byte[] omacKtri() {
        return CmsEnvelopedDataBuilder.create().data(DATA).addRecipient(cert).build();
    }

    private static byte[] plainKtri() {
        return CmsEnvelopedDataBuilder.create()
                .data(DATA)
                .addRecipient(cert)
                .withoutIntegrity()
                .build();
    }

    private static byte[] omacKari() {
        return CmsEnvelopedDataBuilder.createKari().data(DATA).addRecipient(cert).build();
    }

    private static byte[] plainKari() {
        return CmsEnvelopedDataBuilder.createKari()
                .data(DATA)
                .addRecipient(cert)
                .withoutIntegrity()
                .build();
    }

    private static String contentOid(byte[] envelopedDer) throws PkixException {
        byte[][] env = CmsEnvelopedRewriter.envParts(envelopedDer);
        byte[][] eci = DerCodec.parseSequenceContents(env[2], 0);
        byte[][] alg = DerCodec.parseSequenceContents(eci[1], 0);
        return DerCodec.parseOid(alg[0], 0);
    }

    private static PkixException decryptFails(byte[] envelopedDer) {
        return assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.decrypt(envelopedDer, privateKey, cert));
    }

    private static PkixException decryptAllowingFails(byte[] envelopedDer) {
        return assertThrows(
                PkixException.class,
                () ->
                        CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                                envelopedDer, privateKey, cert));
    }

    // ------------------------------------------------------------------
    // Умолчания построителя
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Построитель по умолчанию даёт OMAC: OID, version = 2, атрибут content-mac")
    void builderDefaultsToOmac() throws PkixException {
        byte[] enveloped = omacKtri();

        byte[][] env = CmsEnvelopedRewriter.envParts(enveloped);
        assertEquals(
                GostOids.KUZ_CTR_ACPKM_OMAC,
                contentOid(enveloped),
                "по умолчанию OID шифра должен быть OMAC");
        assertEquals(4, env.length, "OMAC-контейнер должен нести unprotectedAttrs");
        assertEquals(2, DerCodec.parseInteger(env[0], 0).intValueExact(), "version должна быть 2");
    }

    @Test
    @DisplayName("withoutIntegrity даёт обычный CTR-ACPKM без unprotectedAttrs")
    void withoutIntegrityProducesPlainContainer() throws PkixException {
        byte[] enveloped = plainKtri();

        byte[][] env = CmsEnvelopedRewriter.envParts(enveloped);
        assertEquals(GostOids.KUZ_CTR_ACPKM, contentOid(enveloped), "OID должен быть обычным");
        assertEquals(3, env.length, "обычный контейнер не должен нести unprotectedAttrs");
    }

    // ------------------------------------------------------------------
    // Политика целостности
    // ------------------------------------------------------------------

    @Test
    @DisplayName("decrypt принимает OMAC-контейнеры (ktri и kari)")
    void strictDecryptAcceptsOmac() throws PkixException {
        assertArrayEquals(
                DATA, CmsEnvelopedDataDecryptor.decrypt(omacKtri(), privateKey, cert), "ktri");
        assertArrayEquals(
                DATA, CmsEnvelopedDataDecryptor.decrypt(omacKari(), privateKey, cert), "kari");
    }

    @Test
    @DisplayName("decrypt отвергает контейнер без имитовставки: INTEGRITY_REQUIRED (ktri и kari)")
    void strictDecryptRejectsPlain() {
        assertEquals(
                PkixException.Reason.INTEGRITY_REQUIRED,
                decryptFails(plainKtri()).reason(),
                "ktri без OMAC");
        assertEquals(
                PkixException.Reason.INTEGRITY_REQUIRED,
                decryptFails(plainKari()).reason(),
                "kari без OMAC");
    }

    @Test
    @DisplayName("decryptAllowingNoIntegrity принимает оба режима (ktri и kari)")
    void allowingNoIntegrityAcceptsBothModes() throws PkixException {
        for (byte[] container : new byte[][] {plainKtri(), omacKtri(), plainKari(), omacKari()}) {
            assertArrayEquals(
                    DATA,
                    CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                            container, privateKey, cert),
                    "оба режима должны расшифровываться");
        }
    }

    @Test
    @DisplayName("decryptAllowingNoIntegrity проверяет MAC у OMAC-контейнера, а не отключает его")
    void allowingNoIntegrityStillVerifiesOmac() throws PkixException {
        byte[] tampered = CmsEnvelopedRewriter.withTamperedEncryptedMac(omacKtri());

        assertEquals(
                PkixException.Reason.OTHER,
                decryptAllowingFails(tampered).reason(),
                "испорченный MAC должен давать отказ и в разрешающем методе");
    }

    // ------------------------------------------------------------------
    // OID шифра содержимого
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Неизвестный OID контентного шифра отвергается, а не обрабатывается как Кузнечик")
    void unknownContentOidRejected() throws PkixException {
        for (byte[] source : new byte[][] {plainKtri(), omacKtri()}) {
            byte[] forged = CmsEnvelopedRewriter.withContentOid(source, UNKNOWN_OID);

            PkixException strict = decryptFails(forged);
            assertEquals(PkixException.Reason.OTHER, strict.reason(), "decrypt");
            assertTrue(
                    strict.getMessage().contains("Unsupported content encryption algorithm"),
                    "причина должна быть в неподдерживаемом шифре: " + strict.getMessage());

            PkixException allowing = decryptAllowingFails(forged);
            assertEquals(PkixException.Reason.OTHER, allowing.reason(), "decryptAllowing");
            assertTrue(
                    allowing.getMessage().contains("Unsupported content encryption algorithm"),
                    "причина должна быть в неподдерживаемом шифре: " + allowing.getMessage());
        }
    }

    @Test
    @DisplayName("Подмена OMAC на обычный режим при сохранённом content-mac: PARSE_ERROR")
    void downgradeWithAttributeKeptRejected() throws PkixException {
        byte[] forged = CmsEnvelopedRewriter.withContentOid(omacKtri(), GostOids.KUZ_CTR_ACPKM);

        assertEquals(
                PkixException.Reason.PARSE_ERROR,
                decryptFails(forged).reason(),
                "противоречие режима и атрибута в decrypt");
        assertEquals(
                PkixException.Reason.PARSE_ERROR,
                decryptAllowingFails(forged).reason(),
                "противоречие режима и атрибута в разрешающем методе");
    }

    @Test
    @DisplayName("OMAC-контейнер без атрибута content-mac: PARSE_ERROR")
    void omacWithoutAttributeRejected() throws PkixException {
        byte[] stripped = CmsEnvelopedRewriter.withoutUnprotectedAttrs(omacKtri());

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(stripped).reason());
        assertEquals(PkixException.Reason.PARSE_ERROR, decryptAllowingFails(stripped).reason());
    }

    @Test
    @DisplayName(
            "Подмена OMAC на обычный режим с удалением атрибута: decrypt отказывает по политике")
    void downgradeWithAttributeRemovedRejectedByPolicy() throws PkixException {
        byte[] forged =
                CmsEnvelopedRewriter.withoutUnprotectedAttrs(
                        CmsEnvelopedRewriter.withContentOid(omacKtri(), GostOids.KUZ_CTR_ACPKM));

        assertEquals(
                PkixException.Reason.INTEGRITY_REQUIRED,
                decryptFails(forged).reason(),
                "строгий decrypt закрывает понижение режима");
    }

    @Test
    @DisplayName(
            "Граница decryptAllowingNoIntegrity: понижение с удалением атрибута даёт мусор как успех")
    void allowingNoIntegrityDoesNotDetectDowngrade() throws PkixException {
        byte[] forged =
                CmsEnvelopedRewriter.withoutUnprotectedAttrs(
                        CmsEnvelopedRewriter.withContentOid(omacKtri(), GostOids.KUZ_CTR_ACPKM));

        // Тест фиксирует свойство режима без целостности: контейнер без атрибута выглядит как
        // законный обычный CTR. Ключ потока другой (CEK вместо K(1)), поэтому текст не совпадает.
        byte[] result =
                CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(forged, privateKey, cert);

        assertFalse(
                Arrays.equals(DATA, result),
                "после подмены режима исходный текст восстановиться не должен");
    }

    // ------------------------------------------------------------------
    // Структура и обёртка ключа
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Контейнер с originatorInfo отвергается явно: PARSE_ERROR")
    void originatorInfoRejected() throws PkixException {
        byte[] forged = CmsEnvelopedRewriter.withOriginatorInfo(omacKtri());

        PkixException e = decryptFails(forged);
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason());
        assertTrue(
                e.getMessage().contains("originatorInfo"),
                "сообщение должно называть originatorInfo: " + e.getMessage());
    }

    @Test
    @DisplayName("EnvelopedData без encryptedContentInfo отвергается: PARSE_ERROR")
    void truncatedEnvelopedDataRejected() throws PkixException {
        byte[][] env = CmsEnvelopedRewriter.envParts(omacKtri());
        byte[] truncated = CmsEnvelopedRewriter.assemble(env[0], env[1]);

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(truncated).reason());
    }

    @Test
    @DisplayName("Чужой keyEncryptionAlgorithm в ktri отвергается")
    void foreignKeyEncryptionAlgorithmKtriRejected() throws PkixException {
        byte[] forged = CmsEnvelopedRewriter.withKeyEncryptionOid(omacKtri(), UNKNOWN_OID);

        PkixException e = decryptFails(forged);
        assertEquals(PkixException.Reason.OTHER, e.reason());
        assertTrue(
                e.getMessage().contains("key encryption algorithm in ktri"),
                "отказ должен исходить из проверки обёртки ключа: " + e.getMessage());
    }

    @Test
    @DisplayName("Чужой keyEncryptionAlgorithm в kari отвергается")
    void foreignKeyEncryptionAlgorithmKariRejected() throws PkixException {
        byte[] forged = CmsEnvelopedRewriter.withKeyEncryptionOid(omacKari(), UNKNOWN_OID);

        PkixException e = decryptFails(forged);
        assertEquals(PkixException.Reason.OTHER, e.reason());
        assertTrue(
                e.getMessage().contains("key encryption algorithm in kari"),
                "отказ должен исходить из проверки обёртки ключа: " + e.getMessage());
    }

    @Test
    @DisplayName("Недопустимый шифр в чужом контейнере отвергается раньше поиска получателя")
    void unsupportedCipherReportedBeforeRecipientLookup() throws PkixException {
        var otherKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate otherCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        otherKp.getPrivate(),
                        otherKp.getPublic(),
                        BigInteger.valueOf(777),
                        "Other");
        byte[] forged = CmsEnvelopedRewriter.withContentOid(omacKtri(), UNKNOWN_OID);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsEnvelopedDataDecryptor.decrypt(
                                        forged, otherKp.getPrivate(), otherCert));

        assertTrue(
                e.getMessage().contains("Unsupported content encryption algorithm"),
                "для контейнера не нам отказ по шифру идёт до поиска получателя: "
                        + e.getMessage());
    }

    // ------------------------------------------------------------------
    // Разбор unprotectedAttrs: несколько атрибутов
    // ------------------------------------------------------------------

    private static final java.time.Duration PARSE_TIMEOUT = java.time.Duration.ofSeconds(5);

    @Test
    @DisplayName("Лишний атрибут после content-mac не мешает расшифрованию и не зацикливает разбор")
    void extraAttributeAfterContentMacAccepted() throws PkixException {
        byte[] container = omacKtri();
        byte[][] attrs = CmsEnvelopedRewriter.unprotectedAttributes(container);
        // Длина постороннего атрибута равна длине content-mac: на этом сочетании прежний разбор
        // не продвигался по данным
        byte[] extra =
                CmsEnvelopedRewriter.unrelatedAttribute(
                        UNKNOWN_OID, new byte[attrs[0].length - 11]);
        assertEquals(attrs[0].length, extra.length, "длины атрибутов должны совпадать");
        byte[] withExtra =
                CmsEnvelopedRewriter.withUnprotectedAttributes(container, attrs[0], extra);

        byte[] decrypted =
                assertTimeoutPreemptively(
                        PARSE_TIMEOUT,
                        () -> CmsEnvelopedDataDecryptor.decrypt(withExtra, privateKey, cert),
                        "разбор нескольких атрибутов не должен зависать");
        assertArrayEquals(DATA, decrypted, "лишний атрибут не должен влиять на результат");
    }

    @Test
    @DisplayName("Посторонний атрибут перед content-mac: контейнер расшифровывается")
    void extraAttributeBeforeContentMacAccepted() throws PkixException {
        byte[] container = omacKtri();
        byte[][] attrs = CmsEnvelopedRewriter.unprotectedAttributes(container);
        byte[] extra = CmsEnvelopedRewriter.unrelatedAttribute(UNKNOWN_OID, new byte[3]);
        byte[] withExtra =
                CmsEnvelopedRewriter.withUnprotectedAttributes(container, extra, attrs[0]);

        byte[] decrypted =
                assertTimeoutPreemptively(
                        PARSE_TIMEOUT,
                        () -> CmsEnvelopedDataDecryptor.decrypt(withExtra, privateKey, cert),
                        "разбор нескольких атрибутов не должен зависать");
        assertArrayEquals(DATA, decrypted, "порядок атрибутов не должен влиять на результат");
    }

    @Test
    @DisplayName(
            "Несколько посторонних атрибутов разного размера не вызывают зависания или переполнения")
    void manyUnrelatedAttributesTerminate() throws PkixException {
        byte[] container = plainKtri();
        byte[][] attrs = new byte[5][];
        for (int i = 0; i < attrs.length; i++) {
            attrs[i] = CmsEnvelopedRewriter.unrelatedAttribute(UNKNOWN_OID, new byte[1 + i * 7]);
        }
        byte[] withAttrs = CmsEnvelopedRewriter.withUnprotectedAttributes(container, attrs);

        // Без content-mac обычный контейнер остаётся обычным: разбор завершается, и разрешающий
        // метод расшифровывает его, а строгий decrypt отвечает по политике
        byte[] decrypted =
                assertTimeoutPreemptively(
                        PARSE_TIMEOUT,
                        () ->
                                CmsEnvelopedDataDecryptor.decryptAllowingNoIntegrity(
                                        withAttrs, privateKey, cert),
                        "разбор нескольких атрибутов не должен зависать");
        assertArrayEquals(DATA, decrypted, "посторонние атрибуты не должны влиять на результат");
        assertEquals(
                PkixException.Reason.INTEGRITY_REQUIRED,
                decryptFails(withAttrs).reason(),
                "строгий decrypt отвечает по политике, а не зависает");
    }

    @Test
    @DisplayName("Повторяющийся атрибут content-mac отвергается: PARSE_ERROR")
    void duplicateContentMacRejected() throws PkixException {
        byte[] container = omacKtri();
        byte[][] attrs = CmsEnvelopedRewriter.unprotectedAttributes(container);
        byte[] duplicated =
                CmsEnvelopedRewriter.withUnprotectedAttributes(container, attrs[0], attrs[0]);

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(duplicated).reason());
        assertEquals(PkixException.Reason.PARSE_ERROR, decryptAllowingFails(duplicated).reason());
    }

    @Test
    @DisplayName("Лишний элемент после unprotectedAttrs отвергается: PARSE_ERROR")
    void extraEnvelopedDataElementRejected() throws PkixException {
        byte[][] env = CmsEnvelopedRewriter.envParts(omacKtri());
        byte[] withTail = CmsEnvelopedRewriter.assemble(env[0], env[1], env[2], env[3], env[0]);

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(withTail).reason());
    }

    @Test
    @DisplayName("Пустое unprotectedAttrs отвергается: PARSE_ERROR")
    void emptyUnprotectedAttrsRejected() throws PkixException {
        byte[][] env = CmsEnvelopedRewriter.envParts(omacKtri());
        byte[] empty =
                CmsEnvelopedRewriter.assemble(
                        env[0],
                        env[1],
                        env[2],
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, new byte[0]));

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(empty).reason());
        assertEquals(PkixException.Reason.PARSE_ERROR, decryptAllowingFails(empty).reason());
    }

    @Test
    @DisplayName("Усечённый атрибут в unprotectedAttrs отвергается: PARSE_ERROR")
    void truncatedAttributeRejected() throws PkixException {
        byte[] container = omacKtri();
        byte[][] env = CmsEnvelopedRewriter.envParts(container);
        byte[][] attrs = CmsEnvelopedRewriter.unprotectedAttributes(container);
        // Заголовок SEQUENCE обещает больше байт, чем есть в содержимом
        byte[] truncatedAttr = Arrays.copyOf(attrs[0], attrs[0].length - 3);
        byte[] forged =
                CmsEnvelopedRewriter.assemble(
                        env[0],
                        env[1],
                        env[2],
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, truncatedAttr));

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(forged).reason());
        assertEquals(PkixException.Reason.PARSE_ERROR, decryptAllowingFails(forged).reason());
    }

    @Test
    @DisplayName("Данные после явного SET в unprotectedAttrs отвергаются: PARSE_ERROR")
    void trailingBytesAfterExplicitSetRejected() throws PkixException {
        byte[] container = omacKtri();
        byte[][] env = CmsEnvelopedRewriter.envParts(container);
        byte[][] attrs = CmsEnvelopedRewriter.unprotectedAttributes(container);
        byte[] explicitSet = DerCodec.encodeSetOf(attrs[0]);
        byte[] withTail = Arrays.copyOf(explicitSet, explicitSet.length + 3);
        byte[] forged =
                CmsEnvelopedRewriter.assemble(
                        env[0],
                        env[1],
                        env[2],
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, withTail));

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(forged).reason());

        // Контейнер с явным SET без хвоста принимается: проверка не ломает прежнюю кодировку
        byte[] legacy =
                CmsEnvelopedRewriter.assemble(
                        env[0],
                        env[1],
                        env[2],
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, explicitSet));
        assertArrayEquals(
                DATA,
                CmsEnvelopedDataDecryptor.decrypt(legacy, privateKey, cert),
                "явный SET без хвоста должен приниматься");
    }

    @Test
    @DisplayName("Битый ContentInfo даёт PkixException(PARSE_ERROR), а не IllegalArgumentException")
    void malformedContentInfoRejected() {
        byte[] garbage = {(byte) 0x96, 0x01, 0x02};

        assertEquals(PkixException.Reason.PARSE_ERROR, decryptFails(garbage).reason());
        assertEquals(PkixException.Reason.PARSE_ERROR, decryptAllowingFails(garbage).reason());
    }

    // ========================================================================
    // Отказ проверки имитовставки обёртки ключа (на этом пути KEK и IV затираются в finally)
    // ========================================================================

    @Test
    @DisplayName("ktri: испорченный обёрнутый CEK даёт PkixException, а не мусор")
    void ktriCorruptedWrappedKeyIsRejected() throws PkixException {
        byte[] corrupted = CmsEnvelopedRewriter.withCorruptedWrappedKey(omacKtri());
        assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.decrypt(corrupted, privateKey, cert),
                "Испорченный wrappedCek должен отвергаться проверкой KExp15");
    }

    @Test
    @DisplayName("kari: испорченный обёрнутый CEK даёт PkixException, а не мусор")
    void kariCorruptedWrappedKeyIsRejected() throws PkixException {
        byte[] corrupted = CmsEnvelopedRewriter.withCorruptedWrappedKey(omacKari());
        assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.decrypt(corrupted, privateKey, cert),
                "Испорченный wrappedCek должен отвергаться проверкой KExp15");
    }

    @Test
    @DisplayName("Исходные контейнеры после проверки отказа по-прежнему расшифровываются")
    void uncorruptedContainersStillDecrypt() throws PkixException {
        assertArrayEquals(DATA, CmsEnvelopedDataDecryptor.decrypt(omacKtri(), privateKey, cert));
        assertArrayEquals(DATA, CmsEnvelopedDataDecryptor.decrypt(omacKari(), privateKey, cert));
    }
}
