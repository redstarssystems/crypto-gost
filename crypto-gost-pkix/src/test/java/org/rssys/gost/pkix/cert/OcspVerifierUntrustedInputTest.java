package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Недоверенные поля OCSP-ответа (certs и ResponderID byKey) приводят только к
 * {@link PkixException}: проверяющий код не выпускает непроверяемые исключения.
 */
@DisplayName("OcspVerifier: недоверенный ввод — certs и ResponderID byKey")
class OcspVerifierUntrustedInputTest {

    private static final byte[] LEAF_SERIAL = {0x01, 0x23, 0x45};

    /** Число искажений в детерминированном переборе; зерно фиксировано для воспроизводимости. */
    private static final int MUTATION_ROUNDS = 3000;

    private static final long MUTATION_SEED = 0x5EED_0348L;

    private static PkixCertTestHelper.CertBundle ca;
    private static PkixCertTestHelper.CertBundle foreignCa;
    private static PkixCertTestHelper.CertBundle delegate;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ECParameters params = ECParameters.tc26a256();
        ca = PkixCertTestHelper.createRootCA(params);
        foreignCa = PkixCertTestHelper.createRootCA(params);
        delegate = createDelegate(params);
    }

    private static PkixCertTestHelper.CertBundle createDelegate(ECParameters params)
            throws Exception {
        byte[] keyUsage =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                null,
                keyUsage,
                new String[] {GostOids.EXT_OCSP_SIGNING},
                false,
                null);
    }

    // ------------------------------------------------------------------
    // Мусор в certs
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Подпись УЦ напрямую: сертификаты из certs не разбираются, мусор не мешает")
    void directSignature_garbageCertsNotParsed() {
        byte[] ocsp =
                GostOcspResponseBuilder.create(LEAF_SERIAL)
                        .issuerDn(ca.subjectDn)
                        .withResponderByKey()
                        .withDelegatedCerts(garbageCerts())
                        .sign(ca.priv);

        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                "Подпись напрямую ключом УЦ принимается без разбора certs");
    }

    @Test
    @DisplayName("Чужой подписант и мусор в certs: SIGNATURE_INVALID, не IllegalArgumentException")
    void garbageCerts_foreignSigner_signatureInvalid() {
        for (byte[] garbage : garbageCerts()) {
            byte[] ocsp =
                    GostOcspResponseBuilder.create(LEAF_SERIAL)
                            .issuerDn(ca.subjectDn)
                            .withResponderByKey()
                            .withDelegatedCerts(garbage)
                            .sign(foreignCa.priv);

            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                            "Нет подходящего подписанта: ожидается PkixException");
            assertEquals(
                    PkixException.Reason.SIGNATURE_INVALID,
                    ex.reason(),
                    "Нераспознанный сертификат пропускается, итог — неверная подпись");
        }
    }

    @Test
    @DisplayName("Действительный делегат после мусора в certs: ответ принимается")
    void validDelegateAfterGarbage_accepted() throws Exception {
        // Разбор ответа ограничивает число сертификатов в certs, поэтому берём часть мусора
        byte[][] garbage = Arrays.copyOf(garbageCerts(), 3);
        byte[][] certs = Arrays.copyOf(garbage, garbage.length + 1);
        certs[garbage.length] = delegate.cert.getEncoded();
        byte[] ocsp =
                GostOcspResponseBuilder.create(LEAF_SERIAL)
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withResponderByKey()
                        .withDelegatedCerts(certs)
                        .sign(delegate.priv);

        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                "Мусор пропускается, делегат с подписью УЦ распознаётся");
    }

    // ------------------------------------------------------------------
    // ResponderID byKey
    // ------------------------------------------------------------------

    @Test
    @DisplayName("byKey Стрибог-256 и Стрибог-512 сверяются и принимаются")
    void byKeyStreebog_accepted() {
        for (int hlen :
                new int[] {GostOids.STREEBOG_256_HASH_LEN, GostOids.STREEBOG_512_HASH_LEN}) {
            byte[] ocsp =
                    GostOcspResponseBuilder.create(LEAF_SERIAL)
                            .issuerDn(ca.subjectDn)
                            .withResponderByKey(hlen)
                            .sign(ca.priv);
            assertDoesNotThrow(
                    () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                    "byKey на " + hlen + " байт с верным хэшем принимается");
        }
    }

    @Test
    @DisplayName("byKey Стрибог с чужим хэшем: отказ")
    void byKeyStreebogMismatch_rejected() {
        for (int hlen :
                new int[] {GostOids.STREEBOG_256_HASH_LEN, GostOids.STREEBOG_512_HASH_LEN}) {
            byte[] foreignKeyHash = CertIdHasher.hashIssuerPublicKey(foreignCa.cert, hlen);
            byte[] ocsp = signByKey(ca, foreignKeyHash, ca.priv);

            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                            "Чужой хэш ключа на " + hlen + " байт должен отвергаться");
            assertTrue(
                    ex.getMessage().contains("responder key hash mismatch"),
                    "Ожидался отказ по хэшу ключа, получено: " + ex.getMessage());
        }
    }

    @Test
    @DisplayName("byKey на 20 байт (SHA-1 по норме) принимается без сверки")
    void byKeySha1Length_acceptedWithoutComparison() {
        byte[] anyTwentyBytes = new byte[GostOids.SHA1_HASH_LEN];
        Arrays.fill(anyTwentyBytes, (byte) 0x5A);
        byte[] ocsp = signByKey(ca, anyTwentyBytes, ca.priv);

        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                "Ответ стороннего ответчика с 20-байтным byKey принимается: подпись верна");
    }

    @Test
    @DisplayName("byKey прочих допустимых парсеру длин: PkixException, не IllegalArgumentException")
    void byKeyUnsupportedLengths_pkixException() {
        for (int len : new int[] {21, 31, 33, 48, 63}) {
            byte[] ocsp = signByKey(ca, new byte[len], ca.priv);

            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                            "Длина хэша " + len + " не поддерживается: ожидается PkixException");
            assertTrue(
                    ex.getMessage().contains("unsupported responder key hash length"),
                    "Ожидался отказ по длине, получено: " + ex.getMessage());
        }
    }

    @Test
    @DisplayName("byKey вне 20..64 байт: отказ уже при разборе ответа")
    void byKeyOutOfRange_parserRejects() {
        for (int len : new int[] {0, 1, 19, 65, 100}) {
            byte[] ocsp = signByKey(ca, new byte[len], ca.priv);
            assertThrows(
                    PkixException.class,
                    () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                    "Длина хэша " + len + " вне 20..64: ожидается PkixException");
        }
    }

    @Test
    @DisplayName(
            "Неверная подпись и byKey на 20 байт: SIGNATURE_INVALID, подпись проверяется раньше")
    void invalidSignatureWithSha1ByKey_signatureInvalid() {
        // Подписано ключом чужого УЦ, а проверяется ключом нашего: ResponderID не должен
        // «спасать» ответ и не должен маскировать неверную подпись
        byte[] ocsp = signByKey(ca, new byte[GostOids.SHA1_HASH_LEN], foreignCa.priv);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                        "Неверная подпись должна отвергаться");
        assertEquals(
                PkixException.Reason.SIGNATURE_INVALID,
                ex.reason(),
                "Порядок проверки: сначала подпись, затем ResponderID");
    }

    // ------------------------------------------------------------------
    // Детерминированный перебор искажений
    // ------------------------------------------------------------------

    @Test
    @DisplayName(
            "Искажённые ответы с делегатом в certs: verify и verifyEvidence дают только PkixException")
    void mutatedResponses_onlyPkixException() throws Exception {
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x3C);
        // Два исходных ответа: good с byKey и revoked с nonce и byName. Второй задевает
        // разбор расширений и статуса отзыва, до которых порча первого почти не доходит.
        byte[] goodByKey =
                GostOcspResponseBuilder.create(LEAF_SERIAL)
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .withResponderByKey()
                        .withDelegatedCerts(delegate.cert.getEncoded())
                        .sign(delegate.priv);
        byte[] revokedWithNonce =
                GostOcspResponseBuilder.create(LEAF_SERIAL)
                        .caPublicKey(ca.cert.getPublicKey())
                        .issuerDn(ca.subjectDn)
                        .revoked("20250101000000Z")
                        .nonce(nonce)
                        .withDelegatedCerts(delegate.cert.getEncoded())
                        .sign(delegate.priv);
        assertDoesNotThrow(
                () -> OcspVerifier.verify(goodByKey, LEAF_SERIAL, ca.cert),
                "Исходный ответ для искажений должен быть верным");
        assertThrows(
                PkixException.class,
                () -> OcspVerifier.verify(revokedWithNonce, LEAF_SERIAL, ca.cert, nonce),
                "Исходный второй ответ отозван, отказ ожидаем");

        Random random = new Random(MUTATION_SEED);
        for (int round = 0; round < MUTATION_ROUNDS; round++) {
            byte[] source = round % 2 == 0 ? goodByKey : revokedWithNonce;
            byte[] mutated = mutate(source, random);
            expectOnlyPkixException(
                    "verify с nonce",
                    round,
                    () -> OcspVerifier.verify(mutated, LEAF_SERIAL, ca.cert, nonce));
            expectOnlyPkixException(
                    "verify", round, () -> OcspVerifier.verify(mutated, LEAF_SERIAL, ca.cert));
            expectOnlyPkixException(
                    "verifyEvidence",
                    round,
                    () ->
                            OcspVerifier.verifyEvidence(
                                    mutated,
                                    LEAF_SERIAL,
                                    ca.cert,
                                    nowWindow(),
                                    RevocationFreshnessPolicy.ETSI_DEFAULT));
        }
    }

    /** Отказ допустим только как {@link PkixException}; любое иное исключение — провал. */
    private static void expectOnlyPkixException(String method, int round, Executable call) {
        try {
            call.execute();
        } catch (PkixException expected) {
            // Отказ по контракту
        } catch (Throwable other) {
            fail(failureMessage(method, round, other));
        }
    }

    private static String failureMessage(String method, int round, Throwable e) {
        return method
                + ", раунд "
                + round
                + " (зерно "
                + MUTATION_SEED
                + "): вместо PkixException выброшено "
                + e;
    }

    private static RevocationEvidenceWindow nowWindow() {
        Instant now = Instant.now();
        return new RevocationEvidenceWindow(now, now);
    }

    private static byte[] mutate(byte[] source, Random random) {
        byte[] mutated = source.clone();
        int kind = random.nextInt(4);
        if (kind == 0) {
            // Усечение: ломает длины вложенных TLV
            return Arrays.copyOf(mutated, random.nextInt(mutated.length));
        }
        int flips = 1 + random.nextInt(3);
        for (int i = 0; i < flips; i++) {
            int pos = random.nextInt(mutated.length);
            mutated[pos] =
                    kind == 1
                            ? (byte) random.nextInt(256)
                            : (byte) (mutated[pos] ^ (1 << random.nextInt(8)));
        }
        return mutated;
    }

    // ------------------------------------------------------------------
    // Вспомогательные методы
    // ------------------------------------------------------------------

    /**
     * Корректные по TLV, но не являющиеся сертификатами элементы certs. Ответы с ними строятся с
     * byKey: при byName построитель сам разбирает первый сертификат из certs и отверг бы мусор.
     */
    private static byte[][] garbageCerts() {
        return new byte[][] {
            DerCodec.encodeSequence(new byte[0]),
            DerCodec.encodeSequence(DerCodec.encodeTlv(0x02, new byte[] {0x01})),
            DerCodec.encodeSequence(
                    DerCodec.encodeSequence(DerCodec.encodeTlv(0x04, new byte[] {0x00, 0x01}))),
            DerCodec.encodeTlv(0x04, new byte[] {(byte) 0xFF, 0x00, 0x7F}),
            DerCodec.encodeSequence(
                    DerCodec.concat(
                            DerCodec.encodeSequence(DerCodec.encodeTlv(0x05, new byte[0])),
                            DerCodec.encodeSequence(DerCodec.encodeTlv(0x05, new byte[0])),
                            DerCodec.encodeBitString(new byte[] {0x01})))
        };
    }

    /**
     * Ответ с произвольным ResponderID byKey: построитель библиотеки выпускает только 32 и
     * 64 байта, а для проверки сторонних ответов нужны иные длины. Запись о LEAF_SERIAL
     * ссылается на {@code ca}; подпись ставит {@code signerPriv}.
     */
    private static byte[] signByKey(
            PkixCertTestHelper.CertBundle issuer,
            byte[] responderKeyHash,
            PrivateKeyParameters signerPriv) {
        String now = GostSignatureHelper.nowGeneralizedTime();
        int hlen = GostOids.STREEBOG_256_HASH_LEN;
        byte[] certId =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256)),
                        DerCodec.encodeOctetString(CertIdHasher.hashIssuerName(issuer.cert, hlen)),
                        DerCodec.encodeOctetString(
                                CertIdHasher.hashIssuerPublicKey(issuer.cert, hlen)),
                        DerCodec.encodeTlv(0x02, LEAF_SERIAL));
        byte[] nextUpdate =
                DerCodec.encodeTlv(
                        0xA0,
                        DerCodec.encodeTlv(
                                0x18,
                                GostSignatureHelper.nowPlusYears(3)
                                        .getBytes(StandardCharsets.US_ASCII)));
        byte[] singleResponse =
                DerCodec.encodeSequence(
                        certId,
                        DerCodec.encodeTlv(0x80, new byte[0]),
                        DerCodec.encodeGeneralizedTime(now),
                        nextUpdate);

        // byKey [2] EXPLICIT KeyHash (OCTET STRING)
        byte[] responderId =
                DerCodec.encodeTlv(
                        DerCodec.TAG_CTX_CONSTRUCTED_2,
                        DerCodec.encodeOctetString(responderKeyHash));
        byte[] producedAt = DerCodec.encodeTlv(0x18, now.getBytes(StandardCharsets.US_ASCII));
        ByteArrayOutputStream responses = new ByteArrayOutputStream();
        responses.write(singleResponse, 0, singleResponse.length);
        byte[] tbs =
                DerCodec.encodeSequence(
                        DerCodec.concat(
                                responderId,
                                producedAt,
                                DerCodec.encodeSequence(responses.toByteArray())));

        PublicKeyParameters signerPub = signerPriv.derivePublicKey();
        byte[] hash = GostSignatureHelper.doHash(tbs, signerPub.getParams().hlen);
        byte[] signature = GostSignatureHelper.signHashChecked(hash, GostSigner.of(signerPriv));
        byte[] basicOcsp =
                DerCodec.encodeSequence(
                        tbs,
                        GostSignatureHelper.buildAlgId(signerPub.getParams()),
                        DerCodec.encodeBitString(signature));
        byte[] responseBytes =
                DerCodec.encodeTlv(
                        0xA0,
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.OCSP_BASIC),
                                DerCodec.encodeOctetString(basicOcsp)));
        return DerCodec.encodeSequence(new byte[] {0x0A, 0x01, 0x00}, responseBytes);
    }
}
