package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostDerParser;
import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Интеграционные тесты абстракции {@link GostSigner} в оставшихся PKIX-билдерах
 * (CmsSignedDataBuilder, GostOcspResponseBuilder, CountersignatureBuilder,
 * GostOcspRequestBuilder) и транзитивных потребителях.
 * План 231.
 */
@DisplayName("GostSigner в CMS/OCSP/countersignature билдерах")
class GostSignerBuildersExtensionTest {

    private static final byte[] DATA = "test data for signing".getBytes();

    private static ECParameters params256;
    private static ECParameters params512;
    private static KeyPair kp256;
    private static KeyPair kp512;
    private static GostCertificate cert256;
    private static GostCertificate cert512;

    @BeforeAll
    static void setUp() {
        params256 = ECParameters.tc26a256();
        params512 = ECParameters.tc26a512();
        kp256 = KeyGenerator.generateKeyPair(params256);
        kp512 = KeyGenerator.generateKeyPair(params512);
        cert256 = CmsTestUtils.createSelfSignedCert(kp256.getPrivate(), kp256.getPublic());
        cert512 = CmsTestUtils.createSelfSignedCert(kp512.getPrivate(), kp512.getPublic());
    }

    // ========================================================================
    // 1. CmsSignedDataBuilder — регрессия, truncated, mismatched
    // ========================================================================

    @Test
    @DisplayName(
            "CmsSignedDataBuilder: регрессия — пути priv и GostSigner.of() дают идентичный DER (256)")
    void cmsSignedDataRegression256() {
        byte[] viaPriv =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .addSigner(kp256.getPrivate(), cert256)
                        .build();
        byte[] viaSigner =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .addSigner(GostSigner.of(kp256.getPrivate()), cert256)
                        .build();

        assertArrayEquals(
                viaPriv,
                viaSigner,
                "CMS SignedData: пути priv и GostSigner должны давать идентичный DER");
    }

    @Test
    @DisplayName("CmsSignedDataBuilder: регрессия 512")
    void cmsSignedDataRegression512() {
        byte[] viaPriv =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .digestAlgorithm(org.rssys.gost.pkix.GostOids.DIGEST_512)
                        .addSigner(kp512.getPrivate(), cert512)
                        .build();
        byte[] viaSigner =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .digestAlgorithm(org.rssys.gost.pkix.GostOids.DIGEST_512)
                        .addSigner(GostSigner.of(kp512.getPrivate()), cert512)
                        .build();

        assertArrayEquals(
                viaPriv,
                viaSigner,
                "CMS SignedData 512: пути priv и GostSigner должны давать идентичный DER");
    }

    @Test
    @DisplayName("CmsSignedDataBuilder: truncated-подпись -> IllegalStateException")
    void cmsSignedDataTruncated() {
        GostSigner broken = new TruncatingSigner(kp256, params256);

        assertThrows(
                IllegalStateException.class,
                () -> CmsSignedDataBuilder.create().data(DATA).addSigner(broken, cert256).build(),
                "усечённая подпись должна перехватываться fail-closed");
    }

    @Test
    @DisplayName("CmsSignedDataBuilder: mismatched-ключ -> IllegalStateException")
    void cmsSignedDataMismatched() {
        KeyPair actual = KeyGenerator.generateKeyPair(params256);
        GostSigner mismatched = new MismatchedSigner(kp256, actual, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        CmsSignedDataBuilder.create()
                                .data(DATA)
                                .addSigner(mismatched, cert256)
                                .build(),
                "подпись не тем ключом должна перехватываться self-verify");
    }

    // ========================================================================
    // 2. GostOcspResponseBuilder — регрессия, truncated, mismatched
    // ========================================================================

    @Test
    @DisplayName(
            "GostOcspResponseBuilder: регрессия — пути priv и GostSigner.of() дают идентичный DER")
    void ocspResponseRegression() {
        byte[] viaPriv =
                GostOcspResponseBuilder.create(cert256.getSerialNumber())
                        .issuerDn(cert256.getSubjectDnBytes())
                        .sign(kp256.getPrivate());
        byte[] viaSigner =
                GostOcspResponseBuilder.create(cert256.getSerialNumber())
                        .issuerDn(cert256.getSubjectDnBytes())
                        .sign(GostSigner.of(kp256.getPrivate()));

        assertArrayEquals(
                viaPriv,
                viaSigner,
                "OCSP ответ: пути priv и GostSigner должны давать идентичный DER");
    }

    @Test
    @DisplayName("GostOcspResponseBuilder: truncated-подпись -> IllegalStateException")
    void ocspResponseTruncated() {
        GostSigner broken = new TruncatingSigner(kp256, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspResponseBuilder.create(cert256.getSerialNumber())
                                .issuerDn(cert256.getSubjectDnBytes())
                                .sign(broken),
                "усечённая подпись должна перехватываться fail-closed");
    }

    @Test
    @DisplayName("GostOcspResponseBuilder: mismatched-ключ -> IllegalStateException")
    void ocspResponseMismatched() {
        KeyPair actual = KeyGenerator.generateKeyPair(params256);
        GostSigner mismatched = new MismatchedSigner(kp256, actual, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspResponseBuilder.create(cert256.getSerialNumber())
                                .issuerDn(cert256.getSubjectDnBytes())
                                .sign(mismatched),
                "подпись не тем ключом должна перехватываться self-verify");
    }

    // ========================================================================
    // 3. CountersignatureBuilder — регрессия, truncated, mismatched
    // ========================================================================

    @Test
    @DisplayName(
            "CountersignatureBuilder: регрессия — пути priv и GostSigner.of() дают идентичный DER")
    void countersigRegression() {
        byte[] parentSig = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(parentSig);

        String digestOid = org.rssys.gost.pkix.GostOids.DIGEST_256;

        byte[] viaPriv =
                CountersignatureBuilder.buildCountersignature(
                        parentSig, kp256.getPrivate(), cert256, digestOid);
        byte[] viaSigner =
                CountersignatureBuilder.buildCountersignature(
                        parentSig, GostSigner.of(kp256.getPrivate()), cert256, digestOid);

        assertArrayEquals(
                viaPriv,
                viaSigner,
                "Countersignature: пути priv и GostSigner должны давать идентичный DER");
    }

    @Test
    @DisplayName("CountersignatureBuilder: truncated-подпись -> IllegalStateException")
    void countersigTruncated() {
        byte[] parentSig = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(parentSig);
        GostSigner broken = new TruncatingSigner(kp256, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        CountersignatureBuilder.buildCountersignature(
                                parentSig,
                                broken,
                                cert256,
                                org.rssys.gost.pkix.GostOids.DIGEST_256),
                "усечённая подпись должна перехватываться fail-closed");
    }

    @Test
    @DisplayName("CountersignatureBuilder: mismatched-ключ -> IllegalStateException")
    void countersigMismatched() {
        byte[] parentSig = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(parentSig);
        KeyPair actual = KeyGenerator.generateKeyPair(params256);
        GostSigner mismatched = new MismatchedSigner(kp256, actual, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        CountersignatureBuilder.buildCountersignature(
                                parentSig,
                                mismatched,
                                cert256,
                                org.rssys.gost.pkix.GostOids.DIGEST_256),
                "подпись не тем ключом должна перехватываться self-verify");
    }

    // ========================================================================
    // 4. GostOcspRequestBuilder — регрессия, truncated, mismatched
    // ========================================================================

    @Test
    @DisplayName(
            "GostOcspRequestBuilder: регрессия — пути priv и GostSigner.of() дают валидные подписи")
    void ocspRequestRegression() {
        byte[] viaPriv =
                GostOcspRequestBuilder.create()
                        .targetCert(cert256.getEncoded())
                        .issuerCert(cert256.getEncoded())
                        .signKey(kp256.getPrivate())
                        .params(params256)
                        .build();
        byte[] viaSigner =
                GostOcspRequestBuilder.create()
                        .targetCert(cert256.getEncoded())
                        .issuerCert(cert256.getEncoded())
                        .signKey(GostSigner.of(kp256.getPrivate()))
                        .build();

        assertTrue(
                verifyOcspRequestSignature(viaPriv, kp256.getPublic()),
                "путь priv должен давать валидную подпись");
        assertTrue(
                verifyOcspRequestSignature(viaSigner, kp256.getPublic()),
                "путь GostSigner должен давать валидную подпись");
    }

    @Test
    @DisplayName("GostOcspRequestBuilder: params()+GostSigner запрещена -> IllegalStateException")
    void ocspRequestParamsWithGostSignerForbidden() {
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(cert256.getEncoded())
                                .issuerCert(cert256.getEncoded())
                                .signKey(GostSigner.of(kp256.getPrivate()))
                                .params(params256)
                                .build(),
                "params() вместе с signKey(GostSigner) должна бросать исключение");
    }

    @Test
    @DisplayName("GostOcspRequestBuilder: truncated-подпись -> IllegalStateException")
    void ocspRequestTruncated() {
        GostSigner broken = new TruncatingSigner(kp256, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(cert256.getEncoded())
                                .issuerCert(cert256.getEncoded())
                                .signKey(broken)
                                .build(),
                "усечённая подпись должна перехватываться fail-closed");
    }

    @Test
    @DisplayName("GostOcspRequestBuilder: mismatched-ключ -> IllegalStateException")
    void ocspRequestMismatched() {
        KeyPair actual = KeyGenerator.generateKeyPair(params256);
        GostSigner mismatched = new MismatchedSigner(kp256, actual, params256);

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(cert256.getEncoded())
                                .issuerCert(cert256.getEncoded())
                                .signKey(mismatched)
                                .build(),
                "подпись не тем ключом должна перехватываться self-verify");
    }

    // ========================================================================
    // 5. TspResponseBuilder smoke: GostSigner доходит до CmsSignedDataBuilder
    // ========================================================================

    @Test
    @DisplayName(
            "TspResponseBuilder smoke: GostSigner прокидывается до CmsSignedDataBuilder, ответ проходит верификацию")
    void tspResponseSmoke() throws Exception {
        ECParameters tsaParams = ECParameters.tc26a256();
        KeyPair tsaKp = KeyGenerator.generateKeyPair(tsaParams);
        GostCertificate tsaCert = CmsTestUtils.createTsaCert(tsaKp.getPrivate(), tsaKp.getPublic());

        byte[] hash = org.rssys.gost.api.Digest.digest256(DATA);
        byte[] tspReqDer =
                org.rssys.gost.pkix.tsp.TspRequestBuilder.create()
                        .messageImprint(hash, org.rssys.gost.pkix.GostOids.DIGEST_256)
                        .certReq(true)
                        .build();

        org.rssys.gost.pkix.tsp.TspRequest request =
                org.rssys.gost.pkix.tsp.TspRequest.fromDer(tspReqDer);

        byte[] responseDer =
                org.rssys.gost.pkix.tsp.TspResponseBuilder.create(request)
                        .signer(GostSigner.of(tsaKp.getPrivate()), tsaCert)
                        .policyOid("1.3.6.1.4.1.4146.1.2.1")
                        .serialNumber(java.math.BigInteger.ONE)
                        .buildGranted();

        org.rssys.gost.pkix.tsp.TspResponse response =
                org.rssys.gost.pkix.tsp.TspResponse.fromDer(responseDer);
        assertDoesNotThrow(
                () ->
                        response.verify(
                                hash,
                                org.rssys.gost.pkix.GostOids.DIGEST_256,
                                request.nonce(),
                                tsaCert),
                "TSP ответ с GostSigner должен проходить верификацию");
    }

    // ========================================================================
    // 6. CmsSignedAndEnvelopedData smoke: signThenEncrypt + encryptThenSign с GostSigner
    // ========================================================================

    @Test
    @DisplayName("CmsSignedAndEnvelopedData smoke: signThenEncrypt с GostSigner — decryptAndVerify")
    void signThenEncryptSmoke() throws Exception {
        KeyPair recipientKp = KeyGenerator.generateKeyPair(params256);
        GostCertificate recipientCert =
                CmsTestUtils.createSelfSignedCert(
                        recipientKp.getPrivate(), recipientKp.getPublic());

        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        DATA, GostSigner.of(kp256.getPrivate()), cert256, recipientCert);

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, recipientKp.getPrivate(), recipientCert, cert256);

        assertArrayEquals(DATA, result.data(), "decryptAndVerify должен вернуть исходные данные");
    }

    @Test
    @DisplayName("CmsSignedAndEnvelopedData smoke: encryptThenSign с GostSigner — verifyAndDecrypt")
    void encryptThenSignSmoke() throws Exception {
        KeyPair recipientKp = KeyGenerator.generateKeyPair(params256);
        GostCertificate recipientCert =
                CmsTestUtils.createSelfSignedCert(
                        recipientKp.getPrivate(), recipientKp.getPublic());

        byte[] combined =
                CmsSignedAndEnvelopedData.encryptThenSign(
                        DATA, GostSigner.of(kp256.getPrivate()), cert256, recipientCert);

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.verifyAndDecrypt(
                        combined, recipientKp.getPrivate(), recipientCert, cert256);

        assertArrayEquals(DATA, result.data(), "verifyAndDecrypt должен вернуть исходные данные");
    }

    // ========================================================================
    // 7. CAdESExtender smoke: embedCountersignature с GostSigner
    // ========================================================================

    @Test
    @DisplayName(
            "CAdESExtender smoke: embedCountersignature с GostSigner — результат проходит verifyCountersignature")
    void cadesExtenderCountersignatureSmoke() throws Exception {
        // 1. Строим базовый CAdES-BES
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .addSigner(kp256.getPrivate(), cert256)
                        .withCAdES()
                        .build();

        // 2. Встраиваем countersignature через GostSigner
        KeyPair csKp = KeyGenerator.generateKeyPair(params256);
        GostCertificate csCert =
                CmsTestUtils.createSelfSignedCert(csKp.getPrivate(), csKp.getPublic());

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, GostSigner.of(csKp.getPrivate()), csCert);

        // 3. Верифицируем — оба сертификата как доверенные корни
        VerifiedCAdESData result =
                CAdESExtender.verifyCountersignature(countersigned, cert256, csCert);

        assertArrayEquals(
                DATA, result.data(), "verifyCountersignature должен вернуть исходные данные");
    }

    // ========================================================================
    // 8. OcspRequestBuilder (jsse) smoke: проверка в jsse-модуле отдельно
    // ========================================================================

    // Тест для jsse-модуля находится в crypto-gost-jsse:
    // OcspRequestBuilderSignerTest — проверяет подпись GostSigner после парсинга
    //

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /**
     * Извлекает signatureValue из DER OCSPRequest и проверяет подпись.
     */
    private static boolean verifyOcspRequestSignature(byte[] ocspDer, PublicKeyParameters pubKey) {
        int[] topSeq = GostDerParser.readTlv(ocspDer, 0);
        int pos = topSeq[0];
        int end = topSeq[1];

        while (pos < end) {
            if ((ocspDer[pos] & 0xFF) == 0xA0) {
                int[] sigTlv = GostDerParser.readTlv(ocspDer, pos);
                byte[] sigSeq = Arrays.copyOfRange(ocspDer, sigTlv[0], sigTlv[1]);

                // sigSeq = SEQUENCE { algId, BIT STRING }
                int[] sigSeqBounds = GostDerParser.readTlv(sigSeq, 0);
                int sigOffset = sigSeqBounds[0];
                int sigEnd = sigSeqBounds[1];

                // Пропускаем algId, находим BIT STRING
                while (sigOffset < sigEnd) {
                    if ((sigSeq[sigOffset] & 0xFF) == DerCodec.TAG_BIT_STRING) {
                        byte[] sigValue = DerCodec.parseBitString(sigSeq, sigOffset);
                        byte[] tbs = Arrays.copyOfRange(ocspDer, topSeq[0], pos);
                        int hlen = pubKey.getParams().hlen;
                        byte[] tbsHash =
                                hlen == GostOids.STREEBOG_512_HASH_LEN
                                        ? Digest.digest512(tbs)
                                        : Digest.digest256(tbs);
                        return Signature.verifyHash(tbsHash, sigValue, pubKey);
                    }
                    int[] tlv = GostDerParser.readTlv(sigSeq, sigOffset);
                    sigOffset = tlv[1];
                }
                return false;
            }
            int[] tlv = GostDerParser.readTlv(ocspDer, pos);
            pos = tlv[1];
        }
        return false;
    }

    /**
     * Извлекает содержимое BIT STRING без первого unused-bits октета.
     */
    private static byte[] getBitStringContent(byte[] buf, int off, int end) {
        return DerCodec.parseBitString(buf, off);
    }

    // Покрытие в этом модуле: ocspRequestRegression (проверяет GostOcspRequestBuilder,
    // в который делегирует jsse-билдер). Прямой smoke-тест jsse — в модуле jsse.

    // ========================================================================
    // Вспомогательные реализации GostSigner для fail-closed тестов
    // ========================================================================

    private static final class TruncatingSigner implements GostSigner {
        private final KeyPair kp;
        private final ECParameters params;

        TruncatingSigner(KeyPair kp, ECParameters params) {
            this.kp = kp;
            this.params = params;
        }

        @Override
        public byte[] signHash(byte[] hash) {
            byte[] sig = Signature.signHash(hash, kp.getPrivate());
            return Arrays.copyOf(sig, sig.length - 1);
        }

        @Override
        public ECParameters getParams() {
            return params;
        }

        @Override
        public PublicKeyParameters getPublicKey() {
            return kp.getPublic();
        }
    }

    private static final class MismatchedSigner implements GostSigner {
        private final KeyPair declared;
        private final KeyPair actual;
        private final ECParameters params;

        MismatchedSigner(KeyPair declared, KeyPair actual, ECParameters params) {
            this.declared = declared;
            this.actual = actual;
            this.params = params;
        }

        @Override
        public byte[] signHash(byte[] hash) {
            return Signature.signHash(hash, actual.getPrivate());
        }

        @Override
        public ECParameters getParams() {
            return params;
        }

        @Override
        public PublicKeyParameters getPublicKey() {
            return declared.getPublic();
        }
    }
}
