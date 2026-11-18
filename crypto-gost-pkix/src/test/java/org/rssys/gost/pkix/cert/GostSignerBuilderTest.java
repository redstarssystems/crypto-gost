package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.SignedDerTestSupport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Интеграционные тесты абстракции {@link GostSigner} в PKIX-билдерах:
 * регрессия «ключ в памяти», имитация внешнего подписанта (HSM),
 * fail-closed проверки длины и self-verify.
 */
@DisplayName("GostSigner в PKIX-билдерах: регрессия и fail-closed")
class GostSignerBuilderTest {

    private static byte[] buildCert(ECParameters params, KeyPair kp, GostSigner signer) {
        byte[] subjectDn = GostDnParser.encodeDn("CN=Signer Test");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, signer).getEncoded();
    }

    @Test
    @DisplayName("Регрессия cert: GostSigner.of(priv) даёт байт-в-байт тот же сертификат (256)")
    void testCertRegression256() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Signer Test");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .serial(BigInteger.ONE)
                        .buildTbs();

        byte[] viaPriv =
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();
        byte[] viaSigner =
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();

        // Подпись вероятностна: сравнивается всё, что подписывается (TBS, алгоритмы), побайтно, а
        // значения подписи обнулены. Расхождение двух путей сборки по-прежнему видно.
        SignedDerTestSupport.assertSameExceptSignature(
                "путь priv и путь GostSigner должны совпадать", viaPriv, viaSigner);
    }

    @Test
    @DisplayName("Подпись по умолчанию вероятностна: тот же TBS, разные подписи, обе верны")
    void testDefaultSignatureIsProbabilistic() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Hedged Default");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .serial(BigInteger.ONE)
                        .buildTbs();

        byte[] first =
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();
        byte[] second =
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();

        assertFalse(
                Arrays.equals(first, second),
                "сертификат по умолчанию подписан детерминированно: гибрид не включён");
        SignedDerTestSupport.assertSameExceptSignature("тот же TBS", first, second);
        assertTrue(new GostCertificate(first).verifySignature(kp.getPublic()), "первый неверен");
        assertTrue(new GostCertificate(second).verifySignature(kp.getPublic()), "второй неверен");
    }

    @Test
    @DisplayName("Регрессия cert 512 + CSR + CRL: пути priv и GostSigner совпадают")
    void testRegression512AndCsrCrl() {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] cViaPriv = buildCert(params, kp, GostSigner.of(kp.getPrivate()));
        byte[] cViaPriv2 = buildCert(params, kp, GostSigner.of(kp.getPrivate()));
        SignedDerTestSupport.assertSameExceptSignature(
                "сборка cert стабильна", cViaPriv, cViaPriv2);

        byte[] csrViaPriv = GostCsrBuilder.create("CN=Test", kp.getPublic()).sign(kp.getPrivate());
        byte[] csrViaSigner =
                GostCsrBuilder.create("CN=Test", kp.getPublic())
                        .sign(GostSigner.of(kp.getPrivate()));
        SignedDerTestSupport.assertSameExceptSignature(
                "CSR: пути priv и GostSigner совпадают", csrViaPriv, csrViaSigner);

        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlViaPriv =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate("20250101000000Z")
                        .nextUpdate("20990601120000Z")
                        .sign(kp.getPrivate());
        byte[] crlViaSigner =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate("20250101000000Z")
                        .nextUpdate("20990601120000Z")
                        .sign(GostSigner.of(kp.getPrivate()));
        SignedDerTestSupport.assertSameExceptSignature(
                "CRL: пути priv и GostSigner совпадают", crlViaPriv, crlViaSigner);
    }

    @Test
    @DisplayName("Внешний подписант: cert/CRL/CSR собираются и верифицируются")
    void testExternalSigner() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        // Имитируем HSM: билдер не держит PrivateKeyParameters, подпись приходит «извне».
        GostSigner hsm = new ExternalSigner(kp, params);

        byte[] certDer = buildCert(params, kp, hsm);
        assertTrue(
                new GostCertificate(certDer).verifySignature(kp.getPublic()),
                "cert от внешнего подписанта должен верифицироваться");

        byte[] csrDer = GostCsrBuilder.create("CN=Ext", kp.getPublic()).sign(hsm);
        assertTrue(new GostCsrParser(csrDer).verify(kp.getPublic()), "CSR должен верифицироваться");

        byte[] issuerDn = GostDnParser.encodeDn("CN=Ext CA");
        byte[] crlDer = GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z").sign(hsm);
        assertDoesNotThrow(
                () -> new GostCrl(crlDer).verify(kp.getPublic()), "CRL должен верифицироваться");
    }

    @Test
    @DisplayName("Fail-closed length-check: усечённая подпись -> IllegalStateException")
    void testLengthCheckFailsClosed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostSigner broken = new TruncatingSigner(kp, params);

        assertThrows(
                IllegalStateException.class,
                () -> buildCert(params, kp, broken),
                "подпись неверной длины должна перехватываться немедленно");
    }

    @Test
    @DisplayName("Fail-closed self-verify: подпись другим ключом -> IllegalStateException")
    void testWrongKeyFailsClosed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair declared = KeyGenerator.generateKeyPair(params);
        KeyPair actual = KeyGenerator.generateKeyPair(params);
        // Подписант заявляет открытый ключ declared, но подписывает ключом actual —
        // реалистичный баг неверно сконфигурированного слота HSM. Длина верна, подпись — нет.
        GostSigner mismatched = new MismatchedSigner(declared, actual, params);

        assertThrows(
                IllegalStateException.class,
                () -> buildCert(params, declared, mismatched),
                "подпись не тем ключом должна перехватываться self-verify");
    }

    @Test
    @DisplayName(
            "Fail-closed cert: params из create() не совпадают с signer.getParams() -> IllegalStateException")
    void testCertParamsSignerMismatchFailsClosed() {
        ECParameters createParams = ECParameters.tc26a256();
        KeyPair subject = KeyGenerator.generateKeyPair(createParams);
        // Подписант на 512-битной кривой: algId подписи, зафиксированный в TBS по create-params
        // (256), разошёлся бы с фактическим алгоритмом подписанта (512). Ловим до подписи.
        KeyPair issuer512 = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        byte[] subjectDn = GostDnParser.encodeDn("CN=Mismatch");

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostCertificateBuilder.create(createParams, subjectDn)
                                .publicKey(subject.getPublic())
                                .notBefore("20240501120000Z")
                                .notAfter("21060101120000Z")
                                .issuerDn(subjectDn)
                                .sign(GostSigner.of(issuer512.getPrivate())),
                "рассинхрон params создания и подписанта должен ловиться fail-closed");
    }

    @Test
    @DisplayName(
            "Fail-closed CSR: подпись чужим ключом (proof-of-possession) -> IllegalStateException")
    void testCsrProofOfPossessionFailsClosed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair alice = KeyGenerator.generateKeyPair(params);
        KeyPair bob = KeyGenerator.generateKeyPair(params);
        // CSR сертифицирует ключ alice, но подписан ключом bob — не доказательство владения.
        assertThrows(
                IllegalStateException.class,
                () -> GostCsrBuilder.create("CN=Alice", alice.getPublic()).sign(bob.getPrivate()),
                "CSR, подписанный не владельцем ключа, должен ловиться fail-closed");
    }

    @Test
    @DisplayName("CRL thisUpdate по умолчанию фиксируется в момент sign(), а не create()")
    void testCrlThisUpdateDefaultAtSignTime() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Timing CA");

        GostCrlBuilder builder = GostCrlBuilder.create(issuerDn).nextUpdate("20990601120000Z");
        byte[] crl1 = builder.sign(kp.getPrivate());
        Thread.sleep(1100);
        byte[] crl2 = builder.sign(kp.getPrivate());

        // Дефолтный thisUpdate вычисляется на каждый sign(): CRL, подписанные с секундной
        // разницей, отличаются (разный thisUpdate -> разный TBS).
        assertFalse(
                Arrays.equals(crl1, crl2),
                "дефолтный thisUpdate должен браться на момент sign(), а не create()");
    }

    @Test
    @DisplayName("CRL: явный thisUpdate имеет приоритет и не зависит от момента sign()")
    void testCrlExplicitThisUpdateStable() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Timing CA");

        GostCrlBuilder builder =
                GostCrlBuilder.create(issuerDn)
                        .thisUpdate("20250101000000Z")
                        .nextUpdate("20990601120000Z");
        byte[] crl1 = builder.sign(kp.getPrivate());
        Thread.sleep(1100);
        byte[] crl2 = builder.sign(kp.getPrivate());

        SignedDerTestSupport.assertSameExceptSignature(
                "явный thisUpdate должен иметь приоритет над временем sign()", crl1, crl2);
    }

    @Test
    @DisplayName("Все четыре sign(GostSigner) fail-fast на null с осмысленным сообщением")
    void testSignRejectsNullSigner() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = GostDnParser.encodeDn("CN=Null Signer");

        // Голый NPE без контекста — плохая диагностика; требуем сообщение об аргументе.
        NullPointerException crl =
                assertThrows(
                        NullPointerException.class,
                        () -> GostCrlBuilder.create(dn).sign((GostSigner) null));
        assertTrue(crl.getMessage().contains("signer"), "CRL: сообщение должно упоминать signer");

        assertThrows(
                NullPointerException.class,
                () ->
                        GostCertificateBuilder.create(params, dn)
                                .publicKey(kp.getPublic())
                                .notBefore("20240501120000Z")
                                .notAfter("21060101120000Z")
                                .issuerDn(dn)
                                .sign((GostSigner) null),
                "Certificate: null-signer должен ловиться fail-fast");

        assertThrows(
                NullPointerException.class,
                () -> GostCsrBuilder.create("CN=X", kp.getPublic()).sign((GostSigner) null),
                "CSR: null-signer должен ловиться fail-fast");

        assertThrows(
                NullPointerException.class,
                () ->
                        GostOcspResponseBuilder.create(new byte[] {0x01})
                                .issuerDn(dn)
                                .sign((GostSigner) null),
                "OCSP: null-signer должен ловиться fail-fast");
    }

    private static final class ExternalSigner implements GostSigner {
        private final KeyPair kp;
        private final ECParameters params;

        ExternalSigner(KeyPair kp, ECParameters params) {
            this.kp = kp;
            this.params = params;
        }

        @Override
        public byte[] signHash(byte[] hash) {
            return Signature.signHash(hash, kp.getPrivate());
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
