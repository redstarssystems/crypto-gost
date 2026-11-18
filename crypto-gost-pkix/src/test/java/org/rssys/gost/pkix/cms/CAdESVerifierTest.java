package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESVerifier: якоря, политика срока якоря и контракт уровней")
class CAdESVerifierTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String EXPIRED_ROOT_DN = "CN=Expired CAdES Root";

    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static KeyPair expiredRootKp;
    private static GostCertificate expiredRoot;
    private static KeyPair expiredRootLeafKp;
    private static GostCertificate expiredRootLeaf;
    private static KeyPair tsaLeafKp;
    private static GostCertificate tsaLeaf;

    @BeforeAll
    static void setUp() {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert = CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());

        // Корень с истёкшим сроком и два листа от него: подписант/контрподписант и TSA
        expiredRootKp = KeyGenerator.generateKeyPair(PARAMS);
        expiredRoot =
                GostCertificateBuilder.create(PARAMS, EXPIRED_ROOT_DN)
                        .publicKey(expiredRootKp.getPublic())
                        .notBefore("200101000000Z")
                        .notAfter("210101000000Z")
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .ski()
                        .randomSerial()
                        .sign(expiredRootKp.getPrivate());
        expiredRootLeafKp = KeyGenerator.generateKeyPair(PARAMS);
        expiredRootLeaf = issueLeaf("CN=Leaf Under Expired Root", expiredRootLeafKp, null);
        tsaLeafKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaLeaf = issueLeaf("CN=TSA Under Expired Root", tsaLeafKp, GostOids.EXT_TIME_STAMPING);
    }

    private static GostCertificate issueLeaf(String subjectDn, KeyPair subjectKp, String ekuOid) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(subjectKp.getPublic())
                        .issuerDn(EXPIRED_ROOT_DN)
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .basicConstraints(false, null)
                        .ski()
                        .aki(expiredRootKp.getPublic())
                        .randomSerial();
        if (ekuOid != null) {
            builder.extendedKeyUsage(ekuOid);
        } else {
            builder.keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        }
        return builder.sign(expiredRootKp.getPrivate());
    }

    // ========================================================================
    // Якоря: null и пустой набор - ошибка вызова на каждом уровне
    // ========================================================================

    @Test
    @DisplayName("Null и пустые якоря отвергаются IllegalArgumentException на каждом уровне")
    void nullAndEmptyAnchorsAreRejectedAtEveryLevel() {
        byte[] der = new byte[] {0x30, 0x00};
        byte[] content = new byte[] {1};
        TrustAnchors empty = TrustAnchors.empty();
        RevocationFreshnessPolicy policy = RevocationFreshnessPolicy.STRICT;

        for (TrustAnchors bad : new TrustAnchors[] {null, empty}) {
            List<Executable> calls =
                    List.of(
                            () -> CAdESVerifier.verifyBES(der, bad),
                            () -> CAdESVerifier.verifyBESDetached(der, content, bad),
                            () -> CAdESVerifier.verifyT(der, bad),
                            () -> CAdESVerifier.verifyTDetached(der, content, bad),
                            () -> CAdESVerifier.verifyC(der, bad),
                            () -> CAdESVerifier.verifyCDetached(der, content, bad),
                            () -> CAdESVerifier.verifyXLong(der, bad),
                            () -> CAdESVerifier.verifyXLong(der, policy, bad),
                            () -> CAdESVerifier.verifyXLongDetached(der, content, bad),
                            () -> CAdESVerifier.verifyXLongDetached(der, content, policy, bad),
                            () -> CAdESVerifier.verifyCountersignature(der, bad),
                            () -> CAdESVerifier.verifyCountersignatureDetached(der, content, bad));
            for (Executable call : calls) {
                assertThrows(
                        IllegalArgumentException.class,
                        call,
                        "Пустые или отсутствующие якоря - ошибка вызова, а не повреждённая подпись");
            }
        }
    }

    // ========================================================================
    // Политика срока якоря: DEFAULT -> REJECT, явное значение сохраняется
    // ========================================================================

    @Test
    @DisplayName(
            "Подпись и цепочка: DEFAULT и REJECT отклоняют истёкший якорь, явный WARN допускает")
    void signerChainFollowsExpiryPolicy() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("expired anchor".getBytes())
                        .addSigner(expiredRootLeafKp.getPrivate(), expiredRootLeaf)
                        .addCertificate(expiredRoot)
                        .withCAdES()
                        .build();
        TrustAnchors byDefault = TrustAnchors.ofCertificates(expiredRoot);

        PkixException byDefaultError =
                assertThrows(
                        PkixException.class,
                        () -> CAdESVerifier.verifyBES(cadesBes, byDefault),
                        "DEFAULT в CAdES трактуется как REJECT");
        assertEquals(PkixException.Reason.EXPIRED, byDefaultError.reason());
        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyBES(
                                cadesBes, byDefault.withExpiryPolicy(AnchorExpiryPolicy.REJECT)),
                "Явный REJECT должен отклонять истёкший якорь");

        VerifiedCAdESData warned =
                CAdESVerifier.verifyBES(
                        cadesBes, byDefault.withExpiryPolicy(AnchorExpiryPolicy.WARN));
        assertEquals(
                expiredRootLeaf,
                warned.signers().get(0).signerCertificate(),
                "Явный WARN должен допускать истёкший якорь для подписи подписанта");
    }

    @Test
    @DisplayName("Контрподписант: явный WARN применяется к его цепочке, DEFAULT отклоняет")
    void countersignerChainFollowsExpiryPolicy() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("countersigner chain".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(expiredRoot)
                        .withCAdES()
                        .build();
        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, expiredRootLeafKp.getPrivate(), expiredRootLeaf);
        TrustAnchors byDefault = TrustAnchors.ofCertificates(signerCert, expiredRoot);

        PkixException byDefaultError =
                assertThrows(
                        PkixException.class,
                        () -> CAdESVerifier.verifyCountersignature(countersigned, byDefault),
                        "DEFAULT в CAdES трактуется как REJECT и для цепочки контрподписанта");
        assertEquals(PkixException.Reason.EXPIRED, byDefaultError.reason());

        VerifiedCAdESData warned =
                CAdESVerifier.verifyCountersignature(
                        countersigned, byDefault.withExpiryPolicy(AnchorExpiryPolicy.WARN));
        assertEquals(
                1,
                warned.signers().get(0).countersignatures().size(),
                "Явный WARN должен допускать истёкший якорь контрподписанта");
    }

    @Test
    @DisplayName("Цепочка TSA остаётся строгой: явный WARN её не ослабляет")
    void tsaChainStaysStrictUnderWarn() throws Exception {
        byte[] cadesT = buildCadesTWithTsaUnderExpiredRoot();
        TrustAnchors warned =
                TrustAnchors.ofCertificates(signerCert, expiredRoot)
                        .withExpiryPolicy(AnchorExpiryPolicy.WARN);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CAdESVerifier.verifyT(cadesT, warned),
                        "Доказательство времени не должно ослабляться политикой WARN");
        assertEquals(PkixException.Reason.EXPIRED, e.reason());
    }

    // ========================================================================
    // Контракт уровня: BES проходит на подписи старшего уровня
    // ========================================================================

    @Test
    @DisplayName("verifyBES принимает CAdES-T и не оценивает метки: список меток пуст")
    void besAcceptsHigherLevelSignatureWithoutEvaluatingTimestamps() throws Exception {
        byte[] cadesT = buildCadesTWithTsaUnderExpiredRoot();

        VerifiedCAdESData result =
                CAdESVerifier.verifyBES(cadesT, TrustAnchors.ofCertificates(signerCert));

        assertNotNull(result);
        assertTrue(
                result.signers().get(0).timestamps().isEmpty(),
                "verifyBES не проверяет метки старших уровней, список меток должен быть пуст");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /** CAdES-T: подписант самоподписанный, метка выпущена TSA под корнем с истёкшим сроком. */
    private static byte[] buildCadesTWithTsaUnderExpiredRoot() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("timestamped".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] token =
                CmsSignedDataBuilder.create()
                        .data(buildTstInfo(hashOfFirstSignature(cadesBes)))
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaLeafKp.getPrivate(), tsaLeaf)
                        .addCertificate(expiredRoot)
                        .build();
        return CAdESExtender.embedTimestamp(cadesBes, token);
    }

    private static byte[] hashOfFirstSignature(byte[] signedDataDer) throws Exception {
        CmsContentInfo contentInfo = CmsContentInfo.decode(signedDataDer);
        byte[][] signedDataParts = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        byte[][] signerInfos =
                DerCodec.parseSetContents(signedDataParts[signedDataParts.length - 1], 0);
        byte[][] signerInfoParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[] signatureOctets = null;
        for (int i = signerInfoParts.length - 1; i >= 0 && signatureOctets == null; i--) {
            if ((signerInfoParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                signatureOctets = signerInfoParts[i];
            }
        }
        byte[] signature = DerCodec.parseOctetString(signatureOctets, 0);
        // Подпись 256-битного ключа занимает 64 байта и хешируется Стрибог-256
        return signature.length == 64 ? Digest.digest256(signature) : Digest.digest512(signature);
    }

    private static byte[] buildTstInfo(byte[] messageHash) {
        String genTime =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
                        .withZone(ZoneOffset.UTC)
                        .format(Instant.now());
        return DerCodec.encodeSequence(
                DerCodec.encodeInteger(1),
                DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1"),
                DerCodec.encodeSequence(
                        CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256),
                        DerCodec.encodeOctetString(messageHash)),
                DerCodec.encodeInteger(BigInteger.ONE),
                DerCodec.encodeGeneralizedTime(genTime),
                DerCodec.encodeInteger(BigInteger.valueOf(42)));
    }
}
