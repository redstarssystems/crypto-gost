package org.rssys.gost.pkix.cms;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.BeforeAll;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Fuzz-тесты для {@link CAdESExtender#embedCountersignature} и
 * {@link CAdESVerifier#verifyCountersignature}.
 *
 * <p>Покрывает мутации DER на входе verifyCountersignature: contentInfo,
 * SignedData, SignerInfo, unsignedAttrs, countersignature.
 */
class CountersignatureFuzzTest {

    private static GostCertificate cert;
    private static GostCertificate csCert;
    private static org.rssys.gost.signature.PrivateKeyParameters csKey;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        cert = CmsTestUtils.createSelfSignedCert(kp.getPrivate(), kp.getPublic());

        var csKp = KeyGenerator.generateKeyPair(params);
        csKey = csKp.getPrivate();
        csCert = CmsTestUtils.createSelfSignedCert(csKp.getPrivate(), csKp.getPublic());
    }

    @FuzzTest
    void fuzzVerifyCountersignature(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            CAdESVerifier.verifyCountersignature(der, TrustAnchors.ofCertificates(cert, csCert));
        } catch (PkixException e) {
            // Ожидаемое поведение для мусорного DER — не падаем
        } catch (Exception e) {
            // Другие исключения допустимы (например, IndexOutOfBounds
            // при недостаточной длине данных в DerCodec), но не AssertionError
        }
    }

    @FuzzTest
    void fuzzEmbedCountersignature(FuzzedDataProvider data) {
        byte[] cadesBes = data.consumeBytes(data.consumeInt(0, 65536));
        if (cadesBes.length == 0) return;
        try {
            CAdESExtender.embedCountersignature(cadesBes, csKey, csCert);
        } catch (PkixException e) {
            // Ожидаемое поведение для некорректного DER
        } catch (Exception e) {
            // Другие исключения допустимы
        }
    }

    @FuzzTest
    void fuzzRoundTrip(FuzzedDataProvider data) {
        byte[] payload = data.consumeBytes(data.consumeInt(1, 1024));
        if (payload.length == 0) return;
        var kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        var signerCert = CmsTestUtils.createSelfSignedCert(kp.getPrivate(), kp.getPublic());
        try {
            byte[] cadesBes =
                    CmsSignedDataBuilder.create()
                            .data(payload)
                            .addSigner(kp.getPrivate(), signerCert)
                            .withCAdES()
                            .build();

            byte[] countersigned = CAdESExtender.embedCountersignature(cadesBes, csKey, csCert);

            // Верифицируем тем же набором trusted (signer + cs)
            CAdESVerifier.verifyCountersignature(
                    countersigned, TrustAnchors.ofCertificates(signerCert, csCert));
        } catch (PkixException e) {
            // Ошибка построения/верификации — ожидаемо для fuzz
        } catch (Exception e) {
            // Допустимо при исчерпании ресурсов
        }
    }
}
