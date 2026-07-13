package org.rssys.gost.pkix.cms;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;

/**
 * Fuzz-тесты для {@link CAdESCompleteData} — ручного ASN.1-парсера
 * CAdES-C структур.
 *
 * <p>{@code decodeOtherHash} разбирает CHOICE [1] EXPLICIT с вложенной
 * SEQUENCE AlgorithmIdentifier + OCTET STRING. Мутации DER: усечение,
 * битые длины, чужие теги, oversized-поля.
 *
 * <p>{@code decodeCrlOcspRef} разбирает SEQUENCE с CONTEXT-тегами [0]/[1],
 * каждый — EXPLICIT SEQUENCE с вложенными CrlValidatedID/OcspResponsesID.
 * Мутации: битые длины внутри SEQUENCE, неверные теги, OOB в CHOICE.
 */
class CAdESCompleteFuzzTest {

    private static GostCertificate cert;

    @BeforeAll
    static void setUp() {
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        cert =
                CmsTestUtils.createSelfSignedCert(
                        kp.getPrivate(), kp.getPublic(), BigInteger.valueOf(42));
    }

    @FuzzTest
    void fuzzDecodeOtherHash(FuzzedDataProvider data) {
        byte[] fuzzData = data.consumeRemainingAsBytes();
        if (fuzzData.length == 0) return;
        try {
            CAdESCompleteData.decodeOtherHash(fuzzData);
        } catch (PkixException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
        }
    }

    @FuzzTest
    void fuzzDecodeCrlOcspRef(FuzzedDataProvider data) {
        byte[] fuzzData = data.consumeRemainingAsBytes();
        if (fuzzData.length == 0) return;
        try {
            CAdESCompleteData.decodeCrlOcspRef(fuzzData);
        } catch (PkixException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
        }
    }

    @FuzzTest
    void fuzzDecodeOtherCertID(FuzzedDataProvider data) {
        byte[] fuzzData = data.consumeRemainingAsBytes();
        if (fuzzData.length == 0) return;
        try {
            CAdESCompleteData.decodeOtherCertID(fuzzData);
        } catch (PkixException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
        }
    }

    @FuzzTest
    void fuzzDecodeCompleteCertificateRefs(FuzzedDataProvider data) {
        byte[] fuzzData = data.consumeRemainingAsBytes();
        if (fuzzData.length == 0) return;
        try {
            CAdESCompleteData.decodeCompleteCertificateRefs(fuzzData);
        } catch (PkixException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
        }
    }

    @FuzzTest
    void fuzzDecodeCompleteRevocationRefs(FuzzedDataProvider data) {
        byte[] fuzzData = data.consumeRemainingAsBytes();
        if (fuzzData.length == 0) return;
        try {
            CAdESCompleteData.decodeCompleteRevocationRefs(fuzzData);
        } catch (PkixException | IllegalArgumentException | IndexOutOfBoundsException ignored) {
        }
    }
}
