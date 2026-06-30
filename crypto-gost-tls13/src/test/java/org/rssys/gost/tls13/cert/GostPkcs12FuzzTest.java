package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;

/**
 * Fuzz-тесты для {@link GostPkcs12Parser} и {@link GostPkcs12Loader}.
 * <p>
 * PFX-парсер делегирует DER-разбор в {@code DerCodec} (core):
 * {@code checkTag}, {@code decodeLength}, {@code parseOid}, {@code parseInteger},
 * {@code parseOctetString}, {@code parseSequenceContents}, {@code parseSetContents}.
 * Собственного DER-парсера больше нет — внутренние методы {@code parseConstructed},
 * {@code decodeLength}, {@code checkTag}, {@code peekLength} удалены (план 081).
 * <p>
 * ПОЧЕМУ ловим RuntimeException: DerCodec кидает IllegalArgumentException
 * на неверный тег или длину. AIOOBE возможен, если позиция выходит за пределы
 * массива до проверки тега. PkixException — ожидаемая реакция на битый PFX
 * (fail-closed). Если бы мы ловили только IllegalArgumentException, fuzzer бы
 * спотыкался об AIOOBE.
 */
class GostPkcs12FuzzTest {

    /**
     * parsePfx — главный entry point парсинга PFX.
     * Внутри: parseSequence -> DerCodec.parseSequenceContents -> checkTag.
     * DerCodec.checkTag обращается к data[offset] без внешней проверки границ,
     * но DerCodec сам проверяет offset &lt; data.length на входе.
     */
    @FuzzTest
    void fuzzParsePfx(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostPkcs12Parser.parsePfx(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseSafeContents — разбирает SEQUENCE OF SafeBag.
     * parseSequence -> DerCodec.parseSequenceContents -> checkTag.
     */
    @FuzzTest
    void fuzzParseSafeContents(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostPkcs12Parser.parseSafeContents(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseEncryptedPrivateKeyInfo — разбирает EncryptedPrivateKeyInfo.
     * parseSequence -> DerCodec.parseSequenceContents -> checkTag.
     */
    @FuzzTest
    void fuzzParseEncryptedPrivateKeyInfo(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostPkcs12Parser.parseEncryptedPrivateKeyInfo(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parsePbes2Params — разбирает PBES2-params.
     * Парсит AlgorithmIdentifier, PBKDF2-params, encryptionScheme с OID и OCTET STRING.
     * Использует DerCodec.parseOid, parseOctetString — проверка границ на входе.
     */
    @FuzzTest
    void fuzzParsePbes2Params(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostPkcs12Parser.parsePbes2Params(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * parseCertBag — разбирает CertBag и возвращает DER-сертификат.
     * parseSequence -> unwrapContextSpecific -> decodeLength.
     */
    @FuzzTest
    void fuzzParseCertBag(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostPkcs12Parser.parseCertBag(input);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
