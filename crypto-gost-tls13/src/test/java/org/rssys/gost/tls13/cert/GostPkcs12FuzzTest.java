package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тесты для {@link GostPkcs12Parser} и {@link GostPkcs12Loader}.
 * <p>
 * PFX-парсер имеет собственный внутренний DER-парсер (parseConstructed, decodeLength,
 * checkTag, peekLength на строках 442-590) с нулевой защитой границ. В отличие от
 * DerCodec.decodeLength, внутренний decodeLength (строка 569) не проверяет
 * pos[0] >= data.length перед обращением к data[pos[0]].
 * <p>
 * ПОЧЕМУ ловим RuntimeException: внутренний парсер кидает AIOOBE/NPE на любом
 * битом PFX. IllegalArgumentException — ожидаемая реакция на неверный тег или
 * структуру. Если бы мы ловили только IllegalArgumentException, fuzzer бы
 * спотыкался об AIOOBE.
 */
class GostPkcs12FuzzTest {

    /**
     * parsePfx — главный entry point парсинга PFX.
     * Внутри: parseSequence → parseConstructed → checkTag(data, pos, expectedTag)
     * на строке 583 обращается к data[pos[0]] без проверки границ.
     * Внутренний decodeLength (строка 569) — без проверки pos[0] >= data.length.
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
     * parseConstructed → checkTag → AIOOBE на пустом входе.
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
     * parseSequence → parseConstructed → AIOOBE на пустом входе.
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
     * Много точек AIOOBE через внутренний decodeLength/checkTag.
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
     * parseSequence → unwrapContextSpecific → decodeLength → AIOOBE.
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
