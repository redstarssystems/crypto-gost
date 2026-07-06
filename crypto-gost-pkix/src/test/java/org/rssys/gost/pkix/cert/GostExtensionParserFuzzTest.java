package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тест для {@link GostExtensionParser}.
 *
 * <p>Парсер расширений X.509v3 принимает недоверенные DER-байты из сертификатов
 * (через {@link GostExtensionParser#parseExtensionsFromSequence} и
 * {@link GostExtensionParser#parseFromExtensionsBlock}). Внутри — ручной
 * разбор SEQUENCE OF Extension, OID, BOOLEAN, OCTET STRING и обработчики
 * для всех известных расширений (SAN, KU, EKU, BC, SKI, AKI, AIA, CDP, CP,
 * NameConstraints).</p>
 *
 * <p>ПОЧЕМУ ловим RuntimeException: методы-парсеры используют
 * {@link GostDerParser#readTlv} без проверки границ DER-массива.
 * На битом DER возможно AIOOBE, NPE — документированное поведение.</p>
 */
class GostExtensionParserFuzzTest {

    private static final byte[] SAN_OID = {0x55, 0x1D, 0x11};

    @FuzzTest
    void fuzzParseExtensionsFromSequence(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            GostExtensionParser.parseExtensionsFromSequence(der, 0);
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzParseFromExtensionsBlock(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            GostExtensionParser.parseFromExtensionsBlock(der, 0);
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Targeted: крафт SEQUENCE OF Extension с SAN-расширением,
     * URI GeneralName с constructed-тегом 0xA6 вместо 0x86.
     * Фикс 0.6.2: точное сравнение с TAG_URI (0x86), constructed-бит не маскируется.
     * <p>
     * Длина IA5String-хоста варьируется фаззером, все содержащие DER-длины
     * пересчитываются динамически.
     */
    @FuzzTest
    void fuzzConstructedUriTag(FuzzedDataProvider data) {
        String host = data.consumeRemainingAsString();
        if (host.isEmpty()) return;
        byte[] hostBytes;
        try {
            hostBytes = host.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return;
        }
        int ia5Len = hostBytes.length;
        // IA5String TLV: 0x16 + len + hostBytes
        int ia5TlvLen = 1 + 1 + ia5Len;
        // URI [6] CONSTRUCTED: 0xA6 + len(IA5String TLV) + IA5String TLV
        int uriTlvLen = 1 + 1 + ia5TlvLen;
        // SAN SEQUENCE OF GeneralName: 0x30 + len(URI TLV) + URI TLV
        int sanSeqLen = 1 + 1 + uriTlvLen;
        // extnValue OCTET STRING: 0x04 + len(SAN SEQUENCE) + SAN SEQUENCE
        int octetLen = 1 + 1 + sanSeqLen;
        // Extension content: OID(5) + OCTET STRING
        int extContentLen = 5 + octetLen;
        // Extension TLV: 0x30 + len(extContent) + extContent
        int extTlvLen = 1 + 1 + extContentLen;
        // Extensions TLV: 0x30 + len(Extension TLV) + Extension TLV
        int totalLen = 1 + 1 + extTlvLen;
        byte[] input = new byte[totalLen];
        int pos = 0;
        input[pos++] = 0x30;
        input[pos++] = (byte) extTlvLen;
        input[pos++] = 0x30;
        input[pos++] = (byte) extContentLen;
        input[pos++] = 0x06;
        input[pos++] = (byte) SAN_OID.length;
        System.arraycopy(SAN_OID, 0, input, pos, SAN_OID.length);
        pos += SAN_OID.length;
        input[pos++] = 0x04;
        input[pos++] = (byte) sanSeqLen;
        input[pos++] = 0x30;
        input[pos++] = (byte) uriTlvLen;
        input[pos++] = (byte) 0xA6;
        input[pos++] = (byte) ia5TlvLen;
        input[pos++] = 0x16;
        input[pos++] = (byte) ia5Len;
        System.arraycopy(hostBytes, 0, input, pos, ia5Len);
        try {
            GostExtensionParser.parseExtensionsFromSequence(input, 0);
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Targeted: крафт SEQUENCE OF Extension с N entries,
     * включая превышение лимита MAX_EXTENSIONS_PER_CERT (64).
     * Фикс 0.6.2: MAX_EXTENSIONS_PER_CERT = 64.
     * <p>
     * Каждый extension — минимальный: неизвестный OID (4 байта из фаззера),
     * без critical-флага, пустой OCTET STRING (04 00).
     * N варьируется 1..128 (выше лимита).
     */
    @FuzzTest
    void fuzzManyExtensions(FuzzedDataProvider data) {
        int n = data.consumeInt(1, 128);
        byte[] oidBytes = data.consumeBytes(4);
        if (oidBytes.length < 4) return;
        // Каждый Extension: 30 0A 06 04 XX XX XX XX 04 00 = 10 байт
        int extEntryLen = 10;
        int contentLen = n * extEntryLen;
        // Определяем заголовок SEQUENCE: short-form (83) или long-form (84)
        byte[] input;
        if (contentLen <= 0x7F) {
            input = new byte[2 + contentLen];
            input[0] = 0x30;
            input[1] = (byte) contentLen;
        } else if (contentLen <= 0xFF) {
            input = new byte[3 + contentLen];
            input[0] = 0x30;
            input[1] = (byte) 0x81;
            input[2] = (byte) contentLen;
        } else {
            input = new byte[4 + contentLen];
            input[0] = 0x30;
            input[1] = (byte) 0x82;
            input[2] = (byte) (contentLen >> 8);
            input[3] = (byte) contentLen;
        }
        int headerLen = input.length - contentLen;
        int pos = headerLen;
        for (int i = 0; i < n; i++) {
            input[pos++] = 0x30;
            input[pos++] = (byte) (extEntryLen - 2);
            input[pos++] = 0x06;
            input[pos++] = 0x04;
            System.arraycopy(oidBytes, 0, input, pos, 4);
            pos += 4;
            input[pos++] = 0x04;
            input[pos++] = 0x00;
        }
        try {
            GostExtensionParser.parseExtensionsFromSequence(input, 0);
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Перебрасывает RuntimeException, если это баг (AIOOBE, NPE,
     * NegativeArraySizeException). Иначе — проглатывает.
     */
    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
