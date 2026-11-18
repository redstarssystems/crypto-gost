package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Проверка кодирования и строгого разбора расширения id-pkix-ocsp-nonce (RFC 8954 §2.1)
 * в {@link OcspNonceCodec}, {@link GostOcspRequest} и {@link GostOcspResponse}.
 */
@DisplayName("OCSP nonce: двойная обёртка OCTET STRING по RFC 8954")
class OcspNonceCodecTest {

    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_BOOLEAN = 0x01;

    private static GostCertificate caCert;
    private static GostCertificate leafCert;
    private static byte[] baseRequest;
    private static byte[] baseResponse16;
    private static final byte[] NONCE_16 = randomBytes(16);

    @BeforeAll
    static void setUp() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        GostCertificate ca =
                GostCertificateBuilder.create(params, "CN=Nonce CA,O=Test")
                        .publicKey(caKp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("20351231235959Z")
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .randomSerial()
                        .sign(caKp.getPrivate());
        GostCertificate leaf =
                GostCertificateBuilder.create(params, "CN=Nonce leaf,O=Test")
                        .publicKey(leafKp.getPublic())
                        .issuerDn(ca.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20351231235959Z")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .randomSerial()
                        .sign(caKp.getPrivate());
        caCert = ca;
        leafCert = leaf;
        baseRequest = requestBuilder().build();
        baseResponse16 =
                GostOcspResponseBuilder.create(new byte[] {0x01})
                        .issuerDn(ca.getSubjectDnBytes())
                        .nonce(NONCE_16)
                        .sign(caKp.getPrivate());
    }

    // ========================================================================
    // Кодек: кодирование
    // ========================================================================

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {1, 8, 16, 32})
    @DisplayName("encodeExtension: extnValue = 04 LL 04 NN <nonce>")
    void encodeExtensionDoubleWrap(int length) {
        byte[] nonce = randomBytes(length);

        byte[] extension = OcspNonceCodec.encodeExtension(nonce);

        byte[] oidTlv = DerCodec.encodeOid(GostOids.OCSP_NONCE);
        byte[] expected =
                DerCodec.encodeSequence(
                        oidTlv, DerCodec.encodeOctetString(DerCodec.encodeOctetString(nonce)));
        assertArrayEquals(expected, extension, "Расширение должно иметь двойную обёртку nonce");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {0, 33, 64})
    @DisplayName("encodeExtension: длина вне 1..32 отклоняется")
    void encodeExtensionRejectsBadLength(int length) {
        assertThrows(
                IllegalArgumentException.class,
                () -> OcspNonceCodec.encodeExtension(new byte[length]),
                "Nonce длиной " + length + " должен отклоняться");
    }

    @Test
    @DisplayName("encodeExtension: null отклоняется")
    void encodeExtensionRejectsNull() {
        assertThrows(
                IllegalArgumentException.class,
                () -> OcspNonceCodec.encodeExtension(null),
                "null вместо nonce должен отклоняться");
    }

    // ========================================================================
    // Кодек: разбор внутреннего слоя
    // ========================================================================

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {1, 8, 16, 32})
    @DisplayName("parseExtnValue: границы 1..32 и 8 байт (эхо КриптоПро) принимаются")
    void parseExtnValueAcceptsValidLengths(int length) throws Exception {
        byte[] nonce = randomBytes(length);
        byte[] inner = DerCodec.encodeOctetString(nonce);

        byte[] parsed = OcspNonceCodec.parseExtnValue(inner, 0, inner.length);

        assertArrayEquals(nonce, parsed, "Должны вернуться сырые байты nonce");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {0, 33})
    @DisplayName("parseExtnValue: длина 0 и 33 отклоняются")
    void parseExtnValueRejectsBadLength(int length) {
        byte[] inner = DerCodec.encodeOctetString(new byte[length]);

        assertThrows(
                PkixException.class,
                () -> OcspNonceCodec.parseExtnValue(inner, 0, inner.length),
                "Nonce длиной " + length + " должен отклоняться");
    }

    @Test
    @DisplayName("parseExtnValue: заведомо не TLV (одноуровневый формат) отклоняется")
    void parseExtnValueRejectsNonTlv() {
        byte[] notTlv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        assertThrows(
                PkixException.class,
                () -> OcspNonceCodec.parseExtnValue(notTlv, 0, notTlv.length),
                "Сырые байты, не являющиеся OCTET STRING, должны отклоняться");
    }

    @Test
    @DisplayName("parseExtnValue: хвост после внутреннего OCTET STRING отклоняется")
    void parseExtnValueRejectsTrailingData() {
        byte[] inner = DerCodec.concat(DerCodec.encodeOctetString(randomBytes(16)), new byte[] {0});

        assertThrows(
                PkixException.class,
                () -> OcspNonceCodec.parseExtnValue(inner, 0, inner.length),
                "Хвост после nonce должен отклоняться");
    }

    @Test
    @DisplayName("parseExtnValue: два OCTET STRING подряд отклоняются")
    void parseExtnValueRejectsTwoOctetStrings() {
        byte[] inner =
                DerCodec.concat(
                        DerCodec.encodeOctetString(randomBytes(8)),
                        DerCodec.encodeOctetString(randomBytes(8)));

        assertThrows(
                PkixException.class,
                () -> OcspNonceCodec.parseExtnValue(inner, 0, inner.length),
                "Допустим ровно один внутренний OCTET STRING");
    }

    @Test
    @DisplayName(
            "parseExtnValue: длина внутреннего TLV больше доступных данных -> PkixException с причиной")
    void parseExtnValueWrapsMalformedDer() {
        byte[] truncated = {TAG_OCTET_STRING, 0x20, 0x01, 0x02};

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> OcspNonceCodec.parseExtnValue(truncated, 0, truncated.length),
                        "Обрезанный TLV должен отклоняться");
        assertInstanceOf(
                IllegalArgumentException.class,
                e.getCause(),
                "Причиной должно быть исключение разбора DER");
    }

    @Test
    @DisplayName(
            "parseExtnValue: старый сырой nonce вида 04 0E + 14 байт неотличим от RFC-nonce и принимается")
    void parseExtnValueAcceptsStructurallyValidLegacyValue() throws Exception {
        byte[] legacyRaw = new byte[16];
        legacyRaw[0] = TAG_OCTET_STRING;
        legacyRaw[1] = 14;
        byte[] body = randomBytes(14);
        System.arraycopy(body, 0, legacyRaw, 2, 14);

        byte[] parsed = OcspNonceCodec.parseExtnValue(legacyRaw, 0, legacyRaw.length);

        assertArrayEquals(
                body,
                parsed,
                "Структурно валидное значение читается как 14-байтный RFC-nonce (осознанная неотличимость)");
    }

    // ========================================================================
    // Запрос
    // ========================================================================

    @Test
    @DisplayName("Запрос: builder -> GostOcspRequest.getNonce() возвращает те же 32 байта")
    void requestRoundTrip() throws Exception {
        GostOcspRequestBuilder builder = requestBuilder();

        byte[] der = builder.build();
        GostOcspRequest parsed = GostOcspRequest.fromDer(der);

        assertEquals(32, builder.getNonce().length, "Клиентский nonce должен быть 32 байта");
        assertArrayEquals(
                builder.getNonce(), parsed.getNonce(), "Разбор должен вернуть сырой nonce");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {1, 8, 32})
    @DisplayName("Запрос: nonce допустимой длины принимается")
    void requestAcceptsValidNonceLengths(int length) throws Exception {
        byte[] nonce = randomBytes(length);
        byte[] der = replaceNonceExtension(baseRequest, nonceExtension(nonce));

        assertArrayEquals(
                nonce,
                GostOcspRequest.fromDer(der).getNonce(),
                "Nonce длиной " + length + " должен приниматься");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {0, 33})
    @DisplayName("Запрос: nonce длиной 0 и 33 отклоняется")
    void requestRejectsBadLengths(int length) {
        byte[] der = replaceNonceExtension(baseRequest, nonceExtension(new byte[length]));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Nonce длиной " + length + " должен отклоняться");
    }

    @Test
    @DisplayName("Запрос: одноуровневый формат (не TLV) отклоняется")
    void requestRejectsSingleLevelFormat() {
        byte[] raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] der = replaceNonceExtension(baseRequest, extension(DerCodec.encodeOctetString(raw)));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Сырой nonce без внутреннего OCTET STRING должен отклоняться");
    }

    @Test
    @DisplayName("Запрос: OID nonce есть, extnValue отсутствует -> PkixException")
    void requestRejectsMissingExtnValue() {
        byte[] der =
                replaceNonceExtension(
                        baseRequest,
                        DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_NONCE)));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Расширение nonce без extnValue должно отклоняться");
    }

    @Test
    @DisplayName("Запрос: extnValue не OCTET STRING -> PkixException")
    void requestRejectsExtnValueNotOctetString() {
        byte[] notOctet = DerCodec.encodeTlv(0x03, DerCodec.encodeOctetString(randomBytes(16)));
        byte[] der = replaceNonceExtension(baseRequest, extension(notOctet));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "extnValue другого типа должен отклоняться");
    }

    @Test
    @DisplayName("Запрос: внутренний элемент не OCTET STRING -> PkixException")
    void requestRejectsInnerNotOctetString() {
        byte[] innerInteger = DerCodec.encodeTlv(0x02, randomBytes(16));
        byte[] der =
                replaceNonceExtension(
                        baseRequest, extension(DerCodec.encodeOctetString(innerInteger)));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Внутри extnValue должен быть именно OCTET STRING");
    }

    @Test
    @DisplayName("Запрос: хвост после внутреннего OCTET STRING -> PkixException")
    void requestRejectsTrailingData() {
        byte[] inner =
                DerCodec.concat(DerCodec.encodeOctetString(randomBytes(16)), new byte[] {0x00});
        byte[] der =
                replaceNonceExtension(baseRequest, extension(DerCodec.encodeOctetString(inner)));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Лишние данные после nonce должны отклоняться");
    }

    @Test
    @DisplayName("Запрос: дубликат nonce-расширения -> PkixException")
    void requestRejectsDuplicateNonce() {
        byte[] first = nonceExtension(randomBytes(16));
        byte[] second = nonceExtension(randomBytes(16));
        byte[] der = replaceNonceExtension(baseRequest, DerCodec.concat(first, second));

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Два nonce-расширения делают значение неоднозначным");
    }

    @Test
    @DisplayName(
            "Запрос: requestExtensions [2] присутствует, но битый -> PkixException, а не «nonce нет»")
    void requestRejectsBrokenExtensionsContainer() {
        // [2] объявляет длину больше фактических данных
        byte[] der = Arrays.copyOf(baseRequest, baseRequest.length);
        int extTagPos = findNonceExtensionsTagPosition(der);
        der[extTagPos + 1] = 0x7F;

        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromDer(der),
                "Битый контейнер расширений нельзя трактовать как отсутствие nonce");
    }

    @Test
    @DisplayName("Запрос: критический флаг BOOLEAN перед extnValue допускается")
    void requestAcceptsCriticalFlag() throws Exception {
        byte[] nonce = randomBytes(16);
        byte[] ext =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.OCSP_NONCE),
                        DerCodec.encodeTlv(TAG_BOOLEAN, new byte[] {(byte) 0xFF}),
                        DerCodec.encodeOctetString(DerCodec.encodeOctetString(nonce)));
        byte[] der = replaceNonceExtension(baseRequest, ext);

        assertArrayEquals(
                nonce,
                GostOcspRequest.fromDer(der).getNonce(),
                "Флаг critical не должен мешать разбору nonce");
    }

    // ========================================================================
    // Ответ
    // ========================================================================

    @Test
    @DisplayName("Ответ: builder -> GostOcspResponse.getNonce() возвращает те же байты")
    void responseRoundTrip() throws Exception {
        assertArrayEquals(
                NONCE_16,
                GostOcspResponse.fromDer(baseResponse16).getNonce(),
                "Разбор должен вернуть сырой nonce");
    }

    @Test
    @DisplayName("Ответ builder: nonce(null) не добавляет расширение")
    void responseBuilderNullNonce() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] der =
                GostOcspResponseBuilder.create(new byte[] {0x01})
                        .issuerDn(GostDnParser.encodeDn("CN=Test CA"))
                        .nonce(NONCE_16)
                        .nonce(null)
                        .sign(kp.getPrivate());

        assertNull(
                GostOcspResponse.fromDer(der).getNonce(),
                "После nonce(null) расширения быть не должно");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {0, 33})
    @DisplayName("Ответ builder: nonce длиной 0 и 33 отклоняется")
    void responseBuilderRejectsBadLengths(int length) {
        GostOcspResponseBuilder builder = GostOcspResponseBuilder.create(new byte[] {0x01});

        assertThrows(
                IllegalArgumentException.class,
                () -> builder.nonce(new byte[length]),
                "Nonce длиной " + length + " должен отклоняться");
    }

    @Test
    @DisplayName("Ответ builder: nonce копируется, изменение исходного массива не влияет")
    void responseBuilderClonesNonce() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] nonce = randomBytes(16);
        byte[] expected = nonce.clone();
        GostOcspResponseBuilder builder =
                GostOcspResponseBuilder.create(new byte[] {0x01})
                        .issuerDn(GostDnParser.encodeDn("CN=Test CA"))
                        .nonce(nonce);

        Arrays.fill(nonce, (byte) 0);
        byte[] der = builder.sign(kp.getPrivate());

        assertArrayEquals(
                expected,
                GostOcspResponse.fromDer(der).getNonce(),
                "Билдер должен хранить копию nonce");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {1, 8, 32})
    @DisplayName("Ответ: nonce допустимой длины принимается")
    void responseAcceptsValidNonceLengths(int length) throws Exception {
        byte[] nonce = randomBytes(length);
        byte[] der = replaceNonceExtension(baseResponse16, nonceExtension(nonce));

        assertArrayEquals(
                nonce,
                GostOcspResponse.fromDer(der).getNonce(),
                "Nonce длиной " + length + " должен приниматься");
    }

    @ParameterizedTest(name = "длина nonce {0}")
    @ValueSource(ints = {0, 33})
    @DisplayName("Ответ: nonce длиной 0 и 33 отклоняется")
    void responseRejectsBadLengths(int length) {
        byte[] der = replaceNonceExtension(baseResponse16, nonceExtension(new byte[length]));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Nonce длиной " + length + " должен отклоняться даже если nonce не ожидается");
    }

    @Test
    @DisplayName("Ответ: одноуровневый формат (не TLV) отклоняется")
    void responseRejectsSingleLevelFormat() {
        byte[] raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] der =
                replaceNonceExtension(baseResponse16, extension(DerCodec.encodeOctetString(raw)));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Сырой nonce без внутреннего OCTET STRING должен отклоняться");
    }

    @Test
    @DisplayName("Ответ: OID nonce есть, extnValue отсутствует -> PkixException")
    void responseRejectsMissingExtnValue() {
        byte[] der =
                replaceNonceExtension(
                        baseResponse16,
                        DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_NONCE)));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Расширение nonce без extnValue должно отклоняться");
    }

    @Test
    @DisplayName("Ответ: extnValue не OCTET STRING -> PkixException")
    void responseRejectsExtnValueNotOctetString() {
        byte[] notOctet = DerCodec.encodeTlv(0x03, DerCodec.encodeOctetString(randomBytes(16)));
        byte[] der = replaceNonceExtension(baseResponse16, extension(notOctet));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "extnValue другого типа должен отклоняться");
    }

    @Test
    @DisplayName("Ответ: внутренний элемент не OCTET STRING -> PkixException")
    void responseRejectsInnerNotOctetString() {
        byte[] innerInteger = DerCodec.encodeTlv(0x02, randomBytes(16));
        byte[] der =
                replaceNonceExtension(
                        baseResponse16, extension(DerCodec.encodeOctetString(innerInteger)));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Внутри extnValue должен быть именно OCTET STRING");
    }

    @Test
    @DisplayName("Ответ: хвост после внутреннего OCTET STRING -> PkixException")
    void responseRejectsTrailingData() {
        byte[] inner =
                DerCodec.concat(DerCodec.encodeOctetString(randomBytes(16)), new byte[] {0x00});
        byte[] der =
                replaceNonceExtension(baseResponse16, extension(DerCodec.encodeOctetString(inner)));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Лишние данные после nonce должны отклоняться");
    }

    @Test
    @DisplayName("Ответ: дубликат nonce-расширения -> PkixException")
    void responseRejectsDuplicateNonce() {
        byte[] first = nonceExtension(randomBytes(16));
        byte[] second = nonceExtension(randomBytes(16));
        byte[] der = replaceNonceExtension(baseResponse16, DerCodec.concat(first, second));

        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromDer(der),
                "Два nonce-расширения делают значение неоднозначным");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static GostOcspRequestBuilder requestBuilder() {
        return GostOcspRequestBuilder.create()
                .targetCert(leafCert.getEncoded())
                .issuerCert(caCert.getEncoded());
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    /** Extension {@code SEQUENCE { id-pkix-ocsp-nonce, extnValue }}, extnValue подаётся готовым TLV. */
    private static byte[] extension(byte[] extnValueTlv) {
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_NONCE), extnValueTlv);
    }

    /** Корректное расширение nonce с произвольной длиной (в обход проверок builder'а). */
    private static byte[] nonceExtension(byte[] nonce) {
        return extension(DerCodec.encodeOctetString(DerCodec.encodeOctetString(nonce)));
    }

    /**
     * Заменяет единственное nonce-расширение в DER на заданные байты (одно или несколько
     * расширений подряд) и пересчитывает длины всех охватывающих TLV. Подпись при этом
     * не пересчитывается — разбор её не проверяет.
     */
    private static byte[] replaceNonceExtension(byte[] der, byte[] replacementExtensions) {
        byte[] oidTlv = DerCodec.encodeOid(GostOids.OCSP_NONCE);
        int oidPos = indexOf(der, oidTlv);
        assertTrue(oidPos >= 4, "В исходном DER должно быть nonce-расширение");
        // Extension SEQUENCE с коротким заголовком из двух байт перед OID
        int extStart = oidPos - 2;
        int extEnd = GostDerParser.readTlv(der, extStart)[1];
        return rewrite(der, 0, extStart, extEnd, replacementExtensions);
    }

    private static int findNonceExtensionsTagPosition(byte[] der) {
        int oidPos = indexOf(der, DerCodec.encodeOid(GostOids.OCSP_NONCE));
        // Идём назад до тега requestExtensions [2] EXPLICIT (0xA2)
        for (int pos = oidPos; pos >= 0; pos--) {
            if ((der[pos] & 0xFF) == 0xA2) {
                return pos;
            }
        }
        throw new AssertionError("Не найден requestExtensions [2]");
    }

    /** Пересобирает TLV по смещению {@code pos}, подменяя диапазон целевого TLV. */
    private static byte[] rewrite(
            byte[] der, int pos, int targetStart, int targetEnd, byte[] replacement) {
        if (pos == targetStart) {
            return replacement;
        }
        int tag = der[pos] & 0xFF;
        int[] value = GostDerParser.readTlv(der, pos);
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        int childPos = value[0];
        while (childPos < value[1]) {
            int[] child = GostDerParser.readTlv(der, childPos);
            boolean containsTarget = childPos <= targetStart && targetEnd <= child[1];
            if (containsTarget) {
                byte[] rebuilt = rewrite(der, childPos, targetStart, targetEnd, replacement);
                content.write(rebuilt, 0, rebuilt.length);
            } else {
                content.write(der, childPos, child[1] - childPos);
            }
            childPos = child[1];
        }
        return DerCodec.encodeTlv(tag, content.toByteArray());
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
