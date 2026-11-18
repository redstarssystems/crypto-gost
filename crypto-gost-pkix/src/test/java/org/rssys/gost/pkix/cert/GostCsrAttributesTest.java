package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Атрибуты PKCS#10: {@code challengePassword} и произвольные атрибуты в
 * {@link GostCsrBuilder} и {@link GostCsrParser}.
 */
@DisplayName("CSR: атрибуты challengePassword и произвольные")
class GostCsrAttributesTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    /** Фиксированный ключ: эталонные TBS должны быть воспроизводимы между запусками. */
    private static final PrivateKeyParameters KEY =
            new PrivateKeyParameters(
                    new BigInteger(
                            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16),
                    PARAMS);

    private static final PublicKeyParameters PUB = KEY.derivePublicKey();

    private static final String OID_A = "1.2.3.4";
    private static final String OID_B = "1.2.3.5.6";
    private static final Charset UTF_32_BE = Charset.forName("UTF-32BE");

    // Эталонные TBS сняты с кода до добавления атрибутов (фиксированный ключ, тот же DN)
    private static final String BASELINE_TBS_PLAIN =
            "30819202010030213110300e06035504030c0752656772657373310d300b060355040a0c04546573743068302106"
                    + "082a85030701010101301506092a850307010201010106082a850307010102020343000440a2ff99a02466"
                    + "d63e4729d0a49ad3776802ef0da040249042cfe81f07e84cab28c96e72c8f6d51660c6b18e4c14484f9172"
                    + "1936580cf9a9ad1d4a8adf18425e16a000";
    private static final String BASELINE_TBS_EXTENSIONS =
            "3081e202010030213110300e06035504030c0752656772657373310d300b060355040a0c04546573743068302106"
                    + "082a85030701010101301506092a850307010201010106082a850307010102020343000440a2ff99a02466"
                    + "d63e4729d0a49ad3776802ef0da040249042cfe81f07e84cab28c96e72c8f6d51660c6b18e4c14484f9172"
                    + "1936580cf9a9ad1d4a8adf18425e16a050304e06092a864886f70d01090e3141303f30180603551d110411"
                    + "300f820d612e6578616d706c652e636f6d300e0603551d0f0101ff04040302008030130603551d25040c30"
                    + "0a06082b06010505070301";

    // ========================================================================
    // Помощники
    // ========================================================================

    private static GostCsrBuilder builder() {
        return GostCsrBuilder.create("CN=Regress,O=Test", PUB);
    }

    private static byte[] derUtf8(String text) {
        return DerCodec.encodeUTF8String(text);
    }

    /** Ручная сборка Attribute SEQUENCE { OID, SET { values } } без сортировки. */
    private static byte[] attr(String oid, byte[]... values) {
        return DerCodec.encodeSequence(DerCodec.encodeOid(oid), DerCodec.encodeSet(values));
    }

    private static byte[] passwordAttr(int tag, byte[] content) {
        return attr(GostOids.ATTR_CHALLENGE_PASSWORD, DerCodec.encodeTlv(tag, content));
    }

    /** CSR с произвольным содержимым блока {@code [0]}, подписанный корректной подписью. */
    private static byte[] csrWithBlock(byte[]... attributes) {
        byte[] tbs =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00}),
                        GostDnParser.encodeDn("CN=Regress,O=Test"),
                        GostDerCodec.encodePublicKey(PUB),
                        DerCodec.encodeContextConstructed(0, DerCodec.concat(attributes)));
        return signTbs(tbs);
    }

    private static byte[] signTbs(byte[] tbs) {
        byte[] signature = Signature.sign(tbs, KEY);
        return DerCodec.encodeSequence(
                tbs, GostSignatureHelper.buildAlgId(PARAMS), DerCodec.encodeBitString(signature));
    }

    private static byte[] utf16be(String text) {
        return text.getBytes(StandardCharsets.UTF_16BE);
    }

    private static byte[] utf32be(String text) {
        return text.getBytes(UTF_32_BE);
    }

    private static GostCsrParser parse(byte[] csr) {
        return GostCsrParser.fromDer(csr);
    }

    private static char[] password(byte[] csr) {
        return parse(csr).getChallengePassword().orElseThrow();
    }

    /** Смещение блока {@code [0]} в TBS: после версии, DN и SPKI. */
    private static int attributesBlockOffset(byte[] tbs) {
        int pos = GostDerParser.readTlv(tbs, 0)[0];
        for (int i = 0; i < 3; i++) {
            pos = GostDerParser.readTlv(tbs, pos)[1];
        }
        assertEquals(0xA0, tbs[pos] & 0xFF, "после SPKI должен идти блок [0]");
        return pos;
    }

    private static byte[] attributesBlockContent(byte[] tbs) {
        int[] block = GostDerParser.readTlv(tbs, attributesBlockOffset(tbs));
        return Arrays.copyOfRange(tbs, block[0], block[1]);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(haystack, i, i + needle.length), needle)) {
                return i;
            }
        }
        throw new AssertionError("TBS не найден в CSR");
    }

    private static int passwordTag(byte[] csr) {
        return parse(csr)
                        .getAttribute(GostOids.ATTR_CHALLENGE_PASSWORD)
                        .orElseThrow()
                        .valuesDer()
                        .get(0)[0]
                & 0xFF;
    }

    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    // ========================================================================
    // Регрессия и кодирование блока [0]
    // ========================================================================

    @Test
    @DisplayName("Регрессия: CSR без новых атрибутов побайтно равен эталону, снятому до правок")
    void testBaselineTbsUnchanged() {
        byte[] plain = builder().sign(KEY);
        assertEquals(
                BASELINE_TBS_PLAIN,
                HexFormat.of().formatHex(parse(plain).getTbsCertRequest()),
                "CSR без атрибутов изменился");

        byte[] withExtensions =
                builder()
                        .sanDns("a.example.com")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage("1.3.6.1.5.5.7.3.1")
                        .sign(KEY);
        assertEquals(
                BASELINE_TBS_EXTENSIONS,
                HexFormat.of().formatHex(parse(withExtensions).getTbsCertRequest()),
                "CSR с extensionRequest изменился");
    }

    @Test
    @DisplayName("Блок [0]: содержимое — сразу Attribute SEQUENCE (0x30), а не SET (0x31)")
    void testBlockContentStartsWithSequence() {
        byte[] csr = builder().sanDns("a.example.com").sign(KEY, "pass".toCharArray());
        byte[] block = attributesBlockContent(parse(csr).getTbsCertRequest());
        assertEquals(0x30, block[0] & 0xFF, "внутри [0] не должно быть внешнего SET");
        assertEquals(2, parse(csr).getAttributes().size());
    }

    @Test
    @DisplayName("Блок [0]: перестановка вызовов attribute() не меняет TBS")
    void testAttributeCallOrderDoesNotMatter() {
        byte[] first =
                builder().attribute(OID_A, derUtf8("a")).attribute(OID_B, derUtf8("b")).sign(KEY);
        byte[] second =
                builder().attribute(OID_B, derUtf8("b")).attribute(OID_A, derUtf8("a")).sign(KEY);
        assertArrayEquals(
                parse(first).getTbsCertRequest(),
                parse(second).getTbsCertRequest(),
                "порядок вызовов повлиял на кодирование");
    }

    @Test
    @DisplayName("Блок [0]: перестановка значений внутри атрибута не меняет TBS")
    void testValueOrderDoesNotMatter() {
        byte[] first =
                builder().attribute(OID_A, derUtf8("x"), derUtf8("yy"), derUtf8("z")).sign(KEY);
        byte[] second =
                builder().attribute(OID_A, derUtf8("z"), derUtf8("x"), derUtf8("yy")).sign(KEY);
        assertArrayEquals(
                parse(first).getTbsCertRequest(),
                parse(second).getTbsCertRequest(),
                "порядок значений повлиял на кодирование");
    }

    @Test
    @DisplayName("Атрибуты, пароль и расширения вместе: подпись верна, всё читается")
    void testAllAttributesTogether() {
        byte[] csr =
                builder()
                        .sanDns("a.example.com")
                        .attribute(OID_A, derUtf8("one"), derUtf8("two"))
                        .sign(KEY, "secret".toCharArray());
        GostCsrParser parsed = parse(csr);
        assertTrue(parsed.verifySelf(), "подпись CSR не прошла проверку");
        assertEquals(3, parsed.getAttributes().size());
        assertEquals("secret", new String(parsed.getChallengePassword().orElseThrow()));
        assertEquals(
                "a.example.com", parsed.getExtensions().sanDnsNames[0], "extensionRequest потерян");
        List<byte[]> values = parsed.getAttribute(OID_A).orElseThrow().valuesDer();
        assertEquals(2, values.size());
    }

    // ========================================================================
    // Сборщик: attribute(...)
    // ========================================================================

    @Test
    @DisplayName("attribute: повтор OID, extensionRequest и challengePassword отвергаются")
    void testAttributeRestrictions() {
        GostCsrBuilder b = builder().attribute(OID_A, derUtf8("a"));
        assertThrows(IllegalArgumentException.class, () -> b.attribute(OID_A, derUtf8("b")));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute(GostOids.ATTR_EXTENSION_REQUEST, derUtf8("a")));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute(GostOids.ATTR_CHALLENGE_PASSWORD, derUtf8("a")));
    }

    @Test
    @DisplayName(
            "attribute: пустой список значений, мусор в значении и плохой OID отвергаются сразу")
    void testAttributeArgumentValidation() {
        assertThrows(IllegalArgumentException.class, () -> builder().attribute(OID_A));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute(OID_A, new byte[0]),
                "пустое значение не является DER-элементом");
        byte[] trailing = DerCodec.concat(derUtf8("a"), new byte[] {0x05, 0x00});
        assertThrows(IllegalArgumentException.class, () -> builder().attribute(OID_A, trailing));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute("не-oid", derUtf8("a")),
                "опечатка в OID должна всплыть при вызове, а не в sign");
        assertThrows(IllegalArgumentException.class, () -> builder().attribute("1", derUtf8("a")));
    }

    @Test
    @DisplayName("attribute: зарезервированные теги 0x00 и 0xFF отвергаются")
    void testAttributeReservedTags() {
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute(OID_A, new byte[] {0, 0}));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute(OID_A, new byte[] {(byte) 0xFF, 0}));
    }

    @Test
    @DisplayName("attribute: неканонический OID не обходит запреты и повторы")
    void testAttributeNonCanonicalOid() {
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().attribute("01.2.840.113549.1.9.7", derUtf8("a")),
                "challengePassword в неканонической записи");
        GostCsrBuilder b = builder().attribute(OID_A, derUtf8("a"));
        assertThrows(IllegalArgumentException.class, () -> b.attribute("01.2.03.4", derUtf8("b")));
    }

    @Test
    @DisplayName("attribute: изменение массива после вызова не влияет на CSR")
    void testAttributeCopiesValues() {
        byte[] value = derUtf8("original");
        GostCsrBuilder b = builder().attribute(OID_A, value);
        byte[] expected = builder().attribute(OID_A, derUtf8("original")).sign(KEY);
        Arrays.fill(value, (byte) 0x41);
        assertArrayEquals(
                parse(expected).getTbsCertRequest(),
                parse(b.sign(KEY)).getTbsCertRequest(),
                "сборщик хранит ссылку на массив вызывающего");
    }

    // ========================================================================
    // Сборщик: sign(..., char[])
    // ========================================================================

    @Test
    @DisplayName("sign с паролем: ASCII-алфавит -> PrintableString, иначе UTF8String")
    void testPasswordTypeSelection() {
        assertEquals(
                DerCodec.TAG_PRINTABLE_STRING,
                passwordTag(builder().sign(KEY, "Pass 123".toCharArray())));
        // '@' вне алфавита X.680: при записи строго -> UTF8String
        assertEquals(
                DerCodec.TAG_UTF8_STRING, passwordTag(builder().sign(KEY, "a@b".toCharArray())));
        assertEquals(
                DerCodec.TAG_UTF8_STRING, passwordTag(builder().sign(KEY, "пароль".toCharArray())));
    }

    @Test
    @DisplayName("sign с паролем: границы длины в знаках и в байтах")
    void testPasswordLengthLimits() {
        assertThrows(IllegalArgumentException.class, () -> builder().sign(KEY, new char[0]));
        assertThrows(IllegalArgumentException.class, () -> builder().sign(KEY, (char[]) null));
        assertEquals("a", new String(password(builder().sign(KEY, "a".toCharArray()))));
        String longest = repeat('a', 255);
        assertEquals(longest, new String(password(builder().sign(KEY, longest.toCharArray()))));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().sign(KEY, repeat('a', 256).toCharArray()));
        // 255 знаков, но 510 байт UTF-8: нарушает предел RFC 7030 §3.5
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().sign(KEY, repeat('я', 255).toCharArray()),
                "255 знаков кириллицей превышают 255 байт");
        assertEquals(
                repeat('я', 127),
                new String(password(builder().sign(KEY, repeat('я', 127).toCharArray()))));
    }

    @Test
    @DisplayName("sign с паролем: управляющие знаки C0, DEL и C1 отвергаются")
    void testPasswordControlCharactersRejected() {
        for (int codePoint : new int[] {0x0000, 0x000A, 0x001F}) {
            String text = "ab" + (char) codePoint + "cd";
            assertThrows(
                    IllegalArgumentException.class,
                    () -> builder().sign(KEY, text.toCharArray()),
                    "C0 U+" + Integer.toHexString(codePoint));
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().sign(KEY, "ab\u007Fcd".toCharArray()),
                "DEL");
        for (int codePoint : new int[] {0x0085, 0x009B}) {
            String text = "ab" + (char) codePoint + "cd";
            assertThrows(
                    IllegalArgumentException.class,
                    () -> builder().sign(KEY, text.toCharArray()),
                    "C1 U+" + Integer.toHexString(codePoint));
        }
    }

    @Test
    @DisplayName("sign с паролем: одиночный суррогат отвергается, пара принимается")
    void testPasswordSurrogates() {
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().sign(KEY, new char[] {'a', '\uD83D', 'b'}));
        assertThrows(
                IllegalArgumentException.class, () -> builder().sign(KEY, new char[] {'\uDE00'}));
        String withEmoji = "a😀b";
        assertEquals(withEmoji, new String(password(builder().sign(KEY, withEmoji.toCharArray()))));
    }

    @Test
    @DisplayName("sign с паролем: переданный массив не изменяется, сборщик пригоден повторно")
    void testPasswordArrayUntouchedAndBuilderReusable() {
        char[] pass = "secret".toCharArray();
        char[] copy = pass.clone();
        GostCsrBuilder b = builder().attribute(OID_A, derUtf8("a"));
        byte[] first = b.sign(KEY, pass);
        assertArrayEquals(copy, pass, "библиотека изменила переданный пароль");

        // После ошибки (недопустимый пароль) сборщик остаётся рабочим
        assertThrows(IllegalArgumentException.class, () -> b.sign(KEY, new char[0]));
        byte[] second = b.sign(KEY, "other".toCharArray());
        assertEquals("secret", new String(password(first)));
        assertEquals("other", new String(password(second)));
        assertTrue(parse(first).verifySelf() && parse(second).verifySelf());

        // sign без пароля побайтно как раньше, на том же сборщике
        assertTrue(parse(b.sign(KEY)).getChallengePassword().isEmpty());
    }

    @Test
    @DisplayName(
            "sign с паролем: несовпадение ключа даёт IllegalStateException и не ломает сборщик")
    void testPasswordSignWithMismatchedKey() {
        PrivateKeyParameters other =
                new PrivateKeyParameters(BigInteger.valueOf(0x1234567L).shiftLeft(100), PARAMS);
        GostCsrBuilder b = builder();
        assertThrows(IllegalStateException.class, () -> b.sign(other, "pw".toCharArray()));
        assertTrue(parse(b.sign(KEY, "pw".toCharArray())).verifySelf());
    }

    // ========================================================================
    // Разборщик: типы строки пароля
    // ========================================================================

    @Test
    @DisplayName("Разбор: один и тот же ASCII-пароль во всех пяти типах даёт одинаковый char[]")
    void testSamePasswordInAllFiveTypes() {
        String text = "Pa55 word";
        byte[][] encodings = {
            text.getBytes(StandardCharsets.UTF_8),
            text.getBytes(StandardCharsets.US_ASCII),
            text.getBytes(StandardCharsets.ISO_8859_1),
            utf16be(text),
            utf32be(text)
        };
        int[] tags = {0x0C, 0x13, 0x14, 0x1E, 0x1C};
        for (int i = 0; i < tags.length; i++) {
            char[] decoded = password(csrWithBlock(passwordAttr(tags[i], encodings[i])));
            assertEquals(text, new String(decoded), "тип 0x" + Integer.toHexString(tags[i]));
        }
    }

    @Test
    @DisplayName("Разбор: кириллица в UTF8String и UniversalString, é в TeletexString")
    void testNonAsciiTypes() {
        assertEquals(
                "пароль",
                new String(password(csrWithBlock(passwordAttr(0x0C, derContent("пароль"))))));
        assertEquals(
                "пароль",
                new String(password(csrWithBlock(passwordAttr(0x1C, utf32be("пароль"))))));
        assertEquals(
                "café",
                new String(
                        password(
                                csrWithBlock(
                                        passwordAttr(
                                                0x14, new byte[] {'c', 'a', 'f', (byte) 0xE9})))),
                "TeletexString читается как ISO-8859-1");
    }

    @Test
    @DisplayName("Разбор: символ вне алфавита PrintableString принимается при чтении")
    void testPrintableAlphabetNotEnforcedOnRead() {
        byte[] csr = csrWithBlock(passwordAttr(0x13, "a@b_c*".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("a@b_c*", new String(password(csr)));
        // а при записи тот же пароль уходит в UTF8String: политики чтения и записи разные
        assertEquals(0x0C, passwordTag(builder().sign(KEY, "a@b_c*".toCharArray())));
    }

    @Test
    @DisplayName("Разбор: getChallengePassword возвращает свежую копию при каждом вызове")
    void testGetterReturnsFreshCopy() {
        GostCsrParser parsed = parse(builder().sign(KEY, "secret".toCharArray()));
        char[] first = parsed.getChallengePassword().orElseThrow();
        Arrays.fill(first, 'x');
        assertEquals("secret", new String(parsed.getChallengePassword().orElseThrow()));
    }

    private static byte[] derContent(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    // ========================================================================
    // Разборщик: негативные случаи пароля
    // ========================================================================

    private static void assertRejected(byte[] csr, String message) {
        assertThrows(IllegalArgumentException.class, () -> parse(csr), message);
    }

    @Test
    @DisplayName("Разбор пароля: нарушения кодировки типов отвергаются")
    void testMalformedPasswordEncodings() {
        assertRejected(csrWithBlock(passwordAttr(0x0C, new byte[] {'a', (byte) 0xFF})), "UTF-8");
        assertRejected(csrWithBlock(passwordAttr(0x13, new byte[] {'a', (byte) 0x80})), "ASCII");
        assertRejected(csrWithBlock(passwordAttr(0x1E, new byte[] {0, 'a', 0})), "BMP нечётная");
        assertRejected(
                csrWithBlock(passwordAttr(0x1C, new byte[] {0, 0, 0, 'a', 0, 0})),
                "Universal не кратно 4");
        assertRejected(
                csrWithBlock(passwordAttr(0x1E, new byte[] {(byte) 0xD8, 0x00, 0x00, 'a'})),
                "BMP непарный суррогат");
        assertRejected(
                csrWithBlock(passwordAttr(0x1E, utf16be("😀"))), "BMP не содержит суррогатных пар");
        assertRejected(
                csrWithBlock(passwordAttr(0x1C, new byte[] {0x00, 0x11, 0x00, 0x00})),
                "Universal выше U+10FFFF");
        assertRejected(
                csrWithBlock(passwordAttr(0x1C, new byte[] {0x00, 0x00, (byte) 0xD8, 0x00})),
                "Universal суррогат");
        assertRejected(
                csrWithBlock(passwordAttr(0x16, "abc".getBytes(StandardCharsets.US_ASCII))),
                "IA5String не DirectoryString");
        assertRejected(
                csrWithBlock(passwordAttr(0x04, "abc".getBytes(StandardCharsets.US_ASCII))),
                "OCTET STRING");
    }

    @Test
    @DisplayName("Разбор пароля: пустой, 256 знаков, 255 знаков кириллицей (>255 байт)")
    void testPasswordLengthLimitsOnParse() {
        assertRejected(csrWithBlock(passwordAttr(0x0C, new byte[0])), "пустой пароль");
        assertRejected(
                csrWithBlock(passwordAttr(0x0C, derContent(repeat('a', 256)))), "256 знаков");
        assertRejected(
                csrWithBlock(passwordAttr(0x0C, derContent(repeat('я', 255)))),
                "255 знаков, но 510 байт");
        assertEquals(
                255,
                password(csrWithBlock(passwordAttr(0x0C, derContent(repeat('a', 255))))).length);
    }

    @Test
    @DisplayName("Разбор пароля: управляющие знаки C0, DEL и C1 отвергаются в каждом из пяти типов")
    void testControlCharactersInEveryType() {
        for (int codePoint : new int[] {0x0000, 0x000D, 0x000A, 0x007F, 0x0085, 0x009B}) {
            String text = "ab" + (char) codePoint + "cd";
            String label = "U+" + Integer.toHexString(codePoint);
            assertRejected(csrWithBlock(passwordAttr(0x0C, derContent(text))), "UTF8 " + label);
            assertRejected(
                    csrWithBlock(passwordAttr(0x14, text.getBytes(StandardCharsets.ISO_8859_1))),
                    "T61 " + label);
            assertRejected(csrWithBlock(passwordAttr(0x1E, utf16be(text))), "BMP " + label);
            assertRejected(csrWithBlock(passwordAttr(0x1C, utf32be(text))), "Universal " + label);
            if (codePoint < 0x80) {
                assertRejected(
                        csrWithBlock(passwordAttr(0x13, text.getBytes(StandardCharsets.US_ASCII))),
                        "Printable " + label);
            }
        }
    }

    @Test
    @DisplayName("Разбор пароля: два значения в атрибуте отвергаются")
    void testTwoPasswordValues() {
        byte[] twoValues =
                attr(
                        GostOids.ATTR_CHALLENGE_PASSWORD,
                        DerCodec.encodeTlv(0x0C, derContent("a")),
                        DerCodec.encodeTlv(0x0C, derContent("b")));
        assertRejected(csrWithBlock(twoValues), "SINGLE VALUE");
    }

    @Test
    @DisplayName("Разбор пароля: CSR с некорректным паролем отвергается целиком")
    void testBadPasswordRejectsWholeCsr() {
        // пароль вызывающему не нужен, но запрос всё равно отвергается: строгий разбор
        assertRejected(
                csrWithBlock(
                        attr(OID_A, derUtf8("ok")), passwordAttr(0x0C, new byte[] {(byte) 0xFF})),
                "CSR принят вместе с битым паролем");
    }

    // ========================================================================
    // Разборщик: структура блока атрибутов
    // ========================================================================

    @Test
    @DisplayName("Разбор: внутренний SET внутри [0] отвергается")
    void testInnerSetRejected() {
        byte[] attribute = attr(OID_A, derUtf8("a"));
        byte[] tbs =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00}),
                        GostDnParser.encodeDn("CN=Regress,O=Test"),
                        GostDerCodec.encodePublicKey(PUB),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeSet(attribute)));
        assertRejected(signTbs(tbs), "внутренний SET принят");
    }

    @Test
    @DisplayName("Разбор: повтор OID и повтор extensionRequest отвергаются")
    void testDuplicateAttributesRejected() {
        assertRejected(csrWithBlock(attr(OID_A, derUtf8("a")), attr(OID_A, derUtf8("b"))), "OID");
        byte[] extensions = DerCodec.encodeSequence();
        byte[] extensionRequest = attr(GostOids.ATTR_EXTENSION_REQUEST, extensions);
        assertRejected(csrWithBlock(extensionRequest, extensionRequest), "extensionRequest");
    }

    @Test
    @DisplayName("Разбор: пустой SET значений, хвосты и не-SEQUENCE в [0] отвергаются")
    void testStructuralViolations() {
        assertRejected(
                csrWithBlock(
                        DerCodec.encodeSequence(DerCodec.encodeOid(OID_A), DerCodec.encodeSet())),
                "пустой SET значений");
        assertRejected(
                csrWithBlock(
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(OID_A),
                                DerCodec.encodeSet(derUtf8("a")),
                                derUtf8("tail"))),
                "хвост после SET значений");
        assertRejected(
                csrWithBlock(DerCodec.encodeSequence(DerCodec.encodeOid(OID_A))),
                "атрибут без значений");
        assertRejected(
                csrWithBlock(
                        DerCodec.encodeSequence(
                                derUtf8("не-OID"), DerCodec.encodeSet(derUtf8("a")))),
                "атрибут без OID");
        assertRejected(csrWithBlock(derUtf8("не атрибут")), "не-SEQUENCE в [0]");
    }

    @Test
    @DisplayName("Разбор: порядок элементов SET OF не проверяется")
    void testUnsortedSetsAccepted() {
        // оба атрибута и значения внутри — в «неправильном» DER-порядке
        byte[] bigger = attr(OID_B, derUtf8("zz"), derUtf8("a"));
        byte[] smaller = attr(OID_A, derUtf8("b"));
        byte[][] sorted = {bigger, smaller};
        DerCodec.sortDer(sorted);
        byte[] csr = csrWithBlock(sorted[1], sorted[0]);
        GostCsrParser parsed = parse(csr);
        assertEquals(2, parsed.getAttributes().size());
        assertTrue(parsed.verifySelf());
    }

    @Test
    @DisplayName("Разбор: extensionRequest из ручной сборки по-прежнему читается")
    void testExtensionRequestStillParsed() {
        byte[] dns = DerCodec.encodeTlv(0x82, "x.example.com".getBytes(StandardCharsets.US_ASCII));
        byte[] extension =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.17"),
                        DerCodec.encodeOctetString(DerCodec.encodeSequence(dns)));
        byte[] csr =
                csrWithBlock(
                        attr(GostOids.ATTR_EXTENSION_REQUEST, DerCodec.encodeSequence(extension)));
        assertEquals("x.example.com", parse(csr).getExtensions().sanDnsNames[0]);
    }

    @Test
    @DisplayName("Разбор: CSR без атрибутов и без пароля")
    void testNoAttributes() {
        GostCsrParser parsed = parse(builder().sign(KEY));
        assertTrue(parsed.getAttributes().isEmpty());
        assertEquals(Optional.empty(), parsed.getAttribute(OID_A));
        assertTrue(parsed.getChallengePassword().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> parsed.getAttribute("не-oid"));
    }

    @Test
    @DisplayName("getAttribute: неканонический OID находит тот же атрибут")
    void testGetAttributeNonCanonicalOid() {
        GostCsrParser parsed = parse(builder().attribute(OID_A, derUtf8("v")).sign(KEY));
        assertTrue(parsed.getAttribute("01.2.03.4").isPresent());
    }

    @Test
    @DisplayName("Мутации блока атрибутов не приводят к молчаливой потере атрибута")
    void testMutationsDoNotSilentlyDropAttributes() {
        byte[] csr =
                builder()
                        .sanDns("a.example.com")
                        .attribute(OID_A, derUtf8("a"), derUtf8("b"))
                        .sign(KEY, "secret".toCharArray());
        GostCsrParser original = parse(csr);
        int expected = original.getAttributes().size();
        byte[] tbs = original.getTbsCertRequest();
        // блок [0] занимает хвост TBS; мутируем каждый его байт (включая тег и длину)
        int tbsStart = indexOf(csr, tbs);
        int blockStart = tbsStart + attributesBlockOffset(tbs);
        for (int i = blockStart; i < tbsStart + tbs.length; i++) {
            byte[] mutated = csr.clone();
            mutated[i] ^= (byte) 0xFF;
            try {
                GostCsrParser parsed = parse(mutated);
                assertEquals(
                        expected,
                        parsed.getAttributes().size(),
                        "мутация байта " + i + " молча изменила набор атрибутов");
            } catch (RuntimeException expectedRejection) {
                // отказ — ожидаемый исход
            }
        }
        for (int cut = 1; cut < 40; cut++) {
            byte[] truncated = Arrays.copyOf(csr, csr.length - cut);
            assertThrows(RuntimeException.class, () -> parse(truncated), "обрезка на " + cut);
        }
    }

    // ========================================================================
    // Секреты в выводе и идентичность
    // ========================================================================

    @Test
    @DisplayName("toString разборщика и атрибута не содержит пароля")
    void testToStringHasNoPassword() {
        GostCsrParser parsed = parse(builder().sign(KEY, "TopSecret77".toCharArray()));
        assertFalse(parsed.toString().contains("TopSecret77"));
        CsrAttribute attribute =
                parsed.getAttribute(GostOids.ATTR_CHALLENGE_PASSWORD).orElseThrow();
        assertFalse(attribute.toString().contains("TopSecret77"));
        assertFalse(attribute.toString().contains("54 6f 70"));
    }

    @Test
    @DisplayName("CsrAttribute: значения копируются, equals и hashCode побайтные")
    void testCsrAttributeIdentity() {
        GostCsrParser parsed = parse(builder().attribute(OID_A, derUtf8("v")).sign(KEY));
        CsrAttribute attribute = parsed.getAttribute(OID_A).orElseThrow();
        attribute.valuesDer().get(0)[2] ^= 1;
        assertArrayEquals(
                derUtf8("v"), attribute.valuesDer().get(0), "изменение копии затронуло атрибут");
        CsrAttribute same =
                parse(builder().attribute(OID_A, derUtf8("v")).sign(KEY)).getAttributes().get(0);
        assertEquals(attribute, same);
        assertEquals(attribute.hashCode(), same.hashCode());
        assertThrows(
                UnsupportedOperationException.class, () -> parsed.getAttributes().add(attribute));
        assertThrows(
                UnsupportedOperationException.class, () -> attribute.valuesDer().add(new byte[0]));
    }
}
