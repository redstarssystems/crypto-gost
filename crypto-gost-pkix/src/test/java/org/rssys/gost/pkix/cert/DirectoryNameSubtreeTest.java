package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

@DisplayName("DirectoryNameSubtree: RDN-поддеревья и нормализация")
class DirectoryNameSubtreeTest {

    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");
    private static final String UNKNOWN_OID = "1.2.3.4.5";
    // dnQualifier (RFC 5280): не входит в CASE_IGNORE_OIDS, сравнивается побайтно.
    private static final String DN_QUALIFIER_OID = "2.5.4.46";

    @Test
    @DisplayName("AVA, выходящий за границу своего RDN, отвергается как PARSE_ERROR")
    void testAvaExceedingRdnBoundaryRejected() {
        byte[] ava = ava(GostOids.ATTR_CN, utf8("Evil"));
        // SET объявляет длину на байт короче AVA; недостающий байт лежит уже за SET, но внутри DN
        byte[] shortSet =
                DerCodec.encodeTlv(DerCodec.TAG_SET, java.util.Arrays.copyOf(ava, ava.length - 1));
        byte[] dn = dn(shortSet, new byte[] {ava[ava.length - 1]});

        PkixException e = assertThrows(PkixException.class, () -> parse(dn));
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), "Ожидался PARSE_ERROR");
    }

    @Test
    @DisplayName("Второй AVA, выходящий за границу RDN, отвергается как PARSE_ERROR")
    void testSecondAvaExceedingRdnBoundaryRejected() {
        byte[] first = ava(GostOids.ATTR_CN, utf8("Evil"));
        byte[] second = ava(GostOids.ATTR_O, utf8("Org"));
        byte[] shortSet =
                DerCodec.encodeTlv(
                        DerCodec.TAG_SET,
                        java.util.Arrays.copyOf(
                                DerCodec.concat(first, second), first.length + second.length - 1));
        byte[] dn = dn(shortSet, new byte[] {second[second.length - 1]});

        PkixException e = assertThrows(PkixException.class, () -> parse(dn));
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), "Ожидался PARSE_ERROR");
    }

    @Test
    @DisplayName("Одинаковый DN входит в поддерево")
    void testIdenticalDn() throws Exception {
        DirectoryNameSubtree.Dn dn = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        dn, dn, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Поддерево из одного и двух RDN является префиксом")
    void testPrefix() throws Exception {
        DirectoryNameSubtree.Dn one = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_O, utf8("Evil"))),
                                rdn(ava(GostOids.ATTR_CN, utf8("x")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, one, DirectoryNameSubtree.MatchMode.PERMITTED));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, name, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Имя короче поддерева не входит")
    void testNameShorter() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_O, utf8("Evil"))),
                                rdn(ava(GostOids.ATTR_CN, utf8("x")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Порядок RDN значим")
    void testDifferentRdnOrder() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_CN, utf8("x"))),
                                rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_O, utf8("Evil"))),
                                rdn(ava(GostOids.ATTR_CN, utf8("x")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Multi-valued RDN: порядок AVA не значим")
    void testMultiValuedRdn() throws Exception {
        byte[] o = ava(GostOids.ATTR_O, utf8("Evil"));
        byte[] cn = ava(GostOids.ATTR_CN, utf8("x"));
        DirectoryNameSubtree.Dn name = parse(dn(rdnRaw(o, cn)));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdnRaw(cn, o)));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: тип строки не важен для caseIgnore-атрибута")
    void testPermittedStringTypeInsensitive() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Good")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, printable("Good")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: регистр не важен для CN")
    void testPermittedCaseInsensitive() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_CN, utf8("EVIL")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_CN, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: неизвестный OID сравнивается побайтно")
    void testPermittedUnknownOidBinary() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(UNKNOWN_OID, utf8("Good")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(UNKNOWN_OID, printable("Good")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: нестроковое значение не совпадает")
    void testPermittedOctetStringRejected() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, octet("Good")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, printable("Good")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Excluded: тип строки не важен")
    void testExcludedStringTypeInsensitive() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, printable("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Excluded: UniversalString декодируется и совпадает")
    void testExcludedUniversalString() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, universal("Evil")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, printable("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Excluded: пробелы нормализуются")
    void testExcludedWhitespace() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(dn(rdn(ava(GostOids.ATTR_O, utf8("  Evil   Corp  ")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil Corp")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Excluded: fullwidth-символы нормализуются через NFKC")
    void testExcludedFullwidth() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Ｅｖｉｌ")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Excluded: zero-width символы удаляются")
    void testExcludedZeroWidth() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Ev\u200Bil")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Excluded: турецкая ı без точки не зависит от default locale")
    void testExcludedTurkishDotlessI() throws Exception {
        Locale old = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("ı")))));
            DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("I")))));
            assertTrue(
                    DirectoryNameSubtree.isWithinSubtree(
                            name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
        } finally {
            Locale.setDefault(old);
        }
    }

    @Test
    @DisplayName("Excluded: OCTET STRING у известного и неизвестного OID — совпадение")
    void testExcludedOctetString() throws Exception {
        DirectoryNameSubtree.Dn knownName = parse(dn(rdn(ava(GostOids.ATTR_O, octet("Evil")))));
        DirectoryNameSubtree.Dn knownSubtree =
                parse(dn(rdn(ava(GostOids.ATTR_O, printable("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        knownName, knownSubtree, DirectoryNameSubtree.MatchMode.EXCLUDED));

        DirectoryNameSubtree.Dn unknownName = parse(dn(rdn(ava(UNKNOWN_OID, octet("x")))));
        DirectoryNameSubtree.Dn unknownSubtree = parse(dn(rdn(ava(UNKNOWN_OID, printable("x")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        unknownName, unknownSubtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Пустой DN разбирается, но не входит в непустое поддерево")
    void testEmptyDn() throws Exception {
        DirectoryNameSubtree.Dn empty = parse(dn());
        assertTrue(empty.isEmpty());
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        empty, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Кириллица в permitted-поддереве сравнивается без учёта регистра")
    void testCyrillicCaseInsensitive() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("ООО РОМАШКА")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("ооо ромашка")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Malformed DN и лимиты отклоняются")
    void testMalformedAndLimits() {
        assertThrows(PkixException.class, () -> parse(new byte[] {0x31, 0x00}));
        assertThrows(PkixException.class, () -> parse(dn(rdnRaw())));
        byte[] valid = dn(rdn(ava(GostOids.ATTR_O, utf8("Evil"))));
        byte[] trailing = DerCodec.concat(valid, new byte[] {0x00});
        assertThrows(PkixException.class, () -> parse(trailing));

        byte[][] manyRdns = new byte[DirectoryNameSubtree.MAX_RDNS + 1][];
        for (int i = 0; i < manyRdns.length; i++) {
            manyRdns[i] = rdn(ava(GostOids.ATTR_O, utf8("v" + i)));
        }
        assertThrows(PkixException.class, () -> parse(dn(manyRdns)));

        byte[][] manyAvas = new byte[DirectoryNameSubtree.MAX_AVAS_PER_RDN + 1][];
        for (int i = 0; i < manyAvas.length; i++) {
            manyAvas[i] = ava(GostOids.ATTR_CN, utf8("v" + i));
        }
        assertThrows(PkixException.class, () -> parse(dn(rdnRaw(manyAvas))));
    }

    @Test
    @DisplayName("Неминимальный OID в AVA отклоняется")
    void testNonMinimalOidRejected() {
        byte[] nonMinimalOid = {(byte) 0x80, 0x55, 0x04, 0x03};
        byte[] der = dn(rdn(avaRawOid(nonMinimalOid, utf8("Evil"))));
        assertThrows(
                PkixException.class,
                () -> parse(der),
                "неминимальное кодирование OID должно отклоняться");
    }

    @Test
    @DisplayName("Строки с символами вне алфавита отклоняются")
    void testRestrictedStringAlphabet() {
        assertThrows(
                PkixException.class,
                () -> parse(dn(rdn(ava(GostOids.ATTR_O, printable("bad@example"))))),
                "PrintableString не допускает @");
        assertThrows(
                PkixException.class,
                () -> parse(dn(rdn(ava(GostOids.ATTR_CN, numeric("12A"))))),
                "NumericString допускает только цифры и пробел");
        assertThrows(
                PkixException.class,
                () ->
                        parse(
                                dn(
                                        rdn(
                                                ava(
                                                        GostOids.ATTR_O,
                                                        rawValue(
                                                                0x16, new byte[] {(byte) 0x80}))))),
                "IA5String не допускает байты вне ASCII");
    }

    @Test
    @DisplayName("Некорректный UTF-8 отклоняется")
    void testMalformedUtf8Rejected() {
        byte[] der = dn(rdn(ava(GostOids.ATTR_O, rawValue(0x0C, new byte[] {(byte) 0xC3, 0x28}))));
        assertThrows(PkixException.class, () -> parse(der));
    }

    @Test
    @DisplayName("emailAddress допускается только как IA5String")
    void testEmailAddressRequiresIa5() {
        assertDoesNotThrow(() -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, ia5("user@example.com"))))));
        assertThrows(
                PkixException.class,
                () -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, utf8("user@example.com"))))),
                "emailAddress в UTF8String недопустим");
        assertThrows(
                PkixException.class,
                () -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, printable("user@example.com"))))),
                "emailAddress в PrintableString недопустим");
    }

    @Test
    @DisplayName("emailAddress: NUL, C0 и DEL отвергаются, обычный адрес проходит")
    void testEmailAddressControlCharactersRejected() {
        for (String bad :
                new String[] {
                    "a\0b@example.com",
                    "a\nb@example.com",
                    "a\tb@example.com",
                    "a\u001fb@example.com",
                    "a\u007fb@example.com",
                    "\0user@example.com",
                    "user@example.com\0"
                }) {
            assertThrows(
                    PkixException.class,
                    () -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, ia5(bad))))),
                    "управляющий символ в emailAddress должен отвергаться");
        }
        assertDoesNotThrow(() -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, ia5("user@example.com"))))));
    }

    @Test
    @DisplayName("T61 в emailAddress отвергается (обязателен IA5String)")
    void testEmailAddressT61Rejected() {
        assertThrows(
                PkixException.class,
                () -> parse(dn(rdn(ava(GostOids.ATTR_EMAIL, t61("user@example.com"))))));
    }

    @Test
    @DisplayName("T61 без ограничений directoryName разбирается без ошибки")
    void testT61ParsesWithoutConstraints() {
        assertDoesNotThrow(() -> parse(dn(rdn(ava(GostOids.ATTR_CN, t61("Legacy"))))));
    }

    @Test
    @DisplayName("Permitted: побайтово идентичные T61 CN совпадают")
    void testPermittedT61IdenticalValueMatches() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_CN, t61("Legacy")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_CN, t61("Legacy")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: T61 с разным регистром не совпадают (сравнение побайтовое)")
    void testPermittedT61DifferentCaseDoesNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_CN, t61("EXAMPLE")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_CN, t61("example")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: байты 0xC9 и 0xE9 не склеиваются (в Latin-1 É и é, в T.61 разные)")
    void testPermittedT61LatinCaseFoldedBytesDoNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdn(
                                        ava(
                                                GostOids.ATTR_CN,
                                                rawValue(0x14, new byte[] {(byte) 0xC9, 'x'})))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdn(
                                        ava(
                                                GostOids.ATTR_CN,
                                                rawValue(0x14, new byte[] {(byte) 0xE9, 'x'})))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED),
                "приведение регистра по Latin-1 не должно склеивать разные байты T.61");
    }

    @Test
    @DisplayName("Permitted: T61 в ограничении не совпадает с UTF8-значением того же текста")
    void testPermittedT61VersusUtf8DoesNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_CN, utf8("Legacy")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_CN, t61("Legacy")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Permitted: идентичный T61 для dnQualifier (вне caseIgnore) совпадает побайтно")
    void testPermittedT61NonCaseIgnoreOidMatchesBinary() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(DN_QUALIFIER_OID, t61("Legacy")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(DN_QUALIFIER_OID, t61("Legacy")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED));
    }

    @Test
    @DisplayName("Excluded: T61 в ограничении срабатывает при совпавших предшествующих RDN")
    void testExcludedT61MatchesAnyValueOfSameOid() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_C, printable("RU"))),
                                rdn(ava(GostOids.ATTR_CN, utf8("Anything")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_C, printable("RU"))),
                                rdn(ava(GostOids.ATTR_CN, t61("Legacy")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "значение T61 нельзя истолковать однозначно: excluded должен сработать");
    }

    @Test
    @DisplayName("Excluded: T61 не срабатывает, если предшествующий RDN не совпал")
    void testExcludedT61DoesNotMatchWhenPrecedingRdnDiffers() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_C, printable("US"))),
                                rdn(ava(GostOids.ATTR_CN, utf8("Anything")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdn(ava(GostOids.ATTR_C, printable("RU"))),
                                rdn(ava(GostOids.ATTR_CN, t61("Legacy")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED));
    }

    @Test
    @DisplayName("Корректные NumericString и PrintableString принимаются")
    void testValidRestrictedStringsAccepted() {
        assertDoesNotThrow(
                () ->
                        parse(
                                dn(
                                        rdn(ava(GostOids.ATTR_O, printable("Good Org"))),
                                        rdn(ava(GostOids.ATTR_CN, numeric("123 456"))))));
    }

    @Test
    @DisplayName("Excluded: RDN с лишним AVA входит в запрещённое поддерево")
    void testExcludedRdnWithExtraAvaMatches() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Evil")),
                                        ava(GostOids.ATTR_OU, utf8("x")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Лишний AVA в RDN не должен выводить имя из запрещённого поддерева");
    }

    @Test
    @DisplayName("Excluded: запрет с большим числом AVA, чем в имени, не срабатывает")
    void testExcludedSubtreeWiderThanNameDoesNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Evil")),
                                        ava(GostOids.ATTR_OU, utf8("x")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Запрет, требующий больше AVA, чем есть в имени, не должен совпадать");
    }

    @Test
    @DisplayName("Excluded: несколько AVA запрета входят в более широкий RDN имени")
    void testExcludedMultiAvaSubsetMatches() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Evil")),
                                        ava(GostOids.ATTR_OU, utf8("x")),
                                        ava(GostOids.ATTR_CN, utf8("y")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_CN, utf8("y")),
                                        ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Подмножество AVA запрета должно находиться в RDN имени независимо от порядка");
    }

    @Test
    @DisplayName("Excluded: лишний AVA в RDN имени не совпадает с чужим значением")
    void testExcludedExtraAvaWithDifferentValueDoesNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Good")),
                                        ava(GostOids.ATTR_OU, utf8("x")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Другое значение O не должно попадать в запрещённое поддерево");
    }

    @Test
    @DisplayName("Permitted: лишний AVA в RDN имени не входит в разрешённое поддерево")
    void testPermittedRdnWithExtraAvaDoesNotMatch() throws Exception {
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Evil")),
                                        ava(GostOids.ATTR_OU, utf8("x")))));
        DirectoryNameSubtree.Dn subtree = parse(dn(rdn(ava(GostOids.ATTR_O, utf8("Evil")))));
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.PERMITTED),
                "Для permitted совпадение RDN остаётся строгим равенством");
    }

    @Test
    @DisplayName("Excluded: недекодируемый AVA не мешает найти сопоставление остальных")
    void testExcludedUndecodableAvaDoesNotBreakMatching() throws Exception {
        // OCTET STRING (0x04) в каноническом порядке идёт раньше UTF8String (0x0C), поэтому
        // жадный перебор отдал бы ему первый же AVA имени и не нашёл пару для O=Evil.
        DirectoryNameSubtree.Dn name =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, utf8("Evil")),
                                        ava(GostOids.ATTR_O, utf8("Other")))));
        DirectoryNameSubtree.Dn subtree =
                parse(
                        dn(
                                rdnRaw(
                                        ava(GostOids.ATTR_O, octet("opaque")),
                                        ava(GostOids.ATTR_O, utf8("Evil")))));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        name, subtree, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Существующее сопоставление AVA не должно теряться из-за порядка перебора");
    }

    @Test
    @DisplayName("Excluded: дубликаты AVA требуют отдельной пары каждому")
    void testExcludedDuplicateAvasNeedSeparatePairs() throws Exception {
        byte[] evil = ava(GostOids.ATTR_O, utf8("Evil"));
        DirectoryNameSubtree.Dn twoEvil = parse(dn(rdnRaw(evil, evil)));
        DirectoryNameSubtree.Dn oneEvil = parse(dn(rdnRaw(evil)));
        assertTrue(
                DirectoryNameSubtree.isWithinSubtree(
                        twoEvil, twoEvil, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Два одинаковых AVA должны сопоставиться с двумя одинаковыми");
        assertFalse(
                DirectoryNameSubtree.isWithinSubtree(
                        oneEvil, twoEvil, DirectoryNameSubtree.MatchMode.EXCLUDED),
                "Один AVA имени не может закрыть два AVA запрета");
    }

    private static DirectoryNameSubtree.Dn parse(byte[] der) throws PkixException {
        return DirectoryNameSubtree.parse(der);
    }

    private static byte[] dn(byte[]... rdns) {
        return DerCodec.encodeSequence(rdns);
    }

    private static byte[] rdn(byte[]... avas) {
        return DerCodec.encodeSetOf(avas);
    }

    private static byte[] rdnRaw(byte[]... avas) {
        return DerCodec.encodeTlv(DerCodec.TAG_SET, DerCodec.concat(avas));
    }

    private static byte[] ava(String oid, byte[] value) {
        return DerCodec.encodeSequence(DerCodec.encodeOid(oid), value);
    }

    private static byte[] utf8(String value) {
        return DerCodec.encodeTlv(0x0C, value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] printable(String value) {
        return DerCodec.encodeTlv(0x13, value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] numeric(String value) {
        return DerCodec.encodeTlv(0x12, value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] t61(String value) {
        return DerCodec.encodeTlv(0x14, value.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static byte[] ia5(String value) {
        return DerCodec.encodeTlv(0x16, value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] rawValue(int tag, byte[] value) {
        return DerCodec.encodeTlv(tag, value);
    }

    private static byte[] avaRawOid(byte[] oidBytes, byte[] value) {
        return DerCodec.encodeSequence(DerCodec.encodeTlv(DerCodec.TAG_OID, oidBytes), value);
    }

    private static byte[] universal(String value) {
        return DerCodec.encodeTlv(0x1C, value.getBytes(UTF_32BE));
    }

    private static byte[] octet(String value) {
        return DerCodec.encodeTlv(0x04, value.getBytes(StandardCharsets.UTF_8));
    }
}
