package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Разбор supported_versions в ClientHello, ServerHello и HelloRetryRequest и строгий разбор
 * server_name. Тесты работают на собранных байтах: клиентской стороны ServerHello без
 * supported_versions у настоящего OpenSSL получить нельзя.
 */
@DisplayName("TlsMessageParser: supported_versions и server_name")
class TlsMessageParserVersionAndSniTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final int NAME_TYPE_HOST_NAME = 0x00;

    // =======================================================================
    // supported_versions в ClientHello
    // =======================================================================

    private static byte[] clientHelloWithVersions(byte[] versionsExtensionBody) throws Exception {
        return TlsMessageParserTest.buildClientHelloBody(
                0x0303,
                new byte[0],
                TlsMessageParserTest.csBytes(0xC103),
                new byte[] {0x00},
                TlsMessageParserTest.encodeExt(
                        TlsConstants.EXT_SUPPORTED_VERSIONS, versionsExtensionBody),
                TlsMessageParserTest.saExt(),
                TlsMessageParserTest.ksExt(TlsConstants.GRP_GC256A));
    }

    @ParameterizedTest(name = "тело supported_versions {0} -> decode_error")
    @ValueSource(
            strings = {
                "", // расширение без тела
                "00", // пустой список версий
                "01 03", // нечётная длина списка
                "02 03", // длина списка больше тела
                "04 03 04", // длина списка больше тела
                "02 03 04 03 04", // тело длиннее списка
            })
    @DisplayName("ClientHello: битый формат supported_versions -> decode_error")
    void testClientHelloMalformedVersions(String hex) throws Exception {
        byte[] body = clientHelloWithVersions(HexFormat.ofDelimiter(" ").parseHex(hex.strip()));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A),
                        "формат supported_versions нарушен");
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    @ParameterizedTest(name = "список версий {0} без TLS 1.3 -> protocol_version")
    @ValueSource(strings = {"02 03 03", "02 03 02", "04 03 03 03 02", "02 00 00"})
    @DisplayName("ClientHello: корректный список без 0x0304 -> protocol_version")
    void testClientHelloListWithoutTls13(String hex) throws Exception {
        byte[] body = clientHelloWithVersions(HexFormat.ofDelimiter(" ").parseHex(hex));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, e.getAlertCode());
    }

    @Test
    @DisplayName("ClientHello: TLS 1.3 среди нескольких версий принимается")
    void testClientHelloTls13AmongOthers() throws Exception {
        byte[] body =
                clientHelloWithVersions(
                        HexFormat.ofDelimiter(" ").parseHex("06 03 03 03 04 03 02"));
        assertNotNull(TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
    }

    // =======================================================================
    // supported_versions в ServerHello и HelloRetryRequest
    // =======================================================================

    private static byte[] serverHello(byte[] random, byte[]... extensions) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03);
        out.write(0x03);
        out.write(random, 0, random.length);
        out.write(0x00); // пустой legacy_session_id
        TlsEncoding.encodeUint16(out, 0xC103);
        out.write(0x00); // compression
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        for (byte[] e : extensions) {
            ext.write(e, 0, e.length);
        }
        TlsEncoding.encodeUint16(out, ext.size());
        out.write(ext.toByteArray(), 0, ext.size());
        return out.toByteArray();
    }

    private static byte[] ordinaryRandom() {
        return new byte[TlsConstants.RANDOM_LENGTH];
    }

    private static byte[] selectedVersionExt(int version) {
        byte[] data = new byte[] {(byte) (version >>> 8), (byte) version};
        return TlsMessageParserTest.encodeExt(TlsConstants.EXT_SUPPORTED_VERSIONS, data);
    }

    @Test
    @DisplayName("ServerHello: нет supported_versions -> protocol_version")
    void testServerHelloWithoutVersion() throws Exception {
        byte[] body = serverHello(ordinaryRandom());
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT));
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, e.getAlertCode());
    }

    @Test
    @DisplayName("HRR: нет supported_versions -> protocol_version, тем же путём, что и ServerHello")
    void testHelloRetryRequestWithoutVersion() throws Exception {
        byte[] body = serverHello(TlsMessageParser.HRR_RANDOM);
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT));
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, e.getAlertCode());
    }

    @ParameterizedTest(name = "тело supported_versions {0} байт -> decode_error")
    @ValueSource(ints = {0, 1, 3, 4})
    @DisplayName("ServerHello и HRR: selected_version не из двух байт -> decode_error")
    void testSelectedVersionWrongLength(int length) throws Exception {
        byte[] ext =
                TlsMessageParserTest.encodeExt(
                        TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[length]);
        for (byte[] random : List.of(ordinaryRandom(), TlsMessageParser.HRR_RANDOM)) {
            byte[] body = serverHello(random, ext);
            TlsException e =
                    assertThrows(
                            TlsException.class,
                            () ->
                                    TlsMessageParser.parseServerHello(
                                            body, SERVER_RESPONSE_TYPES_SENT));
            assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
        }
    }

    @ParameterizedTest(name = "версия 0x{0} -> illegal_parameter")
    @ValueSource(ints = {0x0303, 0x0302, 0x0301, 0x0305, 0x0000, 0x7F1C})
    @DisplayName("ServerHello и HRR: версия не 0x0304 -> illegal_parameter (RFC 8446 §4.2.1)")
    void testSelectedVersionNotTls13(int version) throws Exception {
        // Клиент предлагает только 0x0304, поэтому другая версия - не предложенная им, и это
        // же объясняет, почему отдельной проверки «версия HRR равна версии ServerHello» нет
        for (byte[] random : List.of(ordinaryRandom(), TlsMessageParser.HRR_RANDOM)) {
            byte[] body = serverHello(random, selectedVersionExt(version));
            TlsException e =
                    assertThrows(
                            TlsException.class,
                            () ->
                                    TlsMessageParser.parseServerHello(
                                            body, SERVER_RESPONSE_TYPES_SENT));
            assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, e.getAlertCode());
        }
    }

    @Test
    @DisplayName("ServerHello и HRR: версия 0x0304 принимается")
    void testSelectedVersionTls13Accepted() throws Exception {
        for (byte[] random : List.of(ordinaryRandom(), TlsMessageParser.HRR_RANDOM)) {
            byte[] body = serverHello(random, selectedVersionExt(TlsConstants.PROTOCOL_TLS_1_3));
            assertNotNull(TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT));
        }
    }

    // =======================================================================
    // server_name: структура
    // =======================================================================

    private static byte[] hostNameEntry(byte[] name) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        entry.write(NAME_TYPE_HOST_NAME);
        TlsEncoding.encodeUint16(entry, name.length);
        entry.write(name, 0, name.length);
        return entry.toByteArray();
    }

    /** Тело расширения server_name: длина списка и записи подряд. */
    private static byte[] serverNameBody(byte[]... entries) {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            list.write(entry, 0, entry.length);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(body, list.size());
        body.write(list.toByteArray(), 0, list.size());
        return body.toByteArray();
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static TlsException parseSni(byte[] body) {
        return assertThrows(
                TlsException.class,
                () -> TlsMessageParser.parseServerNameExtension(body, 0, body.length));
    }

    @Test
    @DisplayName("server_name: пустое расширение и расширение из одного байта -> decode_error")
    void testSniTruncated() {
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(new byte[0]).getAlertCode());
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(new byte[] {0x00}).getAlertCode());
    }

    @Test
    @DisplayName("server_name: пустой список -> decode_error")
    void testSniEmptyList() {
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(serverNameBody()).getAlertCode());
    }

    @Test
    @DisplayName("server_name: длина списка не совпадает с телом -> decode_error")
    void testSniListLengthMismatch() {
        byte[] body = serverNameBody(hostNameEntry(ascii("a.example")));
        byte[] longer = body.clone();
        longer[1]++; // список «длиннее» тела
        byte[] shorter = body.clone();
        shorter[1]--; // список «короче» тела
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(longer).getAlertCode());
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(shorter).getAlertCode());
    }

    @Test
    @DisplayName("server_name: имя длиннее записи -> decode_error")
    void testSniNameLongerThanEntry() {
        byte[] body = serverNameBody(hostNameEntry(ascii("a.example")));
        body[4]++; // старший байт длины имени остаётся, младший больше фактического
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseSni(body).getAlertCode());
    }

    @Test
    @DisplayName("server_name: нулевая длина имени -> decode_error")
    void testSniZeroNameLength() {
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                parseSni(serverNameBody(hostNameEntry(new byte[0]))).getAlertCode());
    }

    @Test
    @DisplayName("server_name: чужой name_type при согласованной длине -> decode_error")
    void testSniUnknownNameType() {
        byte[] entry = hostNameEntry(ascii("a.example"));
        entry[0] = 0x01;
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR, parseSni(serverNameBody(entry)).getAlertCode());
    }

    @Test
    @DisplayName("server_name: хвост после первой записи и вторая запись host_name -> decode_error")
    void testSniTrailingData() {
        byte[] first = hostNameEntry(ascii("a.example"));
        byte[] second = hostNameEntry(ascii("b.example"));
        // Список из двух host_name запрещён RFC 6066 §3; строже OpenSSL, который хвост молча
        // игнорирует: структуру, которую мы не разобрали, принимать нельзя
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                parseSni(serverNameBody(first, second)).getAlertCode());
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                parseSni(serverNameBody(first, new byte[] {0x7F})).getAlertCode());
    }

    // =======================================================================
    // server_name: допустимость имени
    // =======================================================================

    /** Имя из меток по 63, 63, 63 и {@code lastLabel} символов: 189 + 3 точки + lastLabel. */
    private static String longName(int lastLabel) {
        String label63 = "a".repeat(63);
        return String.join(".", label63, label63, label63, "b".repeat(lastLabel));
    }

    @Test
    @DisplayName("server_name: NUL, управляющие символы и не-ASCII -> unrecognized_name")
    void testSniUnsafeBytes() {
        byte[][] names = {
            {'a', 0x00, 'b', '.', 'e', 'x'},
            {'a', '\n', 'b', '.', 'e', 'x'},
            {'a', 0x1F, '.', 'e', 'x'},
            {'a', 0x7F, '.', 'e', 'x'},
            {(byte) 0xC3, (byte) 0xA9, '.', 'e', 'x'},
            {'a', (byte) 0xFF, '.', 'e', 'x'},
        };
        for (byte[] name : names) {
            TlsException e = parseSni(serverNameBody(hostNameEntry(name)));
            assertEquals(
                    TlsConstants.ALERT_UNRECOGNIZED_NAME,
                    e.getAlertCode(),
                    "имя с недопустимым байтом: " + HexFormat.of().formatHex(name));
        }
    }

    @Test
    @DisplayName("server_name: имя длиннее 253 символов -> unrecognized_name, 253 принимается")
    void testSniLengthBoundary() throws TlsException {
        String name253 = longName(61);
        assertEquals(TlsConstants.MAX_SERVER_NAME_LENGTH, name253.length());
        byte[] ok = serverNameBody(hostNameEntry(ascii(name253)));
        assertEquals(name253, TlsMessageParser.parseServerNameExtension(ok, 0, ok.length));

        // Одна конечная точка не входит в предел: 253 символа с точкой равны 253 без неё
        byte[] okWithDot = serverNameBody(hostNameEntry(ascii(name253 + ".")));
        assertEquals(
                name253, TlsMessageParser.parseServerNameExtension(okWithDot, 0, okWithDot.length));

        String name254 = longName(62);
        assertEquals(
                TlsConstants.ALERT_UNRECOGNIZED_NAME,
                parseSni(serverNameBody(hostNameEntry(ascii(name254)))).getAlertCode());
        assertEquals(
                TlsConstants.ALERT_UNRECOGNIZED_NAME,
                parseSni(serverNameBody(hostNameEntry(ascii(name254 + ".")))).getAlertCode());
    }

    @Test
    @DisplayName("server_name: пустые метки и имя из одних точек -> unrecognized_name")
    void testSniEmptyLabels() {
        for (String name : List.of("a..", ".a", "a..b", ".", "..", "...")) {
            assertEquals(
                    TlsConstants.ALERT_UNRECOGNIZED_NAME,
                    parseSni(serverNameBody(hostNameEntry(ascii(name)))).getAlertCode(),
                    "пустая метка: " + name);
        }
    }

    @Test
    @DisplayName("server_name: _, punycode, верхний регистр и одна конечная точка принимаются")
    void testSniAcceptedNames() throws TlsException {
        String[][] cases = {
            {"_dmarc.example.org", "_dmarc.example.org"},
            {"xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},
            {"Example.COM.", "example.com"},
            {"localhost", "localhost"},
        };
        for (String[] c : cases) {
            byte[] body = serverNameBody(hostNameEntry(ascii(c[0])));
            assertEquals(c[1], TlsMessageParser.parseServerNameExtension(body, 0, body.length));
        }
    }

    // =======================================================================
    // parseClientHelloSni: строгий разбор до PSK и выбора сертификата
    // =======================================================================

    private static byte[] clientHelloWithSni(int legacyVersion, byte[] serverNameBody)
            throws Exception {
        return TlsMessageParserTest.buildClientHelloBody(
                legacyVersion,
                new byte[0],
                TlsMessageParserTest.csBytes(0xC103),
                new byte[] {0x00},
                TlsMessageParserTest.svExt(),
                TlsMessageParserTest.saExt(),
                TlsMessageParserTest.encodeExt(TlsConstants.EXT_SERVER_NAME, serverNameBody),
                TlsMessageParserTest.ksExt(TlsConstants.GRP_GC256A));
    }

    @Test
    @DisplayName("NUL в SNI: лёгкий и полный разбор дают один и тот же alert unrecognized_name")
    void testBothPathsRejectNulInName() throws Exception {
        // Лёгкий разбор кормит PSK-привязку и выбор сертификата, полный идёт позже: если бы они
        // расходились, имя с NUL дошло бы до потребителей раньше отказа
        byte[] body =
                clientHelloWithSni(
                        0x0303, serverNameBody(hostNameEntry(new byte[] {'a', 0x00, '.', 'e'})));
        TlsException light =
                assertThrows(TlsException.class, () -> TlsMessageParser.parseClientHelloSni(body));
        TlsException full =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_UNRECOGNIZED_NAME, light.getAlertCode());
        assertEquals(light.getAlertCode(), full.getAlertCode());
    }

    @Test
    @DisplayName("Хвост после имени: лёгкий и полный разбор дают decode_error")
    void testBothPathsRejectTrailingData() throws Exception {
        byte[] first = hostNameEntry(ascii("a.example"));
        byte[] body = clientHelloWithSni(0x0303, serverNameBody(first, first));
        TlsException light =
                assertThrows(TlsException.class, () -> TlsMessageParser.parseClientHelloSni(body));
        TlsException full =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, light.getAlertCode());
        assertEquals(light.getAlertCode(), full.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHelloSni: неверный legacy_version по-прежнему даёт null")
    void testLightParseLegacyVersionStillNull() throws Exception {
        // Ответ на legacy_version даёт полный разбор (illegal_parameter): код alert не меняется
        byte[] body = clientHelloWithSni(0x0301, serverNameBody(hostNameEntry(ascii("a.example"))));
        assertNull(TlsMessageParser.parseClientHelloSni(body));
    }

    // =======================================================================
    // Проверка имени на клиенте: одна функция с сервером
    // =======================================================================

    @Test
    @DisplayName("ServerNameCheck: недопустимое имя -> IllegalArgumentException без имени в тексте")
    void testClientCheckRejects() {
        for (String name :
                List.of(
                        "a\u0000.example",
                        "a\n.example",
                        "é.example",
                        "a..example",
                        ".example",
                        ".",
                        longName(62))) {
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> ServerNameCheck.requireValidForSni(name),
                            "имя должно быть отвергнуто");
            assertFalse(
                    e.getMessage().contains("example"),
                    "имя приходит извне и в сообщение не входит: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("ServerNameCheck: null, пустое имя, IP-литералы и допустимые имена проходят")
    void testClientCheckAccepts() {
        for (String name :
                List.of(
                        "example.com",
                        "example.com.",
                        "_x.example",
                        "192.0.2.1",
                        "::1",
                        "fe80::1%eth0",
                        longName(61))) {
            assertDoesNotThrow(() -> ServerNameCheck.requireValidForSni(name), name);
        }
        assertDoesNotThrow(() -> ServerNameCheck.requireValidForSni(null));
        assertDoesNotThrow(() -> ServerNameCheck.requireValidForSni(""));
    }

    @Test
    @DisplayName(
            "TlsMessageBuilder.buildClientHello: недопустимое имя -> исключение, а не пропуск SNI")
    void testBuilderRejectsUnsafeName() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        byte[] point = TlsEncoding.encodePoint(kp.getPublic());
        TlsMessageBuilder builder =
                new TlsMessageBuilder(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        List.of(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        kp.getPrivate(),
                        Collections.emptyList(),
                        32);
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.buildClientHello(point, "evil\u0000.example"));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.buildClientHello(point, longName(62)));
        // IP-литерал по-прежнему не кладётся в SNI и ошибкой не является
        assertDoesNotThrow(() -> builder.buildClientHello(point, "192.0.2.1"));
    }
}
