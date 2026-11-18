package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("TlsMessageParser: парсинг handshake-сообщений")
class TlsMessageParserTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    /** Типы ответных расширений EE, на которые клиент якобы отправил запрос. */
    private static final Set<Integer> ALL_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    TlsConstants.EXT_MAX_FRAGMENT_LENGTH,
                    TlsConstants.EXT_SERVER_NAME);

    // =======================================================================
    // Тесты parseKeyShareEntry
    // =======================================================================
    //
    // Разбор key_share entry необходим для согласования ECDHE.
    // Без этого ни один handshake не может установить общий секрет.

    @Test
    @DisplayName("parseKeyShareEntry: корректный парсинг key_share")
    void testParseKeyShareEntry() throws TlsException {
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        byte[] point = TlsEncoding.encodePoint(kp.getPublic());

        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(entry, TlsConstants.GRP_GC256A);
        TlsEncoding.encodeUint16(entry, point.length);
        entry.write(point, 0, point.length);

        int[] actualGroup = new int[1];
        byte[] parsed =
                TlsMessageParser.parseKeyShareEntry(
                        entry.toByteArray(), 0, entry.size(), actualGroup);
        assertArrayEquals(point, parsed);
        assertEquals(TlsConstants.GRP_GC256A, actualGroup[0]);
    }

    @Test
    @DisplayName("parseKeyShareEntry: actualGroup захвачен, даже если отличается от ожидаемой")
    // Сервер в ServerHello выбирает группу (может отличаться от клиентской).
    // Парсер должен вернуть фактическую группу из сообщения, чтобы клиент
    // мог вычислить общий секрет на правильной кривой.
    void testParseKeyShareEntryCapturesActualGroup() throws TlsException {
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        byte[] point = TlsEncoding.encodePoint(kp.getPublic());

        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(entry, TlsConstants.GRP_GC256B);
        TlsEncoding.encodeUint16(entry, point.length);
        entry.write(point, 0, point.length);

        int[] actualGroup = new int[1];
        byte[] parsed =
                TlsMessageParser.parseKeyShareEntry(
                        entry.toByteArray(), 0, entry.size(), actualGroup);
        assertArrayEquals(point, parsed);
        assertEquals(TlsConstants.GRP_GC256B, actualGroup[0]);
    }

    // =======================================================================
    // Тесты parseServerHello
    // =======================================================================
    //
    // ServerHello — первое сообщение от сервера, содержащее key_share.
    // Если key_share отсутствует, handshake не может продолжаться (нет ECDHE).

    @Test
    @DisplayName("parseServerHello: нет key_share возвращает пустой ключ, группы 0")
    void testParseServerHelloMissingKeyShare() throws TlsException {
        // RFC 8446 §4.2.8 разрешает опускать key_share в HRR.
        //      parseServerHello не отличает HRR от обычного SH на этапе
        //      парсинга — он возвращает пустой ecdhePublicKeyRaw и group=0,
        //      а caller (receiveServerHello) решает, HRR это или нет.
        byte[] body = new byte[2 + 32 + 1 + 2 + 1 + 2 + 6];
        int pos = 0;
        body[pos++] = 0x03;
        body[pos++] = 0x03;
        pos += 32;
        body[pos++] = 0x00;
        body[pos++] = (byte) 0xC1;
        body[pos++] = 0x03;
        body[pos++] = 0x00;
        // единственное расширение - supported_versions с TLS 1.3 (без него разбор отвергает
        // ServerHello): длина блока 6 = тип(2) + длина(2) + selected_version(2)
        body[pos++] = 0x00;
        body[pos++] = 0x06;
        body[pos++] = 0x00;
        body[pos++] = 0x2B;
        body[pos++] = 0x00;
        body[pos++] = 0x02;
        body[pos++] = 0x03;
        body[pos++] = 0x04;

        TlsMessageParser.ParsedServerHello parsed =
                TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT);
        assertEquals(
                0,
                parsed.ecdhePublicKeyRaw.length,
                "Без key_share ecdhePublicKeyRaw должен быть пустым");
        assertEquals(0, parsed.actualGroup, "Без key_share actualGroup должен быть 0");
    }

    @Test
    @DisplayName("parseServerHello: actualGroup захвачен из key_share")
    // Парсер ServerHello должен извлечь группу из key_share,
    // т.к. клиент использует её для ECDHE. Группа в key_share
    // может отличаться от ожидаемой — сервер волен выбирать.
    void testParseServerHelloCapturesActualGroup() throws TlsException {
        java.io.ByteArrayOutputStream ks = new java.io.ByteArrayOutputStream();
        TlsEncoding.encodeUint16(ks, TlsConstants.GRP_GC256B);
        TlsEncoding.encodeUint16(ks, 64);
        byte[] dummyPoint = new byte[64];
        ks.write(dummyPoint, 0, dummyPoint.length);

        java.io.ByteArrayOutputStream ext = new java.io.ByteArrayOutputStream();
        // supported_versions обязателен в ServerHello (RFC 8446 §4.2.1)
        TlsEncoding.encodeUint16(ext, TlsConstants.EXT_SUPPORTED_VERSIONS);
        TlsEncoding.encodeUint16(ext, 2);
        TlsEncoding.encodeUint16(ext, TlsConstants.PROTOCOL_TLS_1_3);
        TlsEncoding.encodeUint16(ext, TlsConstants.EXT_KEY_SHARE);
        TlsEncoding.encodeUint16(ext, ks.size());
        ext.write(ks.toByteArray(), 0, ks.size());

        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        body.write(0x03);
        body.write(0x03);
        byte[] random = new byte[32];
        body.write(random, 0, 32);
        body.write(0x00);
        body.write(0xC1);
        body.write(0x05);
        body.write(0x00);
        TlsEncoding.encodeUint16(body, ext.size());
        body.write(ext.toByteArray(), 0, ext.size());

        TlsMessageParser.ParsedServerHello result =
                TlsMessageParser.parseServerHello(body.toByteArray(), SERVER_RESPONSE_TYPES_SENT);
        assertEquals(TlsConstants.GRP_GC256B, result.actualGroup);
        assertArrayEquals(dummyPoint, result.ecdhePublicKeyRaw);
    }

    @Test
    @DisplayName("parseServerHello: урезанные данные бросают TlsException(ALERT_DECODE_ERROR)")
    // Парсер должен устойчиво обрабатывать malformed-данные.
    // Урезанное сообщение не может быть корректно разобрано — decode_error.
    // RFC 8446 требует ALERT_DECODE_ERROR при неверном формате.
    void testParseServerHelloTruncated() {
        byte[] body = new byte[2 + 32];
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseServerHello(body, SERVER_RESPONSE_TYPES_SENT));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    // =======================================================================
    // Тесты parseClientHello
    // =======================================================================
    //
    // ClientHello — первое сообщение handshake, открывающее соединение.
    // Парсер должен валидировать обязательные поля и расширения
    // (legacy_version, compression, supported_versions, key_share, signature_algorithms).

    @Test
    @DisplayName("parseClientHello: валидный ClientHello")
    // Базовый happy path — проверка, что корректный ClientHello
    // с обязательными расширениями успешно разбирается.
    void testParseClientHelloValid() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        TlsMessageParser.ParsedKeyShare result =
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A);
        assertEquals(TlsConstants.GRP_GC256A, result.actualGroup, "Группа из key_share");
        assertTrue(result.keySharePresent, "Расширение key_share должно быть замечено");
        assertNotNull(result.ecdhePublicKeyRaw, "Публичный ключ ECDHE выделен");
        assertEquals(1, result.keyShareEntries.size(), "В ClientHello одна запись key_share");
    }

    @Test
    @DisplayName("parseClientHello: неверный legacy_version")
    // legacy_version в TLS 1.3 ДОЛЖЕН быть 0x0303 (TLS 1.2).
    // Любое другое значение — нарушение спецификации -> illegal_parameter.
    void testParseClientHelloWrongVersion() {
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseClientHello(
                                        new byte[] {0x03, 0x02}, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: неверная компрессия")
    // В TLS 1.3 compression_methods ДОЛЖЕН быть {0x00} (null compression).
    // Любой другой метод — нарушение RFC 8446 -> illegal_parameter.
    void testParseClientHelloWrongCompression() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x01},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: обрезанное тело")
    // Урезанные данные не могут быть разобраны — decode_error.
    // Защита от malformed-сообщений обязательна для безопасности.
    void testParseClientHelloTruncated() {
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseClientHello(
                                        new byte[] {0x03, 0x03}, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: нет supported_versions -> protocol_version")
    // Клиент без supported_versions предлагает TLS 1.2 или ниже (RFC 8446 §4.2.1), а сервер,
    // умеющий только TLS 1.3, отвечает protocol_version (§6.2), а не missing_extension.
    void testParseClientHelloMissingSv() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: нет signature_algorithms")
    // signature_algorithms — обязательное расширение (RFC 8446, sec 4.2.3).
    // Сервер не может верифицировать сертификаты без знания алгоритмов подписи клиента.
    void testParseClientHelloMissingSa() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_MISSING_EXTENSION, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: нет key_share - парсер сообщает об отсутствии, решает движок")
    // key_share обязателен для CH1 (missing_extension) и ровно одна запись для CH2 после HRR
    // (illegal_parameter): оба решения принимает движок, парсер лишь описывает ClientHello.
    void testParseClientHelloMissingKs() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303, new byte[0], csBytes(0xC103), new byte[] {0x00}, svExt(), saExt());

        TlsMessageParser.ParsedKeyShare parsed =
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A);

        assertFalse(parsed.keySharePresent, "расширения key_share нет");
        assertTrue(parsed.keyShareEntries.isEmpty());
        assertNull(parsed.ecdhePublicKeyRaw);
    }

    @Test
    @DisplayName("parseClientHello: пустой список key_share - расширение есть, записей нет")
    void testParseClientHelloEmptyKeyShareList() throws Exception {
        byte[] emptyKs = encodeExt(TlsConstants.EXT_KEY_SHARE, new byte[] {0x00, 0x00});
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        emptyKs);

        TlsMessageParser.ParsedKeyShare parsed =
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A);

        assertTrue(parsed.keySharePresent);
        assertTrue(parsed.keyShareEntries.isEmpty());
    }

    @Test
    @DisplayName("parseClientHello: все записи key_share сохраняются в порядке следования")
    void testParseClientHelloKeepsAllKeyShareEntries() throws Exception {
        ByteArrayOutputStream entries = new ByteArrayOutputStream();
        for (int group : new int[] {0xAAAA, TlsConstants.GRP_GC256B}) {
            byte[] point = new byte[64];
            TlsEncoding.encodeUint16(entries, group);
            TlsEncoding.encodeUint16(entries, point.length);
            entries.write(point);
        }
        ByteArrayOutputStream ks = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(ks, entries.size());
        ks.write(entries.toByteArray());
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        encodeExt(TlsConstants.EXT_KEY_SHARE, ks.toByteArray()));

        TlsMessageParser.ParsedKeyShare parsed =
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256B);

        assertEquals(2, parsed.keyShareEntries.size());
        assertEquals(0xAAAA, parsed.keyShareEntries.get(0).group());
        assertEquals(TlsConstants.GRP_GC256B, parsed.keyShareEntries.get(1).group());
        assertFalse(parsed.supportedGroupsDeclared, "supported_groups в ClientHello не было");
    }

    private static byte[] keyShareList(int[] groups, int lastEntryKeyLenOverride) throws Exception {
        ByteArrayOutputStream entries = new ByteArrayOutputStream();
        for (int i = 0; i < groups.length; i++) {
            byte[] point = new byte[64];
            TlsEncoding.encodeUint16(entries, groups[i]);
            boolean last = i == groups.length - 1;
            TlsEncoding.encodeUint16(
                    entries,
                    last && lastEntryKeyLenOverride >= 0 ? lastEntryKeyLenOverride : point.length);
            entries.write(point);
        }
        ByteArrayOutputStream ks = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(ks, entries.size());
        ks.write(entries.toByteArray());
        return encodeExt(TlsConstants.EXT_KEY_SHARE, ks.toByteArray());
    }

    @Test
    @DisplayName(
            "parseClientHello: ожидаемая группа ПЕРВОЙ, хвостовая запись после неё сохраняется")
    void testParseClientHelloExpectedGroupFirstKeepsTrailingEntry() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        keyShareList(
                                new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC256A}, -1));

        TlsMessageParser.ParsedKeyShare parsed =
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256B);

        assertEquals(2, parsed.keyShareEntries.size(), "обе записи должны быть собраны");
        assertEquals(TlsConstants.GRP_GC256B, parsed.keyShareEntries.get(0).group());
        assertEquals(TlsConstants.GRP_GC256A, parsed.keyShareEntries.get(1).group());
        assertEquals(TlsConstants.GRP_GC256B, parsed.actualGroup, "прежняя семантика поля");
    }

    @Test
    @DisplayName("parseClientHello: хвостовая запись key_share с битой длиной -> decode_error")
    void testParseClientHelloBrokenTrailingKeyShareEntry() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        keyShareList(
                                new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC256A},
                                0xFFFF));

        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256B));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHello: supported_versions без 0x0304 -> protocol_version")
    // Корректный список без 0x0304: клиент не предлагает TLS 1.3, соединение невозможно
    // (RFC 8446 §6.2).
    void testParseClientHelloSvWrongVersion() throws Exception {
        byte[] svExt =
                encodeExt(TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[] {0x02, 0x03, 0x02});
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt,
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, e.getAlertCode());
    }

    @Test
    @DisplayName("ClientHello key_share: wire format с client_shares<0..2^16-1>")
    // client_shares — список <0..2^16-1>, где каждый entry содержит
    // group + key_exchange. Проверяем точную структуру wire format,
    // чтобы гарантировать совместимость с другими реализациями TLS 1.3.
    void testClientHelloKeyShareWireFormat() throws Exception {
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
        byte[] ch = builder.buildClientHello(point);

        int pos = 2 + 32 + 1;
        int csLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
        pos += 2 + csLen;
        int compLen = ch[pos] & 0xFF;
        pos += 1 + compLen;
        int extLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
        pos += 2;
        int extEnd = pos + extLen;

        boolean found = false;
        while (pos < extEnd) {
            int extType = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
            int extDataLen = ((ch[pos + 2] & 0xFF) << 8) | (ch[pos + 3] & 0xFF);
            pos += 4;
            if (extType == TlsConstants.EXT_KEY_SHARE) {
                found = true;
                assertTrue(extDataLen >= 4, "key_share extDataLen слишком мал");
                int listLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
                assertEquals(extDataLen - 2, listLen, "длина списка client_shares");
                int group = ((ch[pos + 2] & 0xFF) << 8) | (ch[pos + 3] & 0xFF);
                assertEquals(TlsConstants.GRP_GC256A, group, "группа key_share");
                int keLen = ((ch[pos + 4] & 0xFF) << 8) | (ch[pos + 5] & 0xFF);
                assertEquals(point.length, keLen, "длина key_exchange");
                assertArrayEquals(
                        Arrays.copyOfRange(ch, pos + 6, pos + 6 + keLen),
                        point,
                        "данные key_exchange");
            }
            pos += extDataLen;
        }
        assertTrue(found, "расширение key_share не найдено");
    }

    @Test
    @DisplayName("ClientHelloWithPsk key_share: wire format с client_shares<0..2^16-1>")
    // PSK-рукопожатие добавляет расширение pre_shared_key,
    // но key_share остаётся обязательным. Проверяем, что key_share
    // в PSK ClientHello имеет тот же wire format, что и в обычном.
    void testClientHelloWithPskKeyShareWireFormat() throws Exception {
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
        byte[] ch = builder.buildClientHelloWithPsk(point, new byte[8], 42L);

        int pos = 2 + 32 + 1;
        int csLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
        pos += 2 + csLen;
        int compLen = ch[pos] & 0xFF;
        pos += 1 + compLen;
        int extLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
        pos += 2;
        int extEnd = pos + extLen;

        boolean found = false;
        while (pos < extEnd) {
            int extType = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
            int extDataLen = ((ch[pos + 2] & 0xFF) << 8) | (ch[pos + 3] & 0xFF);
            pos += 4;
            if (extType == TlsConstants.EXT_KEY_SHARE) {
                found = true;
                assertTrue(extDataLen >= 4);
                int listLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
                assertEquals(extDataLen - 2, listLen);
                int group = ((ch[pos + 2] & 0xFF) << 8) | (ch[pos + 3] & 0xFF);
                assertEquals(TlsConstants.GRP_GC256A, group);
                int keLen = ((ch[pos + 4] & 0xFF) << 8) | (ch[pos + 5] & 0xFF);
                assertEquals(point.length, keLen);
                assertArrayEquals(Arrays.copyOfRange(ch, pos + 6, pos + 6 + keLen), point);
                break;
            }
            pos += extDataLen;
        }
        assertTrue(found, "расширение key_share не найдено в PSK ClientHello");
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    static byte[] buildClientHelloBody(
            int legacyVersion,
            byte[] sessionId,
            byte[] cipherSuites,
            byte[] compression,
            byte[]... extensions)
            throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((legacyVersion >>> 8) & 0xFF);
        out.write(legacyVersion & 0xFF);
        out.write(
                new byte[TlsConstants.STREEBOG_256_HASH_LEN],
                0,
                TlsConstants.STREEBOG_256_HASH_LEN);
        out.write(sessionId.length);
        out.write(sessionId, 0, sessionId.length);
        TlsEncoding.encodeUint16(out, cipherSuites.length);
        out.write(cipherSuites, 0, cipherSuites.length);
        out.write(compression.length);
        out.write(compression, 0, compression.length);
        ByteArrayOutputStream extOut = new ByteArrayOutputStream();
        for (byte[] ext : extensions) extOut.write(ext, 0, ext.length);
        TlsEncoding.encodeUint16(out, extOut.size());
        out.write(extOut.toByteArray(), 0, extOut.size());
        return out.toByteArray();
    }

    static byte[] svExt() throws Exception {
        return encodeExt(TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[] {0x02, 0x03, 0x04});
    }

    static byte[] saExt() throws Exception {
        return encodeExt(
                TlsConstants.EXT_SIGNATURE_ALGORITHMS,
                new byte[] {0x00, 0x04, 0x07, 0x09, 0x07, 0x0A});
    }

    static byte[] ksExt(int group) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        byte[] point = TlsEncoding.encodePoint(kp.getPublic());
        ByteArrayOutputStream ksEntry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(ksEntry, group);
        TlsEncoding.encodeUint16(ksEntry, point.length);
        ksEntry.write(point);
        ByteArrayOutputStream ks = new ByteArrayOutputStream();
        byte[] entry = ksEntry.toByteArray();
        TlsEncoding.encodeUint16(ks, entry.length); // client_shares<0..2^16-1>
        ks.write(entry, 0, entry.length);
        return encodeExt(TlsConstants.EXT_KEY_SHARE, ks.toByteArray());
    }

    static byte[] csBytes(int... ids) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(out, ids.length * 2);
        for (int id : ids) TlsEncoding.encodeUint16(out, id);
        return out.toByteArray();
    }

    static byte[] encodeExt(int type, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeExtension(out, type, data);
        return out.toByteArray();
    }

    // =======================================================================
    // Тесты parseNewSessionTicket
    // =======================================================================
    //
    // NewSessionTicket используется для resumption (PSK).
    // Минимальная длина тела — 8 байт (RFC 8446, sec 4.6.1).
    // Меньше — decode_error.

    @Test
    @DisplayName(
            "parseNewSessionTicket: body короче 8 байт бросает TlsException(ALERT_DECODE_ERROR)")
    void testParseNewSessionTicketTruncatedThrows() {
        byte[] malformed = new byte[6];
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseNewSessionTicket(malformed));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("parseNewSessionTicket: пустой ticket бросает TlsException(ALERT_DECODE_ERROR)")
    void testParseNewSessionTicketEmptyTicketThrows() {
        // RFC 8446 §4.6.1: opaque ticket<1..2^16-1>, пустой тикет недопустим
        byte[] body = TlsMessageBuilder.buildNewSessionTicket(7200, 1, new byte[8], new byte[0]);

        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parseNewSessionTicket(body));

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("parseNewSessionTicket: ticket из одного байта принимается (нижняя граница)")
    void testParseNewSessionTicketMinimalTicketAccepted() throws Exception {
        byte[] body =
                TlsMessageBuilder.buildNewSessionTicket(7200, 1, new byte[8], new byte[] {0x42});

        TlsMessageParser.ParsedNewSessionTicket parsed =
                TlsMessageParser.parseNewSessionTicket(body);

        assertEquals(1, parsed.ticket.length);
    }

    // =======================================================================
    // Тесты SNI (server_name)
    // =======================================================================
    //
    // SNI позволяет клиенту указать, к какому хосту он подключается.
    // Сервер использует это для выбора сертификата. RFC 6066.
    // Важно: host_name нормализуется (удаляется точка в конце, lowercasing).

    @Test
    @DisplayName("buildClientHello + разбор ClientHello: обратимость SNI")
    // Проверяем полный цикл: построение ClientHello с SNI -> парсинг ->
    // нормализация имени. Гарантирует, что SNI проходит roundtrip без потерь.
    void testSniRoundtrip() throws Exception {
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
        byte[] chBody = builder.buildClientHello(point, "Example.COM.");
        TlsMessageParser.ParsedKeyShare parsed =
                TlsMessageParser.parseClientHello(chBody, TlsConstants.GRP_GC256A);
        assertNotNull(parsed.serverName, "parsedServerName не должен быть null");
        assertEquals("example.com", parsed.serverName, "SNI должен быть нормализован");
    }

    @Test
    @DisplayName("parseClientHello: SNI с неверным name_type -> decode_error")
    // Структура записи с неизвестным name_type не определена: разборщик не знает, где она
    // кончается, поэтому запись отвергается целиком (RFC 6066 §3), а не пропускается.
    // Запись минимальной допустимой длины (type + длина имени + один байт имени) со списком,
    // согласованным с содержимым: тест доходит до проверки name_type, а не падает раньше на
    // несовпадении длин или слишком короткой записи.
    void testParseServerNameWrongType() throws Exception {
        ByteArrayOutputStream sn = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(sn, 4);
        sn.write(0x01); // name_type != host_name(0)
        TlsEncoding.encodeUint16(sn, 1);
        sn.write('a');
        byte[] sniExt = encodeExt(TlsConstants.EXT_SERVER_NAME, sn.toByteArray());

        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        sniExt,
                        ksExt(TlsConstants.GRP_GC256A));
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    @Test
    @DisplayName("parseServerNameExtension: корректный host_name")
    // Базовый happy path для извлечения host_name из ServerNameList.
    // Если этот тест падает, SNI не работает вообще.
    void testParseServerNameExtensionValid() throws Exception {
        byte[] nameBytes = "example.com".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(buf, 3 + nameBytes.length); // ServerNameList length
        buf.write(0x00); // host_name
        TlsEncoding.encodeUint16(buf, nameBytes.length);
        buf.write(nameBytes);
        byte[] data = buf.toByteArray();

        String result = TlsMessageParser.parseServerNameExtension(data, 0, data.length);
        assertEquals("example.com", result);
    }

    @Test
    @DisplayName("parseServerNameExtension: хост с точкой на конце")
    // DNS-имена могут содержать точку на конце (FQDN).
    // Нормализация удаляет её для единообразия — сервер должен
    // сравнивать имена без учёта конечной точки.
    void testParseServerNameExtensionTrailingDot() throws Exception {
        byte[] nameBytes = "example.com.".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(buf, 3 + nameBytes.length);
        buf.write(0x00);
        TlsEncoding.encodeUint16(buf, nameBytes.length);
        buf.write(nameBytes);
        byte[] data = buf.toByteArray();

        String result = TlsMessageParser.parseServerNameExtension(data, 0, data.length);
        assertEquals("example.com", result, "точка на конце должна быть удалена");
    }

    @Test
    @DisplayName("parseServerNameExtension: пустой host_name -> decode_error")
    // HostName<1..2^16-1> (RFC 6066 §3): пустое имя нарушает формат.
    void testParseServerNameExtensionEmpty() throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(buf, 3); // length: type(1) + empty_len(2) = 3
        buf.write(0x00); // host_name
        TlsEncoding.encodeUint16(buf, 0); // пустое имя
        byte[] data = buf.toByteArray();

        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseServerNameExtension(data, 0, data.length));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    @Test
    @DisplayName("parseServerNameExtension: запись короче заголовка -> decode_error")
    // Минимальная запись ServerName: type(1) + length(2) + один байт имени. Меньшее - битая
    // структура; молчаливое игнорирование принимало бы ClientHello с мусором в расширении.
    void testParseServerNameExtensionTooShort() {
        byte[] data = new byte[] {0x00, 0x01, 0x00};
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseServerNameExtension(data, 0, data.length));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }

    // =======================================================================
    // Тесты parseClientHelloSni (lightweight SNI extractor)
    // =======================================================================
    //
    // parseClientHelloSni — легковесный аналог полного парсинга.
    // Эти тесты проверяют эквивалентность с parseClientHello().serverName
    // на всём диапазоне валидных/невалидных ClientHello.
    // чтобы гарантировать, что SNI certificate selection (вызывающий
    // parseClientHelloSni до engine.receive()) не расходится с полным
    // парсингом внутри receiveClientHello().

    @Test
    @DisplayName("parseClientHelloSni: roundtrip эквивалентен полному парсингу")
    void testParseClientHelloSniEquivalentToFullParse() throws Exception {
        String hostname = "my-server.example.com";
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A),
                        sniExt(hostname));

        String light = TlsMessageParser.parseClientHelloSni(body);
        String full = TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A).serverName;

        assertEquals(full, light, "parseClientHelloSni должен совпадать с полным парсером");
    }

    @Test
    @DisplayName("parseClientHelloSni: без SNI -> null")
    void testParseClientHelloSniNoSni() throws Exception {
        // ClientHello без server_name расширения — selector не должен вызваться
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));

        assertNull(TlsMessageParser.parseClientHelloSni(body));
    }

    @Test
    @DisplayName("parseClientHelloSni: неверный NameType ≠ host_name(0) -> decode_error")
    void testParseClientHelloSniWrongNameType() throws Exception {
        // NameType=1: достоверно разобрать запись неизвестного типа нельзя, она отвергается
        // целиком.
        // Запись минимальной длины (4 байта), чтобы проверялся именно name_type
        ByteArrayOutputStream sn = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(sn, 4);
        sn.write(0x01); // name_type != host_name(0)
        TlsEncoding.encodeUint16(sn, 1);
        sn.write('a');
        byte[] sniExt = encodeExt(TlsConstants.EXT_SERVER_NAME, sn.toByteArray());

        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        sniExt,
                        ksExt(TlsConstants.GRP_GC256A));

        assertSniAlert(TlsConstants.ALERT_DECODE_ERROR, body);
    }

    @Test
    @DisplayName("parseClientHelloSni: пустой ServerNameList -> decode_error")
    void testParseClientHelloSniEmptyList() throws Exception {
        // ServerNameList общей длины 0 нарушает формат ServerNameList<1..2^16-1>
        byte[] sniExt = encodeExt(TlsConstants.EXT_SERVER_NAME, new byte[] {0x00, 0x00});
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        sniExt,
                        ksExt(TlsConstants.GRP_GC256A));

        assertSniAlert(TlsConstants.ALERT_DECODE_ERROR, body);
    }

    @Test
    @DisplayName("parseClientHelloSni: malformed extensions (длина не сходится) -> decode_error")
    void testParseClientHelloSniMalformedExtensions() throws Exception {
        // Обрезаем тело — extensions list не сойдётся по длине
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        byte[] truncated = new byte[body.length - 3]; // обрезаем часть extensions

        System.arraycopy(body, 0, truncated, 0, truncated.length);
        // После обрезания длина extensions в заголовке не совпадает с телом
        assertSniAlert(TlsConstants.ALERT_DECODE_ERROR, truncated);
    }

    @Test
    @DisplayName("parseClientHelloSni: truncated тело -> decode_error, а не исключение Java")
    void testParseClientHelloSniTruncatedBody() {
        // Тело ещё не проверено полностью: ошибка границ даёт alert, а не null и не
        // ArrayIndexOutOfBoundsException
        byte[] tooShort = new byte[] {0x03, 0x03, 0x01, 0x02, 0x03};
        assertSniAlert(TlsConstants.ALERT_DECODE_ERROR, tooShort);
    }

    private static void assertSniAlert(byte expectedAlert, byte[] clientHelloBody) {
        TlsException e =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHelloSni(clientHelloBody));
        assertEquals(expectedAlert, e.getAlertCode());
    }

    @Test
    @DisplayName("parseClientHelloSni: FQDN с точкой нормализуется")
    void testParseClientHelloSniTrailingDot() throws Exception {
        // Точка на конце FQDN должна удаляться нормализацией
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A),
                        sniExt("example.com."));

        assertEquals("example.com", TlsMessageParser.parseClientHelloSni(body));
    }

    // =======================================================================
    // Тесты error message context
    // =======================================================================
    //
    // Сообщения об ошибках должны указывать, какой именно тип сообщения
    // не удалось разобрать. Это упрощает отладку и логирование.
    // Ошибка в Certificate не должна ссылаться на ClientHello.

    @Test
    @DisplayName("parseCertificate: error message содержит Certificate, а не ClientHello")
    void testParseCertificateErrorMessageContext() {
        byte[] malformed = new byte[2];
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseCertificate(
                                        malformed, Set.of(TlsConstants.EXT_STATUS_REQUEST)));
        assertTrue(
                ex.getMessage().contains("Certificate"),
                "сообщение об ошибке должно содержать Certificate, получено: " + ex.getMessage());
        assertFalse(
                ex.getMessage().contains("ClientHello"),
                "сообщение об ошибке не должно содержать ClientHello, получено: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName(
            "parseCertificate: malformed SAN iPAddress -> TlsException(ALERT_DECODE_ERROR), не краш")
    // Страховка границы pkix->tls13: GostExtensionParser бросает IllegalArgumentException на
    // битую iPAddress-запись (fail-closed), а parseCertificate обязан перехватить её и
    // превратить в ALERT_DECODE_ERROR — чистое закрытие по протоколу вместо необработанного
    // краша в живом handshake. Тест держит эту границу на случай рефакторинга try/catch.
    void testParseCertificateMalformedSanIp() throws Exception {
        byte[] certDer = PkixCertTestHelper.malformedSanIpCertDer();

        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, 0); // расширения CertificateEntry отсутствуют

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // request context
        byte[] entryBytes = entry.toByteArray();
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseCertificate(
                                        body.toByteArray(),
                                        Set.of(TlsConstants.EXT_STATUS_REQUEST)));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    // =======================================================================
    // Тесты ALPN (RFC 7301)
    // =======================================================================
    //
    // ALPN позволяет согласовать протокол прикладного уровня (HTTP/2,
    // HTTP/1.1 и т.д.) на уровне TLS. Сервер выбирает первый протокол из
    // своего списка, который есть в списке клиента (RFC 7301, sec 3.2).
    // Это critical extension — неправильное согласование ведёт к разрыву.

    @Test
    @DisplayName("selectAlpn: выбирает первый общий протокол из списка сервера")
    // Сервер выбирает первый по своему приоритету протокол, который
    // есть у клиента. Здесь http/1.1 в списке сервера раньше, чем h2.
    void testSelectAlpnMatches() {
        List<String> server = List.of("http/1.1", "h2");
        List<String> client = List.of("h2", "http/1.1");
        assertEquals("http/1.1", TlsMessageParser.selectAlpn(server, client));
    }

    @Test
    @DisplayName("selectAlpn: нет пересечения -> null")
    // Если у сервера и клиента нет общих протоколов, handshake
    // не может продолжаться. Возврат null — сигнал для engine выбросить
    // ALERT_NO_APPLICATION_PROTOCOL (RFC 7301, sec 3.2).
    void testSelectAlpnNoMatch() {
        assertNull(TlsMessageParser.selectAlpn(List.of("h2"), List.of("http/1.1")));
    }

    @Test
    @DisplayName("selectAlpn: null аргумент -> null")
    // Защита от NPE. Если одна сторона не указала протоколы,
    // ALPN не должен применяться — возвращаем null без выброса.
    void testSelectAlpnNullArgs() {
        assertNull(TlsMessageParser.selectAlpn(null, List.of("h2")));
        assertNull(TlsMessageParser.selectAlpn(List.of("h2"), null));
    }

    @Test
    @DisplayName("parseEncryptedExtensions: находит ALPN в EE")
    // EncryptedExtensions содержит выбранный сервером ALPN-протокол.
    // Клиент должен извлечь его, чтобы узнать, какой протокол согласован.
    void testParseEncryptedExtensionsAlpnValid() throws Exception {
        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        // RFC 7301: ProtocolNameList = listLength(2) || nameLen(1) || name(N)
        byte[] alpnBody = new byte[] {0x00, 0x03, 0x02, 0x68, 0x32}; // listLen=3, nameLen=2, "h2"
        TlsEncoding.encodeExtension(
                extBody, TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnBody);
        byte[] extBytes = extBody.toByteArray();
        byte[] eeBody = new byte[2 + extBytes.length];
        eeBody[0] = (byte) (extBytes.length >>> 8);
        eeBody[1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, eeBody, 2, extBytes.length);
        assertEquals(
                "h2",
                TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT).alpn);
    }

    @Test
    @DisplayName("parseEncryptedExtensions: пустые EE -> alpn=null, maxFragLen=0")
    // Если сервер не выбрал ALPN (не поддерживает или клиент не предложил),
    // EncryptedExtensions не содержит ALPN-расширения. Парсер возвращает null.
    void testParseEncryptedExtensionsEmpty() throws Exception {
        TlsMessageParser.ParsedEncryptedExtensions parsed =
                TlsMessageParser.parseEncryptedExtensions(
                        new byte[] {0x00, 0x00}, ALL_RESPONSE_TYPES_SENT);
        assertNull(parsed.alpn);
        assertEquals(0, parsed.maxFragLen);
    }

    @Test
    @DisplayName("parseEncryptedExtensions: длинный протокол (>1 байт)")
    // Протоколы могут быть многосимвольными ("http/1.1" — 8 байт).
    // Парсер должен корректно читать length-prefixed строки любой длины.
    void testParseEncryptedExtensionsAlpnLonger() throws Exception {
        byte[] name = "http/1.1".getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream extBody = new ByteArrayOutputStream();
        // RFC 7301: ProtocolNameList = listLength(2) || nameLen(1) || name(N)
        byte[] alpnBody = new byte[3 + name.length];
        alpnBody[0] = 0;
        alpnBody[1] = (byte) (1 + name.length);
        alpnBody[2] = (byte) name.length;
        System.arraycopy(name, 0, alpnBody, 3, name.length);
        TlsEncoding.encodeExtension(
                extBody, TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnBody);
        byte[] extBytes = extBody.toByteArray();
        byte[] eeBody = new byte[2 + extBytes.length];
        eeBody[0] = (byte) (extBytes.length >>> 8);
        eeBody[1] = (byte) extBytes.length;
        System.arraycopy(extBytes, 0, eeBody, 2, extBytes.length);
        assertEquals(
                "http/1.1",
                TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT).alpn);
    }

    @Test
    @DisplayName("parseClientHelloAlpn: находит ALPN в ClientHello")
    // Клиент передаёт список поддерживаемых протоколов в ClientHello.
    // Сервер использует этот список для выбора протокола.
    void testParseClientHelloAlpnValid() throws Exception {
        byte[] alpnList = encodeAlpnExt(List.of("h2", "http/1.1"));
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        alpnList,
                        ksExt(TlsConstants.GRP_GC256A));
        List<String> protocols = TlsMessageParser.parseClientHelloAlpn(body);
        assertNotNull(protocols);
        assertEquals(2, protocols.size());
        assertEquals("h2", protocols.get(0));
        assertEquals("http/1.1", protocols.get(1));
    }

    @Test
    @DisplayName("parseClientHelloAlpn: без ALPN -> null")
    // Клиент может не поддерживать ALPN. Парсер возвращает null,
    // и handshake продолжается без согласования протокола прикладного уровня.
    void testParseClientHelloAlpnMissing() throws Exception {
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));
        assertNull(TlsMessageParser.parseClientHelloAlpn(body));
    }

    @Test
    @DisplayName("parseClientHelloAlpn: пустой список -> пустой список")
    // RFC 7301 разрешает пустой ProtocolNameList (хотя это не имеет смысла).
    // Парсер не должен падать — возвращает пустой список вместо null,
    // чтобы сервер мог отличить "не указан" от "указан, но пуст".
    void testParseClientHelloAlpnEmptyList() throws Exception {
        byte[] extData = new byte[] {0x00, 0x00}; // list_len = 0
        byte[] alpnExt =
                encodeExt(TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, extData);
        byte[] body =
                buildClientHelloBody(
                        0x0303,
                        new byte[0],
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        alpnExt,
                        ksExt(TlsConstants.GRP_GC256A));
        List<String> protocols = TlsMessageParser.parseClientHelloAlpn(body);
        assertNotNull(protocols);
        assertTrue(protocols.isEmpty());
    }

    @Test
    @DisplayName("ServerHello: legacy_session_id эхо-отражает ClientHello")
    // RFC 8446 §4.1.3 требует, чтобы сервер эхо-отражал legacy_session_id
    // клиента для middlebox-совместимости. OpenSSL 3.6.0 с патчем gost-engine
    // отвергает ServerHello с несовпадающим session_id (SSL_R_INVALID_SESSION_ID).
    void testServerHelloEchoesClientSessionId() throws Exception {
        byte[] sid = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(sid);

        byte[] ch =
                buildClientHelloBody(
                        0x0303,
                        sid,
                        csBytes(0xC103),
                        new byte[] {0x00},
                        svExt(),
                        saExt(),
                        ksExt(TlsConstants.GRP_GC256A));

        int sidLen = ch[34] & 0xFF;
        byte[] extractedSid = new byte[sidLen];
        System.arraycopy(ch, 35, extractedSid, 0, sidLen);
        assertArrayEquals(sid, extractedSid, "session_id встроен в ClientHello");

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

        builder.setClientSessionId(extractedSid);
        byte[] sh = builder.buildServerHello(point);

        // ServerHello: legacy_version(2) || random(32) || sid_len(1) || sid || ...
        int shSidLen = sh[34] & 0xFF;
        assertEquals(sid.length, shSidLen, "длина session_id в ServerHello");
        byte[] echoedSid = new byte[shSidLen];
        System.arraycopy(sh, 35, echoedSid, 0, shSidLen);
        assertArrayEquals(sid, echoedSid, "ServerHello session_id совпадает с ClientHello");
        assertArrayEquals(
                sid,
                TlsMessageParser.parseServerHello(sh, SERVER_RESPONSE_TYPES_SENT)
                        .legacySessionIdEcho,
                "Разбор ServerHello возвращает то же эхо");
    }

    private static byte[] encodeAlpnExt(List<String> protocols) throws Exception {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (String p : protocols) {
            byte[] name = p.getBytes(StandardCharsets.US_ASCII);
            list.write(name.length & 0xFF);
            list.write(name, 0, name.length);
        }
        byte[] listBytes = list.toByteArray();
        ByteArrayOutputStream extData = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(extData, listBytes.length);
        extData.write(listBytes, 0, listBytes.length);
        return encodeExt(
                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, extData.toByteArray());
    }

    /**
     * Строит extension server_name с указанным hostname (RFC 6066 §3).
     * Используется в тестах parseClientHelloSni для построения ClientHello
     * с конкретным SNI.
     */
    static byte[] sniExt(String hostname) throws Exception {
        byte[] nameBytes = hostname.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream sniBody = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(sniBody, 3 + nameBytes.length); // ServerNameList length
        sniBody.write(0x00); // host_name
        TlsEncoding.encodeUint16(sniBody, nameBytes.length);
        sniBody.write(nameBytes);
        return encodeExt(TlsConstants.EXT_SERVER_NAME, sniBody.toByteArray());
    }
}
