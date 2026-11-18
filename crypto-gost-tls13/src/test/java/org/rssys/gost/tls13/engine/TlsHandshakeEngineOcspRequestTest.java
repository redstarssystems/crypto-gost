package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Сервер шлёт OCSP-staple только в ответ на status_request итогового ClientHello
 * (RFC 8446 §4.2: ответ на незапрошенное расширение запрещён).
 */
@DisplayName("TlsHandshakeEngine: staple только по запросу клиента (RFC 8446 §4.2)")
class TlsHandshakeEngineOcspRequestTest {

    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final byte[] OCSP = {0x30, 0x03, 0x0A, 0x01, 0x00};

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsHandshakeEngine server(int preferredGroup) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        preferredGroup,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN),
                TlsCiphersuite.namedGroupToParams(preferredGroup),
                preferredGroup,
                SIG_SCHEME,
                HASH_LEN,
                OCSP,
                false,
                null);
    }

    private static Map<Integer, byte[]> shares(int... groups) throws Exception {
        Map<Integer, byte[]> m = new LinkedHashMap<>();
        for (int g : groups) {
            m.put(
                    g,
                    TlsEncoding.encodePoint(
                            KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(g))
                                    .getPublic()));
        }
        return m;
    }

    /** Кадр ClientHello; наш клиент всегда шлёт status_request, при withOcsp=false вырезаем его. */
    private static byte[] clientHello(
            int[] groups, Map<Integer, byte[]> keyShares, boolean withOcsp) throws Exception {
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        TlsMessageBuilderTestAccess.setSupportedGroups(b, groups);
        byte[] body = b.buildClientHello(keyShares, "localhost");
        if (!withOcsp) {
            body = removeExtension(body, TlsConstants.EXT_STATUS_REQUEST);
        }
        return new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body).encode();
    }

    /** Вырезает расширение из ClientHello и пересчитывает длину блока расширений. */
    private static byte[] removeExtension(byte[] ch, int extType) {
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        pos += 1 + (ch[pos] & 0xFF);
        pos += 2 + (((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF));
        pos += 1 + (ch[pos] & 0xFF);
        int lenPos = pos;
        int extStart = pos + 2;
        int extEnd = extStart + (((ch[lenPos] & 0xFF) << 8) | (ch[lenPos + 1] & 0xFF));
        byte[] out = new byte[ch.length];
        System.arraycopy(ch, 0, out, 0, extStart);
        int w = extStart;
        for (int p = extStart; p < extEnd; ) {
            int type = ((ch[p] & 0xFF) << 8) | (ch[p + 1] & 0xFF);
            int total = 4 + (((ch[p + 2] & 0xFF) << 8) | (ch[p + 3] & 0xFF));
            if (type != extType) {
                System.arraycopy(ch, p, out, w, total);
                w += total;
            }
            p += total;
        }
        int newExtLen = w - extStart;
        out[lenPos] = (byte) (newExtLen >>> 8);
        out[lenPos + 1] = (byte) newExtLen;
        return Arrays.copyOf(out, w);
    }

    /** Сырое тело серверного Certificate. */
    private static byte[] certificateBodySentBy(TlsHandshakeEngine server) throws Exception {
        byte[] frame;
        while ((frame = HandshakeOutputs.nextMessage(server)) != null) {
            TlsHandshakeMessage msg = TlsHandshakeMessage.decode(frame);
            if (msg.getType() == TlsConstants.HT_CERTIFICATE) {
                return msg.getBody();
            }
        }
        throw new AssertionError("сервер не отправил Certificate");
    }

    /** OCSP-ответ первого сертификата в серверном Certificate или null. */
    private static byte[] stapleSentBy(TlsHandshakeEngine server) throws Exception {
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        certificateBodySentBy(server), Set.of(TlsConstants.EXT_STATUS_REQUEST));
        return chain.get(0).getOcspResponse();
    }

    /** Индекс первого вхождения {@code needle} в {@code haystack} или -1. */
    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    @Test
    @DisplayName("ClientHello со status_request: staple отправляется")
    void stapleSentWhenRequested() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);
        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B},
                        shares(TlsConstants.GRP_GC256B),
                        true));

        byte[] staple = stapleSentBy(s);
        assertNotNull(staple, "клиент запросил OCSP, staple обязан быть отправлен");
        assertArrayEquals(OCSP, staple, "staple должен совпадать с настроенным ответом");
    }

    @Test
    @DisplayName("ClientHello без status_request: staple не отправляется")
    void stapleNotSentWhenNotRequested() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);
        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B},
                        shares(TlsConstants.GRP_GC256B),
                        false));

        assertNull(
                stapleSentBy(s),
                "клиент не просил OCSP: незапрошенное расширение запрещено RFC 8446 §4.2");
    }

    @Test
    @DisplayName("HRR: решение по CH2 — без status_request в CH2 staple не отправляется")
    void stapleDecidedByFinalClientHello() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);
        int[] groups = {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C};

        s.receive(clientHello(groups, shares(TlsConstants.GRP_GC256B), true));
        assertNotNull(
                HandshakeOutputs.nextMessage(s), "первым ответом ожидается HelloRetryRequest");
        s.receive(clientHello(groups, shares(TlsConstants.GRP_GC512C), false));

        assertNull(
                stapleSentBy(s), "решение принимается по итоговому ClientHello, а не по первому");
    }
}
