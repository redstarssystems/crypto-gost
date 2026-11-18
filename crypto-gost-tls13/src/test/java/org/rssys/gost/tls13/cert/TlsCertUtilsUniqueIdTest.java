package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.util.DerCodec;

/**
 * Фильтр расширений из oid_filters (RFC 8446 §4.2.5) на сертификате с issuerUniqueID и
 * subjectUniqueID. Эти поля IMPLICIT BIT STRING, то есть примитивные теги 0x81 и 0x82; раньше
 * обход TBS выходил на них с {@code false}, и фильтр молча не срабатывал.
 */
@DisplayName("TlsCertUtils.matchesOidFilter: сертификат с uniqueID в TBSCertificate")
class TlsCertUtilsUniqueIdTest {

    private static final byte[] SAN_OID = {0x55, 0x1D, 0x11};
    private static final int TAG_EXTENSIONS = 0xA3;

    private static byte[] plainDer;
    private static byte[] sanValue;

    @BeforeAll
    static void setUp() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"unique-id.example.com"});
        plainDer = bundle.cert.getEncoded();
        sanValue = extensionValue(plainDer, SAN_OID);
    }

    /** Содержимое OCTET STRING extnValue расширения с заданным OID. */
    private static byte[] extensionValue(byte[] certDer, byte[] oidBytes) {
        byte[][] top = DerCodec.parseSequenceContents(certDer, 0);
        for (byte[] child : DerCodec.parseSequenceContents(top[0], 0)) {
            if ((child[0] & 0xFF) != TAG_EXTENSIONS) {
                continue;
            }
            int contentOffset = 1 + DerCodec.decodeLength(child, 1)[1];
            for (byte[] extension : DerCodec.parseSequenceContents(child, contentOffset)) {
                byte[][] parts = DerCodec.parseSequenceContents(extension, 0);
                byte[] oid = parts[0];
                if (oid.length == oidBytes.length + 2
                        && java.util.Arrays.equals(
                                java.util.Arrays.copyOfRange(oid, 2, oid.length), oidBytes)) {
                    byte[] octet = parts[parts.length - 1];
                    int offset = 1 + DerCodec.decodeLength(octet, 1)[1];
                    return java.util.Arrays.copyOfRange(octet, offset, octet.length);
                }
            }
        }
        throw new IllegalStateException("Расширение не найдено");
    }

    /** Вставляет uniqueID перед блоком расширений; подпись не пересчитывается (не проверяется). */
    private static byte[] withUniqueIds(byte[]... uniqueIds) {
        byte[][] top = DerCodec.parseSequenceContents(plainDer, 0);
        List<byte[]> children = new ArrayList<>();
        for (byte[] child : DerCodec.parseSequenceContents(top[0], 0)) {
            if ((child[0] & 0xFF) == TAG_EXTENSIONS) {
                for (byte[] uniqueId : uniqueIds) {
                    children.add(uniqueId);
                }
            }
            children.add(child);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        children.forEach(out::writeBytes);
        return DerCodec.encodeSequence(DerCodec.encodeSequence(out.toByteArray()), top[1], top[2]);
    }

    private static boolean sanFilterMatches(byte[] certDer) {
        GostCertificate cert = GostCertificate.fromDer(certDer);
        return TlsCertUtils.matchesOidFilter(cert, new OIDFilter(SAN_OID, sanValue));
    }

    @Test
    @DisplayName("Без uniqueID фильтр по значению SAN срабатывает (контроль)")
    void plainCertificateMatches() {
        assertTrue(sanFilterMatches(plainDer), "Контрольный сертификат должен проходить фильтр");
    }

    @Test
    @DisplayName("С примитивными uniqueID 0x81 и 0x82 фильтр по значению расширения срабатывает")
    void primitiveUniqueIdsDoNotBreakFilter() {
        byte[] der =
                withUniqueIds(
                        DerCodec.encodeTlv(0x81, new byte[] {0x00, 0x5A}),
                        DerCodec.encodeTlv(0x82, new byte[] {0x00, 0x5A}));
        assertTrue(
                sanFilterMatches(der),
                "uniqueID перед расширениями не должны ломать поиск расширения");
    }

    @Test
    @DisplayName("С constructed uniqueID 0xA1 фильтр по-прежнему срабатывает")
    void constructedUniqueIdStillSupported() {
        byte[] der = withUniqueIds(DerCodec.encodeTlv(0xA1, new byte[] {0x03, 0x02, 0x00, 0x5A}));
        assertTrue(sanFilterMatches(der), "Прежняя терпимость к 0xA1 сохранена");
    }
}
