package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Эфемерный открытый ключ CMS: строгий {@code decodePublicKey} не должен ломать BER КриптоПро
 * (AlgorithmIdentifier с indefinite-length), но обязан отвергать лишние элементы.
 */
@DisplayName("CMS: эфемерный открытый ключ")
class CmsEphemeralPublicKeyTest {

    private static final int TAG_CTX_0 = 0xA0;
    private static final int TAG_CTX_1 = 0xA1;

    private final PublicKeyParameters key =
            Signature.derivePublicKey(
                    new PrivateKeyParameters(
                            BigInteger.valueOf(987654321L),
                            GostCurves.byName(GostCurves.OID_TC26_A_256)));

    /** Части SPKI: [AlgorithmIdentifier, BIT STRING] в DER. */
    private byte[][] derParts() {
        return DerCodec.parseStrictSequence(GostDerCodec.encodePublicKey(key));
    }

    /** AlgorithmIdentifier в BER: indefinite-length у внешней и вложенной SEQUENCE. */
    private byte[] berAlgorithm() {
        byte[][] algorithm = DerCodec.parseStrictSequence(derParts()[0]);
        byte[][] parameters = DerCodec.parseStrictSequence(algorithm[1]);
        return DerCodec.concat(
                new byte[] {0x30, (byte) 0x80},
                algorithm[0],
                new byte[] {0x30, (byte) 0x80},
                DerCodec.concat(parameters),
                new byte[] {0x00, 0x00, 0x00, 0x00});
    }

    private byte[] originatorField(byte[]... elements) {
        byte[] originatorKey = DerCodec.encodeTlv(TAG_CTX_1, DerCodec.concat(elements));
        return DerCodec.encodeTlv(TAG_CTX_0, originatorKey);
    }

    private void assertSameKey(PublicKeyParameters decoded) {
        assertEquals(key, decoded, "Эфемерный ключ должен сохраняться");
    }

    @Test
    @DisplayName("parseEphemeralPublicKey: DER SPKI принимается")
    void parseDer() throws PkixException {
        assertSameKey(
                CmsEnvelopedDataDecryptor.parseEphemeralPublicKey(
                        GostDerCodec.encodePublicKey(key)));
    }

    @Test
    @DisplayName("parseEphemeralPublicKey: AlgorithmIdentifier с indefinite-length принимается")
    void parseBerAlgorithm() throws PkixException {
        byte[] spki = DerCodec.encodeSequence(berAlgorithm(), derParts()[1]);
        assertSameKey(CmsEnvelopedDataDecryptor.parseEphemeralPublicKey(spki));
    }

    @Test
    @DisplayName("parseEphemeralPublicKey: лишний элемент отвергается, а не отбрасывается молча")
    void parseExtraElement() {
        byte[] spki = DerCodec.encodeSequence(derParts()[0], derParts()[1], DerCodec.encodeNull());
        assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.parseEphemeralPublicKey(spki),
                "Третий элемент эфемерного ключа должен отвергаться");
    }

    @Test
    @DisplayName("parseEphemeralPublicKey: байты после внешней SEQUENCE отвергаются")
    void parseTrailingBytes() {
        byte[] spki = DerCodec.concat(GostDerCodec.encodePublicKey(key), new byte[] {0x00});
        assertThrows(
                IllegalArgumentException.class,
                () -> CmsEnvelopedDataDecryptor.parseEphemeralPublicKey(spki),
                "Хвост после внешней SEQUENCE эфемерного ключа должен отвергаться");
    }

    @Test
    @DisplayName("parseEphemeralPublicKey: внешняя SEQUENCE с indefinite-length принимается")
    void parseBerOuterSequence() throws PkixException {
        byte[][] parts = derParts();
        byte[] spki =
                DerCodec.concat(
                        new byte[] {0x30, (byte) 0x80},
                        berAlgorithm(),
                        parts[1],
                        new byte[] {0x00, 0x00});
        assertSameKey(CmsEnvelopedDataDecryptor.parseEphemeralPublicKey(spki));
    }

    @Test
    @DisplayName("extractEphemeralPublicKey: originatorKey с DER AlgorithmIdentifier принимается")
    void extractDer() throws PkixException {
        byte[][] parts = derParts();
        assertSameKey(
                CmsEnvelopedDataDecryptor.extractEphemeralPublicKey(
                        originatorField(parts[0], parts[1])));
    }

    @Test
    @DisplayName("extractEphemeralPublicKey: originatorKey с BER AlgorithmIdentifier принимается")
    void extractBerAlgorithm() throws PkixException {
        assertSameKey(
                CmsEnvelopedDataDecryptor.extractEphemeralPublicKey(
                        originatorField(berAlgorithm(), derParts()[1])));
    }

    @Test
    @DisplayName("extractEphemeralPublicKey: originatorKey из трёх элементов отвергается")
    void extractExtraElement() {
        byte[][] parts = derParts();
        byte[] field = originatorField(parts[0], parts[1], DerCodec.encodeNull());
        assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.extractEphemeralPublicKey(field),
                "Лишний элемент originatorKey должен отвергаться");
    }

    @Test
    @DisplayName("extractEphemeralPublicKey: второй элемент не BIT STRING отвергается")
    void extractSecondNotBitString() {
        byte[][] parts = derParts();
        byte[] field = originatorField(parts[0], DerCodec.encodeOctetString(new byte[] {1, 2, 3}));
        assertThrows(
                IllegalArgumentException.class,
                () -> CmsEnvelopedDataDecryptor.extractEphemeralPublicKey(field),
                "Вместо BIT STRING должен отвергаться любой другой тег");
    }

    @Test
    @DisplayName(
            "extractEphemeralPublicKey: constructed OCTET STRING в AlgorithmIdentifier отвергается")
    void extractUnsupportedConstructed() {
        byte[][] parts = derParts();
        byte[] algorithm =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostCurves.OID_SIGN_256),
                        new byte[] {0x24, 0x03, 0x04, 0x01, 0x41});
        byte[] field = originatorField(algorithm, parts[1]);
        assertThrows(
                IllegalArgumentException.class,
                () -> CmsEnvelopedDataDecryptor.extractEphemeralPublicKey(field),
                "Нормализация не должна превращать нестандартные constructed-элементы в DER");
    }
}
