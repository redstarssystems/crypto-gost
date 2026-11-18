package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * {@link GostDerCodec#encodeSpkiKeyBits}: содержимое BIT STRING в SubjectPublicKeyInfo без октета
 * unused-bits. Оно нужно для хэшей OCSP, где в хэш входят только биты ключа.
 */
@DisplayName("GostDerCodec.encodeSpkiKeyBits: содержимое BIT STRING в SPKI без октета unused-bits")
class GostDerCodecSpkiKeyBitsTest {

    @Test
    @DisplayName("Биты ключа совпадают с BIT STRING из DER SPKI после октета unused-bits")
    void matchesSpkiBitStringContent() {
        for (ECParameters params :
                new ECParameters[] {ECParameters.tc26a256(), ECParameters.tc26a512()}) {
            PublicKeyParameters pub = KeyGenerator.generateKeyPair(params).getPublic();

            byte[] bits = GostDerCodec.encodeSpkiKeyBits(pub);

            byte[][] spki = DerCodec.parseSequenceContents(GostDerCodec.encodePublicKey(pub), 0);
            byte[] bitString = spki[1];
            int[] length = DerCodec.decodeLength(bitString, 1);
            byte[] bitStringContent =
                    Arrays.copyOfRange(bitString, 1 + length[1], bitString.length);

            assertEquals(0x00, bitStringContent[0], "первый октет - число неиспользуемых бит, 0");
            assertArrayEquals(
                    bits,
                    Arrays.copyOfRange(bitStringContent, 1, bitStringContent.length),
                    "после октета unused-bits идёт тот же OCTET STRING, что у encodeSpkiKeyBits");
        }
    }
}
