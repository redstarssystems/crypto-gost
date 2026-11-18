package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Контракт публичных {@code decode*}: на любом входе результат либо успех, либо
 * {@link PkixException}; unchecked-исключения {@code DerCodec} наружу не выходят.
 */
@DisplayName("CAdESCompleteData: decode* бросают только PkixException")
class CAdESCompleteDataDecodeContractTest {

    private static final int RANDOM_INPUTS = 300;

    /** Все публичные декодеры под одним интерфейсом. */
    private interface Decoder {
        void decode(byte[] der) throws PkixException;
    }

    private static final List<Decoder> DECODERS =
            List.of(
                    CAdESCompleteData::decodeOtherHash,
                    CAdESCompleteData::decodeOtherCertID,
                    CAdESCompleteData::decodeCompleteCertificateRefs,
                    CAdESCompleteData::decodeCompleteRevocationRefs,
                    CAdESCompleteData::decodeCrlOcspRef);

    private static void assertOnlyPkixException(Decoder decoder, byte[] der, String description) {
        try {
            decoder.decode(der);
        } catch (PkixException expected) {
            // штатный отказ
        } catch (RuntimeException e) {
            fail(description + ": unchecked-исключение вместо PkixException: " + e);
        }
    }

    @Test
    @DisplayName("null и пустой DER дают PkixException")
    void nullAndEmptyGivePkixException() {
        for (Decoder decoder : DECODERS) {
            assertThrows(
                    PkixException.class,
                    () -> decoder.decode(null),
                    "null должен давать PkixException");
            assertThrows(
                    PkixException.class,
                    () -> decoder.decode(new byte[0]),
                    "пустой массив должен давать PkixException");
        }
    }

    @Test
    @DisplayName("Обрезанный корректный DER не даёт unchecked-исключений")
    void truncatedValidDerGivesOnlyPkixException() {
        byte[] otherHash =
                CAdESCompleteData.encodeOtherHashStreebog(new byte[32], GostOids.DIGEST_256);
        for (int len = 0; len < otherHash.length; len++) {
            byte[] truncated = Arrays.copyOf(otherHash, len);
            for (Decoder decoder : DECODERS) {
                assertOnlyPkixException(decoder, truncated, "обрезка до " + len + " байт");
            }
        }
    }

    @Test
    @DisplayName("Случайный DER не даёт unchecked-исключений")
    void randomInputGivesOnlyPkixException() {
        for (int i = 0; i < RANDOM_INPUTS; i++) {
            byte[] random = new byte[1 + (i % 64)];
            CryptoRandom.INSTANCE.nextBytes(random);
            // Начало как у SEQUENCE и контекстных тегов: иначе разбор отсекается на первом байте.
            random[0] = (byte) (i % 3 == 0 ? 0x30 : i % 3 == 1 ? 0xA0 : 0xA1);
            for (Decoder decoder : DECODERS) {
                assertOnlyPkixException(decoder, random, "случайный вход #" + i);
            }
        }
    }
}
