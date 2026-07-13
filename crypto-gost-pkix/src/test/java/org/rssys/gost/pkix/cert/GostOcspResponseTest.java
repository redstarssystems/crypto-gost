package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;

/**
 * Модульные тесты {@link GostOcspResponse}: разбор, PEM round-trip.
 */
@DisplayName("GostOcspResponse: парсинг и PEM round-trip")
class GostOcspResponseTest {

    // ========================================================================
    // PEM round-trip
    // ========================================================================

    @Test
    @DisplayName("PEM round-trip: toPem() -> fromPemOrDer() -> идентичность полей")
    void testPemRoundTrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};
        byte[] nonce = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .issuerDn(issuerDn)
                        .nonce(nonce)
                        .sign(kp.getPrivate());

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        String pem = resp.toPem();
        assertTrue(
                pem.contains("-----BEGIN OCSP RESPONSE-----"),
                "PEM должен содержать BEGIN OCSP RESPONSE");
        assertTrue(
                pem.contains("-----END OCSP RESPONSE-----"),
                "PEM должен содержать END OCSP RESPONSE");

        GostOcspResponse reparsed =
                GostOcspResponse.fromPemOrDer(
                        pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals(resp.getResponseStatus(), reparsed.getResponseStatus());
        assertEquals(resp.getResponses().size(), reparsed.getResponses().size());
        assertArrayEquals(resp.getNonce(), reparsed.getNonce());
        assertEquals(resp.getResponderIdType(), reparsed.getResponderIdType());
    }

    @Test
    @DisplayName("PEM fromPemOrDer: автоопределение DER")
    void testPemFromPemOrDerAutoDetectsDer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .issuerDn(issuerDn)
                        .sign(kp.getPrivate());

        GostOcspResponse parsed = GostOcspResponse.fromPemOrDer(ocspDer);
        assertTrue(parsed.isSuccessful(), "fromPemOrDer должен парсить DER без ошибок");
    }

    @Test
    @DisplayName("PEM fromPemOrDer: мусорные данные -> PkixException")
    void testPemFromPemOrDerGarbage() {
        assertThrows(
                PkixException.class,
                () -> GostOcspResponse.fromPemOrDer(new byte[] {0x00, 0x01, 0x02}));
    }

    @Test
    @DisplayName("getEncoded: возвращает защитную копию исходного DER")
    void testGetEncodedDefensiveCopy() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .issuerDn(GostDnParser.encodeDn("CN=Test CA"))
                        .sign(kp.getPrivate());

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        byte[] encoded = resp.getEncoded();
        assertArrayEquals(ocspDer, encoded, "getEncoded должен вернуть точную копию исходного DER");

        // Модификация копии не должна влиять на объект
        encoded[0] = 0;
        assertArrayEquals(
                ocspDer,
                resp.getEncoded(),
                "мутация возвращённого массива не должна менять состояние");
    }
}
