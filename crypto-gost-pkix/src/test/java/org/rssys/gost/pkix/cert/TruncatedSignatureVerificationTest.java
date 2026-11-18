package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cms.CAdESCompleteData;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Длина подписи приходит из недоверенного DER и при разборе не проверяется. Проверка подписи
 * обязана сообщать о такой подписи штатным отказом, а не unchecked-исключением ядра.
 */
@DisplayName("Подпись неверной длины: штатный отказ вместо unchecked-исключения")
class TruncatedSignatureVerificationTest {

    private static KeyPair keys;

    @BeforeAll
    static void setUp() {
        keys = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
    }

    /** Заменяет подпись (последний элемент SEQUENCE) на укороченную на один байт. */
    private static byte[] withTruncatedSignature(byte[] der) {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        int signatureIdx = parts.length - 1;
        byte[] signature = DerCodec.parseBitString(parts[signatureIdx], 0);
        parts[signatureIdx] =
                DerCodec.encodeBitString(Arrays.copyOf(signature, signature.length - 1));
        return DerCodec.encodeSequence(parts);
    }

    @Test
    @DisplayName("Сертификат: verifySignature возвращает false")
    void certificateReturnsFalse() {
        GostCertificate cert =
                CmsTestUtils.createSelfSignedCert(keys.getPrivate(), keys.getPublic());
        assertTrue(cert.verifySignature(keys.getPublic()), "исходная подпись должна быть валидной");

        GostCertificate broken = GostCertificate.fromDer(withTruncatedSignature(cert.getEncoded()));

        assertFalse(
                broken.verifySignature(keys.getPublic()),
                "подпись неверной длины - не валидная подпись");
    }

    @Test
    @DisplayName("CRL: verify даёт PkixException(SIGNATURE_INVALID)")
    void crlThrowsPkixException() {
        byte[] crlDer =
                GostCrlBuilder.create("CN=Truncated Root,C=RU")
                        .nextUpdate("20990601120000Z")
                        .sign(keys.getPrivate());
        GostCrl broken = GostCrl.fromDer(withTruncatedSignature(crlDer));

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> broken.verify(keys.getPublic()),
                        "подпись CRL неверной длины должна давать PkixException");
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, e.reason(), "причина - подпись");
    }

    @Test
    @DisplayName("CSR: verify и verifySelf возвращают false")
    void csrReturnsFalse() {
        byte[] csrDer =
                GostCsrBuilder.create("CN=Truncated,C=RU", keys.getPublic())
                        .sign(keys.getPrivate());
        assertTrue(GostCsrParser.fromDer(csrDer).verifySelf(), "исходный CSR должен проходить");

        GostCsrParser broken = GostCsrParser.fromDer(withTruncatedSignature(csrDer));

        assertFalse(broken.verify(keys.getPublic()), "подпись неверной длины - не валидная");
        assertFalse(
                broken.verifySelf(), "proof-of-possession с неверной длиной подписи не пройден");
    }

    @Test
    @DisplayName("OtherHash с чужим OID отклоняется при разборе")
    void otherHashWithForeignOidIsRejected() {
        byte[] foreignHash =
                CAdESCompleteData.encodeOtherHashStreebog(new byte[32], "1.2.840.113549.1.1.11");

        assertThrows(
                PkixException.class,
                () -> CAdESCompleteData.decodeOtherHash(foreignHash),
                "OtherHash с OID не из Стрибога должен отклоняться при разборе");
    }
}
