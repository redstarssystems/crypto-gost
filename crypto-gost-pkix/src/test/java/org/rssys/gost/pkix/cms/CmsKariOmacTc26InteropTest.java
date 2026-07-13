package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPemUtils;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;

@DisplayName("CMS EnvelopedData: interop с эталонными векторами TC26 (kari+omac, ktri)")
class CmsKariOmacTc26InteropTest {

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
    }

    @Test
    // Ранее был @Disabled с формулировкой «проблема в разборе контейнера, а не в KEG».
    // Причина KImp15 MAC mismatch — неверный кофактор TC26_A_256 (1 вместо 4) в ECParameters,
    // исправленный в рамках плана 257. Кофактор влияет на VKO_256 в computeVko, т.е. именно
    // на криптографию KEG, а не на парсинг.
    @DisplayName(
            "a231 (ktri, kuznyechik-ctr-acpkm, 256 бит): расшифровка эталонного ktri-вектора TC26")
    void decryptTc26KtriA231() throws PkixException, IOException {
        byte[] envelopedDer = pemResource("tc26_cms/encrypted_keytrans_a231.pem");
        PrivateKeyParameters recipientKey =
                GostDerCodec.decodePrivateKey(pemResource("tc26_cms/recipient256_key.pem"));
        GostCertificate recipientCert =
                GostCertificate.fromPemOrDer(rawResource("tc26_cms/recipient256_cert.pem"));
        byte[] expectedPlain = rawResource("tc26_cms/text_decrypted.plain");

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(
                        envelopedDer, recipientKey, recipientCert, new Kexp15CmsKeyWrap());

        assertArrayEquals(
                expectedPlain,
                decrypted,
                "ktri: расшифрованный текст должен совпасть с эталоном TC26");
    }

    @Test
    @DisplayName("a211: расшифровка эталонного kari+OMAC вектора (Кузнечик, 512-бит получатель)")
    void decryptTc26KariOmacA211() throws PkixException, IOException {
        byte[] envelopedDer = pemResource("tc26_cms/encrypted_keyagree_a211.pem");
        PrivateKeyParameters recipientKey =
                GostDerCodec.decodePrivateKey(pemResource("tc26_cms/recipient512_key.pem"));
        GostCertificate recipientCert =
                GostCertificate.fromPemOrDer(rawResource("tc26_cms/recipient512_cert.pem"));
        byte[] expectedPlain = rawResource("tc26_cms/text_decrypted.plain");

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(
                        envelopedDer, recipientKey, recipientCert, new Kexp15CmsKeyWrap());

        // Эталонный plaintext — точный вывод openssl gost-engine `cms -decrypt` (47 байт).
        // Исходный tc26_cms/text_decrypted.plain из gost-engine несёт лишний завершающий LF
        // (48 байт), не входящий в реальную полезную нагрузку CMS.
        assertArrayEquals(
                expectedPlain, decrypted, "расшифрованный текст должен совпасть с эталоном TC26");
    }

    private static byte[] pemResource(String name) throws IOException {
        return GostPemUtils.pemToDer(rawResource(name));
    }

    private static byte[] rawResource(String name) throws IOException {
        try (InputStream in =
                CmsKariOmacTc26InteropTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "ресурс не найден: " + name);
            return in.readAllBytes();
        }
    }
}
