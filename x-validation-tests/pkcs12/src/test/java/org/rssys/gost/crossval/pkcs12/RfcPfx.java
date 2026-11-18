package org.rssys.gost.crossval.pkcs12;

import java.io.IOException;
import java.io.InputStream;

/** Эталонные PFX из приложения A RFC 9548: собраны независимо от нашей библиотеки. */
final class RfcPfx {

    private RfcPfx() {}

    /** Пример A.2: ключ защищён паролем, сертификат открытый. */
    static byte[] a2() throws IOException {
        return load("a2.pfx");
    }

    /** Пример A.3: ключ и сертификат защищены паролем (Магма, сертификат в EncryptedData). */
    static byte[] a3() throws IOException {
        return load("a3.pfx");
    }

    private static byte[] load(String name) throws IOException {
        try (InputStream in = RfcPfx.class.getResourceAsStream("/rfc9548/" + name)) {
            if (in == null) {
                throw new IOException("не найден ресурс /rfc9548/" + name);
            }
            return in.readAllBytes();
        }
    }
}
