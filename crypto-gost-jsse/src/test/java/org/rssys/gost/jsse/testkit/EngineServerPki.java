package org.rssys.gost.jsse.testkit;

import java.security.cert.CertificateException;
import java.util.List;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Типовая PKI тестов движка: корневой УЦ, серверный сертификат для {@code localhost} (цифровая
 * подпись) и менеджер ключей сервера с цепочкой «сертификат, корень».
 *
 * @param rootCa     корневой УЦ
 * @param serverCert серверный сертификат с ключом
 * @param serverKm   менеджер ключей с одной записью {@code default}
 */
public record EngineServerPki(
        PkixCertTestHelper.CertBundle rootCa,
        PkixCertTestHelper.CertBundle serverCert,
        GostX509KeyManager serverKm) {

    private static final String SERVER_KEY_ALIAS = "default";
    private static final String CERT_NOT_BEFORE = "240501120000Z";
    // Срок далеко в будущем: тестовые сертификаты не должны истекать во время жизни проекта
    private static final String CERT_NOT_AFTER = "21060101120000Z";
    private static final byte[] KEY_USAGE_DIGITAL_SIGNATURE = {(byte) 0x80};

    /** Создаёт новую PKI на кривой tc26a256. */
    public static EngineServerPki create() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        CERT_NOT_BEFORE,
                        CERT_NOT_AFTER,
                        new String[] {"localhost"},
                        KEY_USAGE_DIGITAL_SIGNATURE,
                        null,
                        false,
                        null);
        return new EngineServerPki(rootCa, serverCert, keyManagerFor(serverCert, rootCa));
    }

    private static GostX509KeyManager keyManagerFor(
            PkixCertTestHelper.CertBundle serverCert, PkixCertTestHelper.CertBundle rootCa)
            throws CertificateException {
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                SERVER_KEY_ALIAS,
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        return keyManager;
    }
}
