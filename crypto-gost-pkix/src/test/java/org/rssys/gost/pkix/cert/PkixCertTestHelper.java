package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Вспомогательные методы для тестов PKIX — сертификатные фабрики и утилиты.
 *
 * <p>Выделен из TlsTestHelper при переносе PKCS12-тестов из tls13 в pkix.
 * Содержит только методы, используемые PKCS12-тестами.
 * Не дублирует CRL/OCSP/TLS-специфичные хелперы из TlsTestHelper.
 */
public final class PkixCertTestHelper {

    private PkixCertTestHelper() {}

    // ========================================================================
    // Hex-утилита
    // ========================================================================

    /** Преобразует строку с hex-байтами через пробел в byte[]. */
    public static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        int len = clean.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(clean.charAt(i), 16) << 4)
                                    | Character.digit(clean.charAt(i + 1), 16));
        }
        return data;
    }

    // ========================================================================
    // Пароль -> UTF-8
    // ========================================================================

    /** Преобразует пароль в UTF-8. Пустой пароль -> пустой массив. */
    public static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        return new String(password).getBytes(StandardCharsets.UTF_8);
    }

    // ========================================================================
    // CertBundle
    // ========================================================================

    /** Результат создания сертификата — сертификат, ключи и subject DN. */
    public static class CertBundle {
        public final GostCertificate cert;
        public final PrivateKeyParameters priv;
        public final byte[] subjectDn;

        public CertBundle(GostCertificate cert, PrivateKeyParameters priv, byte[] subjectDn) {
            this.cert = cert;
            this.priv = priv;
            this.subjectDn = subjectDn;
        }
    }

    // ========================================================================
    // Сертификатные фабрики
    // ========================================================================

    private static int certCounter = 0;

    /**
     * Создаёт самоподписанный сертификат.
     * Срок: 2025-01-01 — 2101-01-01.
     */
    public static CertBundle createCertWithKey(ECParameters params) {
        return createCertWithKey(params, "20250101000000Z", "21010101000000Z");
    }

    /** Создаёт самоподписанный сертификат с заданным сроком. */
    public static CertBundle createCertWithKey(
            ECParameters params, String notBefore, String notAfter) {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, priv, params);
        return new CertBundle(cert, priv, subjectDn);
    }

    /**
     * Создаёт корневой CA (самоподписанный, BC: cA=TRUE, KU: keyCertSign).
     * Срок: 2025-01-01 — 2101-01-01.
     */
    public static CertBundle createRootCA(ECParameters params) throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Root CA " + (++certCounter));
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN));
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, priv, params);
        return new CertBundle(cert, priv, subjectDn);
    }

    /**
     * Создаёт сертификат, подписанный issuerPriv.
     * Issuer DN берётся из parentSubjectDn.
     * Возвращает CertBundle с сгенерированным privKey подписанного сертификата.
     *
     * @param sanIps IP-адреса SAN (null если не нужны) — позиция между sanDnsNames и kuFlags
     */
    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen)
            throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        if (isCA || pathLen != null) {
            extBuf.write(GostCertificateBuilder.buildBasicConstraintsExtension(isCA, pathLen));
        }
        if (kuFlags != null) {
            extBuf.write(GostCertificateBuilder.buildKeyUsageExtension(kuFlags));
        }
        if (ekuOids != null) {
            extBuf.write(GostCertificateBuilder.buildEkuExtension(ekuOids));
        }
        byte[] additionalExt = extBuf.size() == 0 ? null : extBuf.toByteArray();
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(leafPub)
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .sanDns(sanDnsNames)
                        .sanIp(sanIps)
                        .additionalExtensions(additionalExt)
                        .issuerDn(parentSubjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, issuerPriv, params);
        return new CertBundle(cert, leafPriv, subjectDn);
    }

    // ========================================================================
    // Приватные
    // ========================================================================

    private static byte[] buildDN(String cn) {
        return GostDnParser.encodeDn("CN=" + cn);
    }
}
