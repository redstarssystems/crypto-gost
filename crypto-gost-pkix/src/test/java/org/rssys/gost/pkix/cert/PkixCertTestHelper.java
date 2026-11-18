package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Общий помощник тестов: тестовые сертификаты, CRL, OCSP-ответы и DER-построители.
 *
 * <p>Объединяет прежние помощники pkix и tls13. Сертификаты создаются с фиксированными
 * сроками 2025-01-01...2101-01-01, корневой CA несёт {@code keyCertSign} и {@code cRLSign}.
 * Построители сводятся в builder'ы pkix; исключение {@link #createCertWithForcedIssuer}
 * (тестовый хак, issuer != signer).</p>
 */
public final class PkixCertTestHelper {

    private PkixCertTestHelper() {}

    private static final DateTimeFormatter GEN_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

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

    /** Преобразует пароль в UTF-8. Пустой пароль -> пустой массив. */
    public static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        return new String(password).getBytes(StandardCharsets.UTF_8);
    }

    public static String hexStr(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    private static int certCounter = 0;

    /** Результат создания сертификата — сам сертификат, ключи и subject DN. */
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
    // Сертификаты (keygen здесь -> builder'ы в pkix для сборки)
    // ========================================================================

    /**
     * Создаёт самоподписанный сертификат и возвращает его с ключом.
     * Генерация ключей — в PkixCertTestHelper (тестовый скоуп), сборка — в GostCertificateBuilder.
     */
    public static CertBundle createCertWithKey(ECParameters params) {
        return createCertWithKey(params, "20250101000000Z", "21010101000000Z", null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params, String notBefore, String notAfter) {
        return createCertWithKey(params, notBefore, notAfter, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params, String notBefore, String notAfter, String[] sanDnsNames) {
        return createCertWithKey(params, notBefore, notAfter, sanDnsNames, null, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids) {
        return createCertWithKey(
                params, notBefore, notAfter, sanDnsNames, kuFlags, ekuOids, null, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            String[] sanIps) {
        return createCertWithKey(
                params, notBefore, notAfter, sanDnsNames, kuFlags, ekuOids, sanIps, null);
    }

    public static CertBundle createCertWithKey(
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            String[] sanIps,
            String[] policyOids) {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Cert " + (++certCounter));
        byte[] additionalExt = buildAdditionalExtensions(kuFlags, ekuOids, policyOids);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .randomSerial()
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .sanDns(sanDnsNames)
                        .sanIp(sanIps)
                        .additionalExtensions(additionalExt)
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(priv));
        return new CertBundle(cert, priv, subjectDn);
    }

    /** Создаёт корневой CA (самоподписанный, BC: cA=TRUE, KU: keyCertSign). */
    public static CertBundle createRootCA(ECParameters params) throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Root CA " + (++certCounter));
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN),
                        false);
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .randomSerial()
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(priv));
        return new CertBundle(cert, priv, subjectDn);
    }

    /** Создаёт самоподписанный корневой CA с NameConstraints по DNS-именам. */
    public static CertBundle createRootCAWithNameConstraints(
            ECParameters params, String[] permittedDns, String[] excludedDns) throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters priv = kp.getPrivate();
        PublicKeyParameters pub = kp.getPublic();

        byte[] subjectDn = buildDN("Test Root CA NC " + (++certCounter));
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN),
                        false);
        byte[] ncExt =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        permittedDns, null, excludedDns, null);
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        extBuf.write(ncExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(pub)
                        .randomSerial()
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(priv));
        return new CertBundle(cert, priv, subjectDn);
    }

    /**
     * Перевыпускает корень с тем же ключом и subject DN, но с новым сроком,
     * серийным номером и DER. NC намеренно не копируются: тест должен доказать,
     * что используется локальный старый якорь, а не присланный новый корень.
     */
    public static CertBundle createReissuedRoot(
            ECParameters params, CertBundle source, String notBefore, String notAfter)
            throws Exception {
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.keyUsageFlags(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN),
                        false);
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, source.subjectDn)
                        .publicKey(source.cert.getPublicKey())
                        .randomSerial()
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(source.subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(source.priv));
        return new CertBundle(cert, source.priv, source.subjectDn);
    }

    /** Создаёт сертификат, подписанный issuerPriv.
     *  Issuer DN берётся из parentSubjectDn.
     *  Возвращает CertBundle с сгенерированным privKey подписанного сертификата. */
    public static CertBundle createCertSignedBy(
            ECParameters params,
            PrivateKeyParameters issuerPriv,
            PublicKeyParameters issuerPub,
            byte[] parentSubjectDn,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            byte[] kuFlags,
            String[] ekuOids,
            boolean isCA,
            Integer pathLen)
            throws Exception {
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                null,
                kuFlags,
                ekuOids,
                isCA,
                pathLen);
    }

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
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                sanIps,
                kuFlags,
                ekuOids,
                isCA,
                pathLen,
                null,
                null);
    }

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
            Integer pathLen,
            byte[] extraExtensions)
            throws Exception {
        return createCertSignedBy(
                params,
                issuerPriv,
                issuerPub,
                parentSubjectDn,
                notBefore,
                notAfter,
                sanDnsNames,
                sanIps,
                kuFlags,
                ekuOids,
                isCA,
                pathLen,
                extraExtensions,
                null);
    }

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
            Integer pathLen,
            byte[] extraExtensions,
            String[] policyOids)
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
            extBuf.write(GostCertificateBuilder.buildKeyUsageExtension(kuFlags, false));
        }
        if (ekuOids != null) {
            extBuf.write(GostCertificateBuilder.buildEkuExtension(ekuOids, false));
        }
        if (policyOids != null) {
            extBuf.write(GostCertificateBuilder.buildCertificatePoliciesExtension(policyOids));
        }
        if (extraExtensions != null) {
            extBuf.write(extraExtensions);
        }
        byte[] additionalExt = extBuf.size() == 0 ? null : extBuf.toByteArray();
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(leafPub)
                        .randomSerial()
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .sanDns(sanDnsNames)
                        .sanIp(sanIps)
                        .additionalExtensions(additionalExt)
                        .issuerDn(parentSubjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(issuerPriv));
        return new CertBundle(cert, leafPriv, subjectDn);
    }

    /** Тестовый хак: issuer != signer. Не переносится в GostCertificateBuilder. */
    public static CertBundle createCertWithForcedIssuer(
            ECParameters params,
            PrivateKeyParameters signerPriv,
            byte[] issuerDn,
            String subjectCN,
            String notBefore,
            String notAfter)
            throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters leafPriv = kp.getPrivate();
        PublicKeyParameters leafPub = kp.getPublic();
        int hlen = params.hlen;
        byte[] subjectDn = buildDN(subjectCN);
        byte[] tbs =
                buildTbs(
                        leafPub, params, notBefore, notAfter, null, null, null, issuerDn,
                        subjectDn);
        byte[] hash = doHash(tbs, hlen);
        byte[] sig = Signature.signHash(hash, signerPriv);
        byte[] algId = buildAlgId(params);
        byte[] sigBs = derBitString(sig);
        byte[] certDer = derSequence(tbs, algId, sigBs);
        return new CertBundle(new GostCertificate(certDer), leafPriv, subjectDn);
    }

    // ========================================================================
    // Расширения X.509 (делегаты)
    // ========================================================================

    public static byte[] buildAiaOcspExtension(String ocspUri) {
        return GostCertificateBuilder.buildAiaExtension(ocspUri, null);
    }

    public static byte[] buildCdpExtension(String... crlUris) {
        return GostCertificateBuilder.buildCdpExtension(crlUris);
    }

    public static byte[] buildTbs(
            PublicKeyParameters pub,
            ECParameters params,
            String notBefore,
            String notAfter,
            String[] sanDnsNames,
            String[] sanIps,
            byte[] additionalExtensions,
            byte[] issuerDn,
            byte[] subjectDn) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(params, subjectDn).publicKey(pub).randomSerial();
        if (notBefore != null) {
            builder.notBefore(notBefore);
        }
        if (notAfter != null) {
            builder.notAfter(notAfter);
        }
        if (sanDnsNames != null) {
            builder.sanDns(sanDnsNames);
        }
        if (sanIps != null) {
            builder.sanIp(sanIps);
        }
        if (additionalExtensions != null) {
            builder.additionalExtensions(additionalExtensions);
        }
        if (issuerDn != null) {
            builder.issuerDn(issuerDn);
        }
        return builder.buildTbs();
    }

    // ========================================================================
    // CRL (делегаты -> GostCrlBuilder)
    // ========================================================================

    /**
     * Convenience-перегрузка для обратной совместимости.
     * Оборачивает {@code byte[][] serialNumbers} в {@link RevokedEntry}[] с null-полями.
     * RevocationDate = текущее время.
     */
    public static byte[] buildCrl(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            boolean withIdpExtension)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder = GostCrlBuilder.create(issuerDnDer);
        if (nextUpdateGeneralizedTime != null) {
            builder = builder.nextUpdate(nextUpdateGeneralizedTime);
        } else {
            // null в хелпере означает осознанный выпуск без nextUpdate
            builder = builder.withoutNextUpdate();
        }
        if (withIdpExtension) {
            builder = builder.withIdpExtension();
        }
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.sign(caPriv);
    }

    public static byte[] buildCrlLegacyVersion(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            boolean withIdpExtension)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        return GostCrlBuilder.assembleCrl(
                entries,
                caPriv,
                issuerDnDer,
                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME),
                nextUpdateGeneralizedTime,
                true,
                null,
                null,
                null,
                withIdpExtension,
                null);
    }

    /**
     * Собирает CRL с cRLNumber.
     */
    public static byte[] buildCrlWithCrlNumber(
            byte[][] serialNumbers,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] issuerDnDer,
            String nextUpdateGeneralizedTime,
            int crlNumber)
            throws Exception {
        RevokedEntry[] entries = null;
        if (serialNumbers != null && serialNumbers.length > 0) {
            entries = new RevokedEntry[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                entries[i] =
                        new RevokedEntry(
                                serialNumbers[i],
                                ZonedDateTime.now(ZoneOffset.UTC).format(GEN_TIME));
            }
        }
        GostCrlBuilder builder = GostCrlBuilder.create(issuerDnDer).withCrlNumber(crlNumber);
        if (nextUpdateGeneralizedTime != null) {
            builder = builder.nextUpdate(nextUpdateGeneralizedTime);
        } else {
            // null в хелпере означает осознанный выпуск без nextUpdate
            builder = builder.withoutNextUpdate();
        }
        if (entries != null) {
            builder = builder.addRevoked(Arrays.asList(entries));
        }
        return builder.sign(caPriv);
    }

    // ========================================================================
    // OCSP (делегаты -> GostOcspResponseBuilder)
    // ========================================================================

    public static byte[] buildOcspResponse(
            byte[] serialNumber,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] caSubjectDer)
            throws Exception {
        return GostOcspResponseBuilder.create(serialNumber).issuerDn(caSubjectDer).sign(caPriv);
    }

    public static byte[] buildOcspResponse(
            byte[] serialNumber,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime)
            throws Exception {
        GostOcspResponseBuilder builder =
                GostOcspResponseBuilder.create(serialNumber).issuerDn(caSubjectDer);
        if (nextUpdateGeneralizedTime != null) {
            builder.nextUpdate(nextUpdateGeneralizedTime);
        }
        return builder.sign(caPriv);
    }

    /**
     * OCSP-ответ с эхо-возвратом nonce из запроса (RFC 8954). Нужен для моков,
     * имитирующих реальный responder: при наличии nonce в запросе ответ обязан его
     * эхировать, иначе fail-closed верификатор отклонит ответ.
     *
     * @param nonce nonce из запроса (или null — не добавлять расширение)
     */
    public static byte[] buildOcspResponseWithNonce(
            byte[] serialNumber,
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            byte[] nonce)
            throws Exception {
        GostOcspResponseBuilder builder =
                GostOcspResponseBuilder.create(serialNumber).issuerDn(caSubjectDer);
        if (nonce != null) {
            builder.nonce(nonce);
        }
        return builder.sign(caPriv);
    }

    /**
     * Извлекает nonce (RFC 8954) из DER OCSP-запроса — для моков responder'а,
     * которым нужно эхировать nonce в ответ.
     *
     * <p>Разбор делегируется {@link GostOcspRequest}, поэтому возвращаются сырые байты
     * значения {@code Nonce} (RFC 8954) без обёрток OCTET STRING.
     *
     * @param requestDer DER OCSP-запроса
     * @return байты nonce или {@code null}, если расширение отсутствует/запрос неразбираем
     */
    public static byte[] extractOcspRequestNonce(byte[] requestDer) {
        try {
            return GostOcspRequest.fromDer(requestDer).getNonce();
        } catch (PkixException | RuntimeException e) {
            return null; // неразбираемый запрос — nonce отсутствует (контракт helper'а)
        }
    }

    public static byte[] buildOcspResponseWithDelegatedCerts(
            byte[] serialNumber,
            PrivateKeyParameters signerPriv,
            PublicKeyParameters signerPub,
            PublicKeyParameters caPub,
            byte[] caSubjectDer,
            String nextUpdateGeneralizedTime,
            byte[][] delegatedCertsDer)
            throws Exception {
        return GostOcspResponseBuilder.create(serialNumber)
                .caPublicKey(caPub)
                .issuerDn(caSubjectDer)
                .nextUpdate(nextUpdateGeneralizedTime)
                .withDelegatedCerts(delegatedCertsDer)
                .sign(signerPriv);
    }

    public static byte[] buildDummyOcspResponse() throws Exception {
        byte[] tbs = new byte[] {0x30, 0x03, 0x02, 0x01, 0x00};
        byte[] sigAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_WITH_DIGEST_256));
        byte[] sig = DerCodec.encodeBitString(new byte[64]);
        byte[] basicOcsp = DerCodec.encodeSequence(tbs, sigAlg, sig);
        // wrapOcspResponse
        byte[] basicOctet = DerCodec.encodeOctetString(basicOcsp);
        byte[] responseBytesContent =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = DerCodec.encodeTlv(0xA0, responseBytesContent);
        byte[] status = new byte[] {0x0A, 0x01, 0x00};
        return DerCodec.encodeSequence(status, responseBytes);
    }

    // ========================================================================
    // Хелперы (оставлены для createCertWithForcedIssuer и обратной совместимости)
    // ========================================================================

    public static byte[] doHash(byte[] data, int hlen) {
        if (hlen == GostOids.STREEBOG_512_HASH_LEN) return Digest.digest512(data);
        return Digest.digest256(data);
    }

    public static byte[] buildAlgId(ECParameters params) {
        int hlen = params.hlen;
        String signOid =
                (hlen == GostOids.STREEBOG_512_HASH_LEN)
                        ? GostOids.SIGN_WITH_DIGEST_512
                        : GostOids.SIGN_WITH_DIGEST_256;
        return derSequence(derOid(signOid));
    }

    public static byte[] buildDN(String cn) {
        return GostDnParser.encodeDn("CN=" + cn);
    }

    /**
     * Строит DER самоподписанного сертификата с намеренно битой записью iPAddress в SAN
     * (тег 0x87, 3 байта вместо 4/16) рядом с валидной записью 10.0.0.1.
     *
     * <p>Возвращает именно сырой DER ({@code byte[]}), а не {@link GostCertificate}: по
     * fail-closed контракту {@code new GostCertificate(der)} обязан бросить
     * {@code IllegalArgumentException}, поэтому готовый объект здесь построить нельзя — он упал
     * бы внутри хелпера. Битый SAN подаётся через additionalExtensions в обход валидации
     * {@code builder.sanIp()}, иначе некорректную запись не собрать.
     *
     * @return DER сертификата с малформед iPAddress в SAN
     */
    public static byte[] malformedSanIpCertDer() {
        byte[] garbageIp = derTlv(0x87, new byte[] {0x01, 0x02, 0x03});
        byte[] validIp = derTlv(0x87, new byte[] {10, 0, 0, 1});
        byte[] gnSeq = derSequence(garbageIp, validIp);
        byte[] sanExt = derSequence(derOid("2.5.29.17"), derOctetString(gnSeq));

        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = buildDN("Test Cert");
        byte[] tbs =
                buildTbs(
                        kp.getPublic(),
                        params,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        sanExt,
                        dn,
                        dn);
        byte[] hash = doHash(tbs, params.hlen);
        byte[] sig = Signature.signHash(hash, kp.getPrivate());
        return derSequence(tbs, buildAlgId(params), derBitString(sig));
    }

    // ========================================================================
    // DER-обёртки (обратная совместимость)
    // ========================================================================

    public static byte[] derSequence(byte[]... elements) {
        return DerCodec.encodeSequence(elements);
    }

    public static byte[] derBitString(byte[] content) {
        return DerCodec.encodeBitString(content);
    }

    public static byte[] derOctetString(byte[] data) {
        return DerCodec.encodeOctetString(data);
    }

    public static byte[] derOid(String oidStr) {
        return DerCodec.encodeOid(oidStr);
    }

    public static byte[] derTime(String time) {
        return DerCodec.encodeTime(time);
    }

    public static byte[] derTlv(int tag, byte[] content) {
        return DerCodec.encodeTlv(tag, content);
    }

    public static byte[] encodeSet(byte[] content) {
        return DerCodec.encodeSet(content);
    }

    // ========================================================================
    // Приватные
    // ========================================================================

    private static byte[] buildAdditionalExtensions(
            byte[] kuFlags, String[] ekuOids, String[] policyOids) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (kuFlags != null) {
                out.write(GostCertificateBuilder.buildKeyUsageExtension(kuFlags, false));
            }
            if (ekuOids != null) {
                out.write(GostCertificateBuilder.buildEkuExtension(ekuOids, false));
            }
            if (policyOids != null) {
                out.write(GostCertificateBuilder.buildCertificatePoliciesExtension(policyOids));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] data = out.toByteArray();
        return data.length == 0 ? null : data;
    }

    /**
     * Заменяет ResponderID готового ответа на byKey с заданным значением хэша и подписывает
     * TBS заново: построитель библиотеки выпускает byKey только длиной 32 и 64 байта, а для
     * проверки сторонних ответов нужны иные длины.
     */
    public static byte[] withResponderKeyHash(
            byte[] baseOcsp, byte[] responderKeyHash, PrivateKeyParameters signKey) {
        byte[][] outer = DerCodec.parseSequenceContents(baseOcsp, 0);
        byte[] rb = outer[1];
        int[] rbLen = DerCodec.decodeLength(rb, 1);
        byte[][] rbContent = DerCodec.parseSequenceContents(rb, 1 + rbLen[1]);
        byte[] basicDer = DerCodec.parseOctetString(rbContent[1], 0);
        byte[][] basicParts = DerCodec.parseSequenceContents(basicDer, 0);
        byte[][] tbsParts = DerCodec.parseSequenceContents(basicParts[0], 0);

        // version [0] DEFAULT v1 в DER не кодируется: позиция responderID зависит от его наличия
        int responderIdPos = (tbsParts[0][0] & 0xFF) == 0xA0 ? 1 : 0;
        byte[][] newTbsParts = tbsParts.clone();
        newTbsParts[responderIdPos] =
                DerCodec.encodeTlv(
                        DerCodec.TAG_CTX_CONSTRUCTED_2,
                        DerCodec.encodeOctetString(responderKeyHash));
        byte[] newTbs = DerCodec.encodeSequence(newTbsParts);

        byte[] hash = doHash(newTbs, signKey.getParams().hlen);
        byte[] sigBs = DerCodec.encodeBitString(Signature.signHash(hash, signKey));
        byte[] newBasic = DerCodec.encodeSequence(newTbs, basicParts[1], sigBs);
        byte[] newRbContent =
                DerCodec.encodeSequence(rbContent[0], DerCodec.encodeOctetString(newBasic));
        byte[] newRb = DerCodec.encodeContextConstructed(0, newRbContent);
        return DerCodec.encodeSequence(outer[0], newRb);
    }
}
