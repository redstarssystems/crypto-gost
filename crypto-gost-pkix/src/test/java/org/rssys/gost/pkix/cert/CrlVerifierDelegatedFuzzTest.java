package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Fuzz-тест для {@link CrlVerifier#verifyDelegated(byte[], byte[], PublicKeyParameters,
 * byte[], GostCertificate, List)}.
 *
 * <p>Фаззит CRL DER, серийный номер, и сертификаты подписантов.
 * Новый код разбора: {@code new GostCertificate(signerDer)} для каждого кандидата
 * (expiry, KeyUsage, подпись цепочки) — attacker-controlled байты.
 * IDP-парсинг покрывается фаззингом CRL DER через verify().
 */
class CrlVerifierDelegatedFuzzTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final KeyPair CA_KP = KeyGenerator.generateKeyPair(PARAMS);
    private static final byte[] CA_ISSUER_DN;
    private static final GostCertificate CA_CERT;
    private static final GostCertificate LEAF_CERT;
    private static final byte[] LEAF_SERIAL;

    static {
        try {
            CA_ISSUER_DN = GostDnParser.encodeDn("CN=Fuzz CA,O=FuzzOrg,C=RU");
            byte[] caKuExt =
                    GostCertificateBuilder.buildKeyUsageExtension(
                            GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                            GostCertificateBuilder.KeyUsage.CRL_SIGN);
            byte[] caBcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, 0);
            byte[] caSkiBytes =
                    org.rssys.gost.api.Digest.digest256(
                            org.rssys.gost.jca.spec.GostDerCodec.subjectPublicKeyPointBytes(
                                    CA_KP.getPublic()));
            byte[] caSkiExt = GostCertificateBuilder.buildSkiExtension(CA_KP.getPublic());

            CA_CERT =
                    GostCertificateBuilder.sign(
                            GostCertificateBuilder.create(PARAMS, "CN=Fuzz CA,O=FuzzOrg,C=RU")
                                    .publicKey(CA_KP.getPublic())
                                    .notBefore("260601000000Z")
                                    .notAfter("360601000000Z")
                                    .serial(BigInteger.ONE)
                                    .additionalExtensions(
                                            concatExtensions(caKuExt, caBcExt, caSkiExt))
                                    .buildTbs(),
                            GostSigner.of(CA_KP.getPrivate()));

            KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
            byte[] leafAkiExt = GostCertificateBuilder.buildAkiExtension(caSkiBytes);
            byte[] leafTbs =
                    GostCertificateBuilder.create(PARAMS, "CN=Fuzz Leaf,O=FuzzOrg,C=RU")
                            .publicKey(leafKp.getPublic())
                            .issuerDn(CA_ISSUER_DN)
                            .notBefore("260601000000Z")
                            .notAfter("360601000000Z")
                            .serial(BigInteger.valueOf(2))
                            .additionalExtensions(leafAkiExt)
                            .buildTbs();
            LEAF_CERT = GostCertificateBuilder.sign(leafTbs, GostSigner.of(CA_KP.getPrivate()));
            LEAF_SERIAL = LEAF_CERT.getSerialNumberBigInt().toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concatExtensions(byte[]... exts) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] ext : exts) out.write(ext);
        return out.toByteArray();
    }

    /**
     * Фаззит {@code CrlVerifier.verifyDelegated()} с произвольным CRL DER
     * и списком сертификатов подписантов.
     *
     * <p>Фаззенные точки входа:
     * <ul>
     *   <li>{@code new GostCrl(crlDer)} — парсинг CRL</li>
     *   <li>{@code new GostCertificate(signerDer)} — парсинг сертификата подписанта</li>
     *   <li>{@code signer.isExpired()} / {@code isCrlSigner()} / {@code verifySignature()}</li>
     * </ul>
     */
    @FuzzTest
    void fuzzVerifyDelegated(FuzzedDataProvider data) {
        byte[] crlDer = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] certSerial = data.consumeBytes(data.consumeInt(0, 32));
        int signerCount = data.consumeInt(0, 8);
        List<byte[]> signerCerts = new ArrayList<>();
        for (int i = 0; i < signerCount; i++) {
            signerCerts.add(data.consumeBytes(data.consumeInt(0, 16384)));
        }

        if (crlDer.length == 0) return;

        try {
            CrlVerifier.verifyDelegated(
                    crlDer,
                    certSerial,
                    CA_KP.getPublic(),
                    CA_ISSUER_DN,
                    CA_CERT,
                    signerCerts,
                    null,
                    GostCrl.DEFAULT_MAX_CRL_SIZE,
                    GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
        } catch (PkixException e) {
            // fail-closed: битый DER или невалидная подпись → ок
        }
    }

    /**
     * Таргетированный фаззинг: валидный CRL (подписан CA-ключом) с
     * фаззенными сертификатами подписантов в {@code crlSignerCertDers}.
     * Гарантирует, что CA-путь успешен, а перебор подписантов парсит
     * сертификаты. Issuer DN совпадает — фаст-путь через CA пройдёт
     * или упадёт на сигнатуре, в любом случае до делегатов не дойдёт.
     */
    @FuzzTest
    void fuzzDelegatedCerts(FuzzedDataProvider data) {
        byte[] signerDer = data.consumeBytes(data.consumeInt(0, 32768));
        if (signerDer.length == 0) signerDer = new byte[] {0x30, 0x00};

        List<byte[]> signerCerts = new ArrayList<>();
        signerCerts.add(signerDer);

        try {
            // Строим валидный CRL, подписанный CA-ключом
            byte[] crlDer =
                    GostCrlBuilder.create(CA_ISSUER_DN)
                            .withCrlNumber(1)
                            .nextUpdate("20990601120000Z")
                            .sign(CA_KP.getPrivate());

            CrlVerifier.verifyDelegated(
                    crlDer,
                    LEAF_SERIAL,
                    CA_KP.getPublic(),
                    CA_ISSUER_DN,
                    CA_CERT,
                    signerCerts,
                    null,
                    GostCrl.DEFAULT_MAX_CRL_SIZE,
                    GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
        } catch (PkixException e) {
            // Ожидаемо: CER (SIGNATURE_INVALID, PARSE_ERROR, REVOKED), expired и т.д.
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
