package org.rssys.gost.crossval.cadest;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Фиксированная иерархия тестовых УЦ для вектора «промежуточные УЦ + CRL»:
 * корень {@link CryptoproFixtureGenerator#buildCa()} выпускает два промежуточных УЦ,
 * по одному на цепочку подписанта и цепочку службы штампов времени.
 *
 * <p>Источники отзыва разведены по звеньям намеренно: у листа подписанта только OCSP,
 * у промежуточных УЦ только CRL корня, у службы штампов OCSP и CRL своего УЦ. Иначе КриптоПро
 * выберет иной источник, и вектор потеряет проверяемую форму. Ключи тестовые, не секретные;
 * корень не меняется, чтобы не менялся отпечаток, установленный в доверенных корнях КриптоПро.
 */
final class CryptoproIntermediateFixtures {

    /** Порт локального сервера TSA/OCSP/CRL. */
    static final int SERVER_PORT = 18080;

    static final String SERVER_BASE_URL = "http://127.0.0.1:" + SERVER_PORT;
    static final String TSP_PATH = "/tsp";
    static final String OCSP_PATH = "/ocsp";
    static final String ROOT_CRL_PATH = "/crl/root.crl";
    static final String TSA_CA_CRL_PATH = "/crl/tsa-ca.crl";

    static final String SIGNER_CA_DN = "CN=Crossval Signer CA,O=crypto-gost,C=RU";
    static final String TSA_CA_DN = "CN=Crossval TSA CA,O=crypto-gost,C=RU";
    static final String SIGNER_DN = "CN=Crossval Intermediate Signer,O=crypto-gost,C=RU";
    static final String TSA_DN = "CN=Crossval Intermediate TSA,O=crypto-gost,C=RU";
    static final String SIGNER_OCSP_DN = "CN=Crossval Signer CA OCSP,O=crypto-gost,C=RU";
    static final String TSA_OCSP_DN = "CN=Crossval TSA CA OCSP,O=crypto-gost,C=RU";

    static final BigInteger SIGNER_CA_SERIAL = BigInteger.valueOf(11);
    static final BigInteger TSA_CA_SERIAL = BigInteger.valueOf(12);
    static final BigInteger SIGNER_SERIAL = BigInteger.valueOf(13);
    static final BigInteger TSA_SERIAL = BigInteger.valueOf(14);
    static final BigInteger SIGNER_OCSP_SERIAL = BigInteger.valueOf(15);
    static final BigInteger TSA_OCSP_SERIAL = BigInteger.valueOf(16);

    private static final BigInteger SIGNER_CA_D =
            new BigInteger("0D3E4F5A6B7C89900D3E4F5A6B7C89900D3E4F5A6B7C89900D3E4F5A6B7C8990", 16);
    private static final BigInteger TSA_CA_D =
            new BigInteger("0E4F5A6B7C8D9AA10E4F5A6B7C8D9AA10E4F5A6B7C8D9AA10E4F5A6B7C8D9AA1", 16);
    private static final BigInteger SIGNER_D =
            new BigInteger("0F5A6B7C8D9EABB20F5A6B7C8D9EABB20F5A6B7C8D9EABB20F5A6B7C8D9EABB2", 16);
    private static final BigInteger TSA_D =
            new BigInteger("105A6B7C8D9EABC3105A6B7C8D9EABC3105A6B7C8D9EABC3105A6B7C8D9EABC3", 16);
    private static final BigInteger SIGNER_OCSP_D =
            new BigInteger("115B6C7D8E9FBCD4115B6C7D8E9FBCD4115B6C7D8E9FBCD4115B6C7D8E9FBCD4", 16);
    private static final BigInteger TSA_OCSP_D =
            new BigInteger("126C7D8E9FA0CDE5126C7D8E9FA0CDE5126C7D8E9FA0CDE5126C7D8E9FA0CDE5", 16);

    private static final String NOT_BEFORE = CryptoproFixtureGenerator.LEAF_NOT_BEFORE;
    private static final String NOT_AFTER = CryptoproFixtureGenerator.LEAF_NOT_AFTER;

    private static final String ROOT_RESOURCE = "/cryptopro-fixtures/ca.cer";

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private final Path stateDir;
    private final CryptoproFixtureGenerator.Fixture root;
    private final CryptoproFixtureGenerator.Fixture signerCa;
    private final CryptoproFixtureGenerator.Fixture tsaCa;
    private final CryptoproFixtureGenerator.Fixture signer;
    private final CryptoproFixtureGenerator.Fixture tsa;
    private final CryptoproFixtureGenerator.Fixture signerOcsp;
    private final CryptoproFixtureGenerator.Fixture tsaOcsp;

    /**
     * @param stateDir каталог, где сертификаты хранятся между запусками: подпись ГОСТ
     *     недетерминирована, и без хранения {@code prepare} и {@code serve} получили бы
     *     сертификаты с одинаковыми ключами, но разным DER
     */
    CryptoproIntermediateFixtures(Path stateDir) {
        this.stateDir = stateDir;
        root = loadRoot();
        signerCa = intermediateCa(SIGNER_CA_D, SIGNER_CA_DN, SIGNER_CA_SERIAL, "signer-ca.cer");
        tsaCa = intermediateCa(TSA_CA_D, TSA_CA_DN, TSA_CA_SERIAL, "tsa-ca.cer");
        signer =
                leaf(SIGNER_D, SIGNER_DN, SIGNER_SERIAL, signerCa, "signer.cer")
                        // у листа только OCSP: CRL-источника нет намеренно
                        .ocspResponder(SERVER_BASE_URL + OCSP_PATH)
                        .build();
        signerOcsp =
                delegatedResponder(
                        SIGNER_OCSP_D,
                        SIGNER_OCSP_DN,
                        SIGNER_OCSP_SERIAL,
                        signerCa,
                        "signer-ocsp.cer");
        tsaOcsp =
                delegatedResponder(TSA_OCSP_D, TSA_OCSP_DN, TSA_OCSP_SERIAL, tsaCa, "tsa-ocsp.cer");
        tsa =
                leaf(TSA_D, TSA_DN, TSA_SERIAL, tsaCa, "tsa.cer")
                        .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                        .ocspResponder(SERVER_BASE_URL + OCSP_PATH)
                        .crlDistributionPoints(SERVER_BASE_URL + TSA_CA_CRL_PATH)
                        .build();
    }

    /**
     * Корень берётся из закоммиченного {@code ca.cer}, а не строится заново: его отпечаток
     * установлен в доверенных корнях КриптоПро, а перевыпуск даёт другой DER.
     */
    private static CryptoproFixtureGenerator.Fixture loadRoot() {
        try (InputStream in =
                CryptoproIntermediateFixtures.class.getResourceAsStream(ROOT_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Root resource not found: " + ROOT_RESOURCE);
            }
            GostCertificate cert = new GostCertificate(in.readAllBytes());
            CryptoproFixtureGenerator.Fixture generated = CryptoproFixtureGenerator.buildCa();
            return new CryptoproFixtureGenerator.Fixture(generated.key(), generated.pub(), cert);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Читает сертификат из каталога состояния или выпускает и сохраняет. */
    private GostCertificate cached(String fileName, Supplier<GostCertificate> issue) {
        Path file = stateDir.resolve(fileName);
        try {
            if (Files.exists(file)) {
                return new GostCertificate(Files.readAllBytes(file));
            }
            GostCertificate cert = issue.get();
            Files.createDirectories(stateDir);
            Files.write(file, cert.getEncoded());
            return cert;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    CryptoproFixtureGenerator.Fixture root() {
        return root;
    }

    CryptoproFixtureGenerator.Fixture signerCa() {
        return signerCa;
    }

    CryptoproFixtureGenerator.Fixture tsaCa() {
        return tsaCa;
    }

    CryptoproFixtureGenerator.Fixture signer() {
        return signer;
    }

    CryptoproFixtureGenerator.Fixture tsa() {
        return tsa;
    }

    CryptoproFixtureGenerator.Fixture signerOcspResponder() {
        return signerOcsp;
    }

    CryptoproFixtureGenerator.Fixture tsaOcspResponder() {
        return tsaOcsp;
    }

    /** Промежуточный УЦ: только CRL корня, без OCSP, чтобы CRL попал в revocationValues. */
    private CryptoproFixtureGenerator.Fixture intermediateCa(
            BigInteger d, String dn, BigInteger serial, String fileName) {
        PrivateKeyParameters key = new PrivateKeyParameters(d, PARAMS);
        PublicKeyParameters pub = CryptoproFixtureGenerator.derivePublic(key);
        GostCertificate cert =
                cached(
                        fileName,
                        () ->
                                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn(dn))
                                        .publicKey(pub)
                                        .issuerDn(root.cert().getSubjectDnBytes())
                                        .notBefore(NOT_BEFORE)
                                        .notAfter(NOT_AFTER)
                                        .keyUsage(
                                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                                        .basicConstraints(true, null)
                                        .crlDistributionPoints(SERVER_BASE_URL + ROOT_CRL_PATH)
                                        .ski()
                                        .aki(root.pub())
                                        .serial(serial)
                                        .sign(root.key()));
        return new CryptoproFixtureGenerator.Fixture(key, pub, cert);
    }

    private LeafSpec leaf(
            BigInteger d,
            String dn,
            BigInteger serial,
            CryptoproFixtureGenerator.Fixture issuer,
            String fileName) {
        return new LeafSpec(d, dn, serial, issuer, fileName);
    }

    private CryptoproFixtureGenerator.Fixture delegatedResponder(
            BigInteger d,
            String dn,
            BigInteger serial,
            CryptoproFixtureGenerator.Fixture issuer,
            String fileName) {
        PrivateKeyParameters key = new PrivateKeyParameters(d, PARAMS);
        PublicKeyParameters pub = CryptoproFixtureGenerator.derivePublic(key);
        GostCertificate cert =
                cached(
                        fileName,
                        () ->
                                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn(dn))
                                        .publicKey(pub)
                                        .issuerDn(issuer.cert().getSubjectDnBytes())
                                        .notBefore(NOT_BEFORE)
                                        .notAfter(NOT_AFTER)
                                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                                        .extendedKeyUsage(true, GostOids.EXT_OCSP_SIGNING)
                                        .ocspNoCheck()
                                        .ski()
                                        .aki(issuer.pub())
                                        .serial(serial)
                                        .sign(issuer.key()));
        return new CryptoproFixtureGenerator.Fixture(key, pub, cert);
    }

    /** Заготовка листового сертификата: расширения источников отзыва задаёт вызывающий. */
    private final class LeafSpec {
        private final PrivateKeyParameters key;
        private final PublicKeyParameters pub;
        private final GostCertificateBuilder builder;
        private final CryptoproFixtureGenerator.Fixture issuer;
        private final String fileName;

        LeafSpec(
                BigInteger d,
                String dn,
                BigInteger serial,
                CryptoproFixtureGenerator.Fixture issuer,
                String fileName) {
            this.fileName = fileName;
            this.key = new PrivateKeyParameters(d, PARAMS);
            this.pub = CryptoproFixtureGenerator.derivePublic(key);
            this.issuer = issuer;
            this.builder =
                    GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn(dn))
                            .publicKey(pub)
                            .issuerDn(issuer.cert().getSubjectDnBytes())
                            .notBefore(NOT_BEFORE)
                            .notAfter(NOT_AFTER)
                            .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                            .ski()
                            .aki(issuer.pub())
                            .serial(serial);
        }

        LeafSpec ocspResponder(String uri) {
            builder.ocspResponder(uri);
            return this;
        }

        LeafSpec crlDistributionPoints(String... uris) {
            builder.crlDistributionPoints(uris);
            return this;
        }

        LeafSpec extendedKeyUsage(boolean critical, String oid) {
            builder.extendedKeyUsage(critical, oid);
            return this;
        }

        CryptoproFixtureGenerator.Fixture build() {
            return new CryptoproFixtureGenerator.Fixture(
                    key, pub, cached(fileName, () -> builder.sign(issuer.key())));
        }
    }
}
