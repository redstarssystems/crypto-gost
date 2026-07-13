package org.rssys.gost.crossval.cadest;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Одноразовый генератор ФИКСИРОВАННЫХ тестовых артефактов для семантической
 * кросс-валидации CAdES с КриптоПро (флаги -cadesbes/-cadest).
 *
 * <p>ПОЧЕМУ фиксированные ключи: флаги {@code -cadesbes/-cadest} требуют, чтобы
 * цепочка подписанта строилась до доверенного корня в хранилище КриптоПро.
 * Установка корня в {@code uRoot} требует ручного подтверждения thumbprint
 * через GUI. Чтобы устанавливать корень ОДИН раз (а не при каждом запуске тестов
 * со случайными ключами), CA-сертификат должен иметь стабильный отпечаток —
 * значит, детерминированный ключ.
 *
 * <p>Запуск (на ВМ или локально):
 * <pre>
 *   java -cp ... org.rssys.gost.crossval.cadest.CryptoproFixtureGenerator &lt;out-dir&gt;
 * </pre>
 * По умолчанию out-dir = {@code src/test/resources/cryptopro-fixtures}.
 * Создаёт: {@code ca.cer}, {@code leaf.cer} (DER). Приватные ключи — константы
 * ниже (тестовые, НЕ секретные).
 */
public final class CryptoproFixtureGenerator {

    // Тестовые приватные ключи (256-бит, tc26a256). НЕ секретны — только для
    // кросс-валидации. Фиксированы для стабильного thumbprint CA.
    private static final BigInteger CA_D = new BigInteger(
            "0A5C3E9F1B2D4A6C8E0F1234567890ABCDEF0123456789ABCDEF0123456789AB", 16);
    private static final BigInteger LEAF_D = new BigInteger(
            "0F2E3D4C5B6A79880F1E2D3C4B5A69780F1E2D3C4B5A69780F1E2D3C4B5A6978", 16);
    private static final BigInteger TSA_D = new BigInteger(
            "0B1C2D3E4F5A69780B1C2D3E4F5A69780B1C2D3E4F5A69780B1C2D3E4F5A6978", 16);

    static final String CA_DN = "CN=Crossval Test Root CA,O=crypto-gost,C=RU";
    static final String LEAF_DN = "CN=Crossval Test Leaf,O=crypto-gost,C=RU";
    static final String TSA_DN = "CN=Crossval Test TSA,O=crypto-gost,C=RU";

    static final String CA_NOT_BEFORE = "20250101000000Z";
    static final String CA_NOT_AFTER = "20450101000000Z";
    static final String LEAF_NOT_BEFORE = "20250101000000Z";
    static final String LEAF_NOT_AFTER = "20450101000000Z";

    private CryptoproFixtureGenerator() {}

    /** Выводит открытый ключ Q = d·G из приватного (как в KeyGenerator). */
    private static PublicKeyParameters derivePublic(PrivateKeyParameters key) {
        ECParameters p = key.getParams();
        ECPoint q = ECPoint.affine(p.gx, p.gy, p).multiply(key.getD()).normalize();
        return new PublicKeyParameters(q, p);
    }

    /** Восстанавливает CA-пару из фиксированного ключа. */
    static Fixture buildCa() {
        ECParameters p = ECParameters.tc26a256();
        PrivateKeyParameters caKey = new PrivateKeyParameters(CA_D, p);
        PublicKeyParameters caPub = derivePublic(caKey);
        byte[] caDn = GostDnParser.encodeDn(CA_DN);
        GostCertificate caCert = GostCertificateBuilder.create(p, caDn)
                .publicKey(caPub)
                .notBefore(CA_NOT_BEFORE)
                .notAfter(CA_NOT_AFTER)
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .basicConstraints(true, null)
                .serial(BigInteger.valueOf(1))
                .sign(caKey);
        return new Fixture(caKey, caPub, caCert);
    }

    /** Восстанавливает leaf-пару, подписанную CA, из фиксированного ключа. */
    static Fixture buildLeaf(Fixture ca) {
        ECParameters p = ECParameters.tc26a256();
        PrivateKeyParameters leafKey = new PrivateKeyParameters(LEAF_D, p);
        PublicKeyParameters leafPub = derivePublic(leafKey);
        byte[] leafDn = GostDnParser.encodeDn(LEAF_DN);
        byte[] caDn = GostDnParser.encodeDn(CA_DN);
        GostCertificate leafCert = GostCertificateBuilder.create(p, leafDn)
                .publicKey(leafPub)
                .issuerDn(caDn)
                .notBefore(LEAF_NOT_BEFORE)
                .notAfter(LEAF_NOT_AFTER)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .serial(BigInteger.valueOf(2))
                .sign(ca.key());
        return new Fixture(leafKey, leafPub, leafCert);
    }

    /**
     * Восстанавливает TSA-пару (Time-Stamping Authority), подписанную CA.
     *
     * <p>ПОЧЕМУ отдельный сертификат: КриптоПро в режиме {@code -cadest}
     * выполняет полную проверку метки времени и требует, чтобы TSA-сертификат
     * нёс EKU {@code id-kp-timeStamping} (RFC 3161 §2.3) и строил цепочку до
     * доверенного корня. Обычный leaf без этого EKU метку не подпишет корректно.
     */
    static Fixture buildTsa(Fixture ca) {
        ECParameters p = ECParameters.tc26a256();
        PrivateKeyParameters tsaKey = new PrivateKeyParameters(TSA_D, p);
        PublicKeyParameters tsaPub = derivePublic(tsaKey);
        byte[] tsaDn = GostDnParser.encodeDn(TSA_DN);
        byte[] caDn = GostDnParser.encodeDn(CA_DN);
        GostCertificate tsaCert = GostCertificateBuilder.create(p, tsaDn)
                .publicKey(tsaPub)
                .issuerDn(caDn)
                .notBefore(LEAF_NOT_BEFORE)
                .notAfter(LEAF_NOT_AFTER)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                .serial(BigInteger.valueOf(3))
                .sign(ca.key());
        return new Fixture(tsaKey, tsaPub, tsaCert);
    }

    /**
     * Строит пустой CRL, подписанный CA (никто не отозван).
     *
     * <p>ПОЧЕМУ нужен: в режиме {@code -cadesbes/-cadest} КриптоПро обязательно
     * проверяет статус отзыва и игнорирует {@code -norev}. Без CRL проверка
     * падает с {@code 0x800B010E} (revocation offline). Установленный CRL делает
     * статус «известным» — цепочка проходит проверку.
     */
    static byte[] buildCrl(Fixture ca) {
        return GostCrlBuilder.create(ca.cert().getSubjectDnBytes())
                .thisUpdate(CA_NOT_BEFORE)
                .nextUpdate(CA_NOT_AFTER)
                .withAki(ca.pub())
                .sign(ca.key());
    }

    public static void main(String[] args) throws Exception {
        Path outDir = Paths.get(args.length > 0 ? args[0]
                : "src/test/resources/cryptopro-fixtures");
        Files.createDirectories(outDir);

        Fixture ca = buildCa();
        Fixture leaf = buildLeaf(ca);

        Files.write(outDir.resolve("ca.cer"), ca.cert().getEncoded());
        Files.write(outDir.resolve("leaf.cer"), leaf.cert().getEncoded());
        Files.write(outDir.resolve("ca.crl"), buildCrl(ca));

        System.out.println("CA   DN: " + ca.cert().getSubjectDn());
        System.out.println("Leaf DN: " + leaf.cert().getSubjectDn());
        System.out.println("Written: " + outDir.resolve("ca.cer"));
        System.out.println("Written: " + outDir.resolve("leaf.cer"));
        System.out.println("Written: " + outDir.resolve("ca.crl"));
    }

    record Fixture(PrivateKeyParameters key, PublicKeyParameters pub,
                   GostCertificate cert) {}
}
