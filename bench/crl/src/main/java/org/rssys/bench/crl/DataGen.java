package org.rssys.bench.crl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.ReasonCode;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;

/**
 * Генерация синтетических CRL.
 *
 * <p>Запись: 16 октетов случайного серийного номера, дата отзыва и {@code reasonCode}; так выходит
 * около 50 байт на запись, как у настоящего CRL ФНС (≈49). Подпись ГОСТ 2012 на 256 бит, как у
 * ФНС. Проверяемый сертификат (лист) имеет небольшой серийный номер, которого нет в CRL.</p>
 */
final class DataGen {

    private static final String CA_DN = "CN=Bench CRL CA,O=Bench,C=RU";
    private static final String LEAF_DN = "CN=Bench Leaf,O=Bench,C=RU";
    private static final String REVOCATION_DATE = "260101000000Z";
    private static final String THIS_UPDATE = "261101000000Z";
    private static final String NEXT_UPDATE = "291101000000Z";
    private static final String CERT_NOT_BEFORE = "250101000000Z";
    private static final String CERT_NOT_AFTER = "350101000000Z";
    private static final int SERIAL_OCTETS = 16;
    private static final long LEAF_SERIAL = 1_234_567L;
    private static final ReasonCode[] REASONS = {
        ReasonCode.KEY_COMPROMISE,
        ReasonCode.AFFILIATION_CHANGED,
        ReasonCode.SUPERSEDED,
        ReasonCode.CESSATION_OF_OPERATION
    };

    /** Готовый набор: CRL, сертификат издателя и проверяемый сертификат. */
    record Built(byte[] crl, byte[] caDer, byte[] leafDer, PublicKeyParameters caKey) {}

    private DataGen() {}

    static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        String name = args[1];
        int entries = Integer.parseInt(args[2]);
        Files.createDirectories(dir);
        long t0 = System.nanoTime();
        Built built = build(entries);
        Files.write(dir.resolve("crl-" + name + CrlBench.CRL_SUFFIX), built.crl());
        Files.write(dir.resolve("crl-" + name + CrlBench.CA_SUFFIX), built.caDer());
        Files.write(dir.resolve("crl-" + name + CrlBench.LEAF_SUFFIX), built.leafDer());
        System.out.printf(
                "gen %s: записей=%d, размер=%d байт, байт на запись=%s, время=%s мс%n",
                name,
                entries,
                built.crl().length,
                entries == 0
                        ? "-"
                        : CrlBench.f1((double) built.crl().length / entries),
                CrlBench.f1(CrlBench.ms(System.nanoTime() - t0)));
    }

    /** Собирает CRL с заданным числом записей, в памяти. */
    static Built build(int entries) throws IOException {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        GostSigner signer = GostSigner.of(keys.getPrivate());

        GostCertificate ca =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(params, CA_DN)
                                .publicKey(keys.getPublic())
                                .issuerDn(CA_DN)
                                .notBefore(CERT_NOT_BEFORE)
                                .notAfter(CERT_NOT_AFTER)
                                .serial(BigInteger.ONE)
                                .buildTbs(),
                        signer);
        GostCertificate leaf =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(params, LEAF_DN)
                                .publicKey(keys.getPublic())
                                .issuerDn(CA_DN)
                                .notBefore(CERT_NOT_BEFORE)
                                .notAfter(CERT_NOT_AFTER)
                                .serial(BigInteger.valueOf(LEAF_SERIAL))
                                .buildTbs(),
                        signer);

        List<RevokedEntry> list = new ArrayList<>(entries);
        for (int i = 0; i < entries; i++) {
            byte[] serial = new byte[SERIAL_OCTETS];
            CryptoRandom.INSTANCE.nextBytes(serial);
            // Старший бит сброшен, первый октет ненулевой: INTEGER ровно в 16 октетов без
            // ведущего нуля знака, как у настоящих УЦ
            serial[0] = (byte) ((serial[0] & 0x7F) | 0x01);
            list.add(
                    new RevokedEntry(
                            serial, REVOCATION_DATE, REASONS[i % REASONS.length], null, null));
        }
        byte[] crl =
                GostCrlBuilder.create(CA_DN)
                        .thisUpdate(THIS_UPDATE)
                        .nextUpdate(NEXT_UPDATE)
                        .withCrlNumber(1)
                        .withAki(keys.getPublic())
                        .addRevoked(list)
                        .sign(signer);
        return new Built(crl, ca.getEncoded(), leaf.getEncoded(), keys.getPublic());
    }
}
