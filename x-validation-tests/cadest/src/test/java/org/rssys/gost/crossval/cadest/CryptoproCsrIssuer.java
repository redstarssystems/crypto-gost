package org.rssys.gost.crossval.cadest;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCsrParser;
import org.rssys.gost.signature.ECParameters;

/**
 * Инструмент получения векторов КриптоПро: выпускает сертификат подписанта по CSR, который
 * создал {@code cryptcp -createrqst}. Закрытый ключ остаётся в контейнере КриптоПро, в
 * репозиторий попадает только сертификат.
 *
 * <p>Использование: {@code <запрос.req> <сертификат.cer> <серийный номер> <каталог состояния>}.
 * Каталог состояния общий с {@link CryptoproIntermediateVectorTool}, чтобы корень совпадал
 * побайтно. Подписант выпускается самим корнем: в сертификате нет ссылок на OCSP и CRL, поэтому
 * проверка цепочки идёт без обращения к сети ({@code -norev -nonet}) и сервер не нужен.
 */
public final class CryptoproCsrIssuer {

    private static final int ARGUMENT_COUNT = 4;

    private CryptoproCsrIssuer() {}

    public static void main(String[] args) throws Exception {
        if (args.length != ARGUMENT_COUNT) {
            System.out.println(
                    "Использование: <запрос.req> <сертификат.cer>"
                            + " <серийный номер> <каталог состояния>");
            return;
        }
        byte[] request = Files.readAllBytes(Paths.get(args[0]));
        Path output = Paths.get(args[1]);
        GostCertificate certificate = issue(request, new BigInteger(args[2]), Paths.get(args[3]));
        Files.write(output, certificate.getEncoded());
        System.out.println("Сертификат " + certificate.getSubjectDn() + " записан в " + output);
    }

    /** Выпускает сертификат подписи по запросу; кривая УЦ не обязана совпадать с кривой ключа. */
    static GostCertificate issue(byte[] requestDer, BigInteger serial, Path stateDir)
            throws Exception {
        CryptoproFixtureGenerator.Fixture issuer =
                new CryptoproIntermediateFixtures(stateDir).root();
        GostCsrParser csr = GostCsrParser.fromDer(requestDer);
        return GostCertificateBuilder.fromCsrIdentity(csr, ECParameters.tc26a256())
                .issuerDn(issuer.cert().getSubjectDnBytes())
                .notBefore(CryptoproFixtureGenerator.LEAF_NOT_BEFORE)
                .notAfter(CryptoproFixtureGenerator.LEAF_NOT_AFTER)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .ski()
                .aki(issuer.cert().getPublicKey())
                .serial(serial)
                .sign(issuer.key());
    }
}
