package org.rssys.gost.crossval.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.signature.ECParameters;

/**
 * КриптоПро {@code certmgr -list -crl -file}: читает CRL, выпущенный библиотекой.
 *
 * <p>Это проверка разбора, а не подписи: {@code -list} показывает содержимое CRL и подпись, судя
 * по выводу, не проверяет. Поэтому утверждать «КриптоПро проверил CRL» нельзя, только «КриптоПро
 * разобрал CRL, выпущенный библиотекой». Контейнеры тест не создаёт, движение мыши не требуется.</p>
 */
@DisplayName("Кросс-валидация CRL: библиотека -> КриптоПро certmgr (чтение)")
class CertmgrCrlReadCrossValidationTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    static boolean certmgrAvailable() {
        return Files.isExecutable(Path.of(CryptoProChecker.resolveCertmgrBinary()));
    }

    @Test
    @EnabledIf("certmgrAvailable")
    @DisplayName("certmgr читает CRL библиотеки: издатель, номер CRL и число записей")
    void certmgrReadsLibraryCrl() throws Exception {
        TempDirUtils.withTempDir(
                "crl-certmgr-",
                dir -> {
                    KeyPair caKp = KeyGenerator.generateKeyPair(PARAMS);
                    byte[] issuerDn = GostDnParser.encodeDn("CN=Certmgr Read CA,O=Test,C=RU");
                    byte[] crlDer =
                            GostCrlBuilder.create(issuerDn)
                                    .thisUpdate("20260101000000Z")
                                    .nextUpdate("20990101000000Z")
                                    .withCrlNumber(BigInteger.valueOf(7))
                                    .addRevoked(new byte[] {0x11}, "20260102000000Z")
                                    .addRevoked(new byte[] {0x12}, "20260103000000Z")
                                    .addRevoked(new byte[] {0x13}, "20260104000000Z")
                                    .sign(caKp.getPrivate());
                    Path crlPath = dir.resolve("library.crl");
                    Files.write(crlPath, crlDer);

                    CryptoProChecker.Result result =
                            CryptoProChecker.runResult(
                                    CryptoProChecker.resolveCertmgrBinary(),
                                    "-list",
                                    "-crl",
                                    "-file",
                                    crlPath.toString());

                    assertEquals(0, result.exitCode(), "certmgr должен разобрать CRL: " + result.output());
                    assertTrue(
                            result.output().contains("Certmgr Read CA"),
                            "В выводе должен быть издатель: " + result.output());
                    assertTrue(
                            result.output().contains("0x07"),
                            "В выводе должен быть номер CRL: " + result.output());
                    assertTrue(
                            result.output().matches("(?s).*:\\s*3\\s*\\R.*"),
                            "В выводе должно быть число записей 3: " + result.output());
                    return null;
                });
    }
}
