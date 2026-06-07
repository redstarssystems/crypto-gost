package org.rssys.gost.crossval.pkcs12;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.nio.file.Files;
import java.nio.file.Path;

final class OpenSslPkcs12Helper {

    private static final String OPENSSL_BIN = OpenSslChecker.resolveOpenSslBinary();

    private OpenSslPkcs12Helper() {}

    record PfxBundle(byte[] pfx, byte[] privateKeyDer) {}

    static PfxBundle buildPfxWithKey(Path tmpDir, String algo,
                                     String paramset, String password) throws Exception {
        Path keyDerFile  = tmpDir.resolve("key.der");
        Path keyPemFile  = tmpDir.resolve("key.pem");
        Path certFile    = tmpDir.resolve("cert.pem");
        Path pfxFile     = tmpDir.resolve("out.pfx");

        String[] eng = OpenSslChecker.resolveEngineFlag();

        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "genpkey"},
            eng,
            new String[]{"-algorithm", algo,
                         "-pkeyopt", "paramset:" + paramset,
                         "-outform", "DER",
                         "-out", keyDerFile.toString()}));

        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "pkey"},
            eng,
            new String[]{"-in", keyDerFile.toString(), "-inform", "DER",
                         "-out", keyPemFile.toString()}));

        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "req", "-new", "-x509"},
            eng,
            new String[]{"-key", keyPemFile.toString(),
                         "-out", certFile.toString(),
                         "-subj", "/CN=crossval",
                         "-days", "3650",
                         "-config", "/dev/null"}));

        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "pkcs12", "-export"},
            eng,
            new String[]{"-inkey",  keyPemFile.toString(),
                         "-in",     certFile.toString(),
                         "-out",    pfxFile.toString(),
                         "-passout", "pass:" + password}));

        return new PfxBundle(
            Files.readAllBytes(pfxFile),
            Files.readAllBytes(keyDerFile)
        );
    }

    /**
     * Проверяет, что OpenSSL может разобрать структуру PFX-файла.
     * Использует -nomacver, так как gost-engine при -export генерирует MAC
     * на старом алгоритме MD и кросс-верификация HMAC-Streebog-512 работает
     * не во всех версиях. MAC верификация выполняется нашим
     * GostPkcs12Mac.verify() в самом тесте.
     * <p>
     * Не выполняет извлечение ключа/сертификата через OpenSSL, так как
     * gost-provider может не поддерживать разбор PBES2-GOST-параметров.
     * Полный roundtrip проверяется через GostPkcs12Loader.
     */
    static void verifyPfxStructureWithOpenSsl(Path pfxFile, String password) throws Exception {
        String[] eng = OpenSslChecker.resolveEngineFlag();

        // Проверяем, что OpenSSL может разобрать PFX без ошибок структуры
        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "pkcs12", "-in", pfxFile.toString(),
                         "-passin", "pass:" + password,
                         "-nokeys", "-nocerts", "-nomacver", "-noout"},
            eng));

        // -info выводит метаданные контейнера
        exec(CrossValUtils.concat(
            new String[]{OPENSSL_BIN, "pkcs12", "-in", pfxFile.toString(),
                         "-passin", "pass:" + password,
                         "-nomacver", "-info", "-noout"},
            eng));
    }

    static void exec(String... cmd) throws Exception {
        OpenSslChecker.exec(cmd);
    }


}
