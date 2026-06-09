package org.rssys.gost.crossval.tls13;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.*;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.concurrent.TimeUnit;


final class OpenSslTls13Helper {

    private static String[] cachedTls13Flags;
    private static String[] cachedTls13ProviderOnly;
    private static String cachedConfigPath;

    private OpenSslTls13Helper() {}

    /**
     * Определяет флаги провайдера и OPENSSL_CONF для TLS 1.3 патченого OpenSSL.
     * Возвращает массив флагов (может быть пустым если используется config-файл).
     */
    static String[] resolveTls13Flags() {
        if (cachedTls13Flags != null) return cachedTls13Flags;

        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String root = OpenSslChecker.resolveOpenSslRoot();

        // Ищем openssl-gost.cnf рядом с бинарником
        if (!root.isEmpty()) {
            Path configPath = Paths.get(root, "ssl", "openssl-gost.cnf");
            if (Files.exists(configPath)) {
                cachedConfigPath = configPath.toString();
                cachedTls13Flags = new String[0];
                return cachedTls13Flags;
            }
        }

        // Пробуем -provider gost (стандартный gost-engine)
        if (testFlags(openssl, new String[]{"-provider", "gost", "-provider", "default"})) {
            cachedTls13Flags = new String[]{"-provider", "gost", "-provider", "default"};
            return cachedTls13Flags;
        }

        // Пробуем -provider gostprov (OpenSSL 3.6 + патч)
        if (testFlags(openssl, new String[]{"-provider", "gostprov", "-provider", "default"})) {
            cachedTls13Flags = new String[]{"-provider", "gostprov", "-provider", "default"};
            return cachedTls13Flags;
        }

        // Пробуем с -provider-path (Debian-style)
        if (!root.isEmpty()) {
            Path osslModules = Paths.get(root, "lib", "ossl-modules");
            if (Files.isDirectory(osslModules)) {
                String[] candidate = new String[]{
                        "-provider-path", osslModules.toString(),
                        "-provider", "gostprov", "-provider", "default"};
                if (testFlags(openssl, candidate)) {
                    cachedTls13Flags = candidate;
                    return cachedTls13Flags;
                }
            }
        }

        // Fallback: engine
        cachedTls13Flags = new String[]{"-engine", "gost"};
        return cachedTls13Flags;
    }

    /**
     * Возвращает только часть провайдера (без -provider-path) для assume-проверок.
     * Так как assume запускает openssl ciphers, а не genpkey/s_client.
     */
    private static String[] resolveAssumeFlags() {
        if (cachedTls13ProviderOnly != null) return cachedTls13ProviderOnly;
        String[] full = resolveTls13Flags();
        if (full.length == 0) {
            cachedTls13ProviderOnly = full;
            return full;
        }
        // Убираем -provider-path если есть
        java.util.ArrayList<String> list = new java.util.ArrayList<>();
        for (int i = 0; i < full.length; i++) {
            if (full[i].equals("-provider-path")) {
                i++; // пропускаем значение
            } else {
                list.add(full[i]);
            }
        }
        cachedTls13ProviderOnly = list.toArray(new String[0]);
        return cachedTls13ProviderOnly;
    }

    /** Проверяет, что openssl понимает GOST TLS 1.3 cipher suite с данными флагами. */
    private static boolean testFlags(String openssl, String[] flags) {
        try {
            String[] cmd = CrossValUtils.concat(
                    new String[]{openssl, "ciphers", "-s", "-tls1_3",
                            "-ciphersuites", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"},
                    flags
            );
            Process p = new ProcessBuilder(cmd).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return out.contains("TLS_GOSTR341112");
        } catch (Exception e) {
            return false;
        }
    }

    static int findFreePort() throws IOException {
        try (ServerSocket ss = new ServerSocket(0)) {
            return ss.getLocalPort();
        }
    }

    static void assumeGostTls13() {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] flags = resolveAssumeFlags();

        try {
            String[] cmd = CrossValUtils.concat(
                    new String[]{openssl, "ciphers", "-s", "-tls1_3",
                            "-ciphersuites", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"},
                    flags
            );
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            int code = p.waitFor();
            assertTrue(code == 0 && out.contains("TLS_GOSTR341112"),
                    "OpenSSL не поддерживает GOST TLS 1.3 cipher suite — пропуск");
        } catch (Exception e) {
            fail("Проверка GOST TLS 1.3 не удалась: " + e.getMessage());
        }
    }

    static Process startSClient(int port, String ciphersuite, String curves,
                                String... extraArgs) throws IOException {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] providerFlags = resolveTls13Flags();

        String[] cmd = CrossValUtils.concat(
                new String[]{openssl, "s_client", "-connect", "127.0.0.1:" + port,
                        "-tls1_3", "-ciphersuites", ciphersuite, "-curves", curves,
                        "-servername", "example.com", "-ign_eof"},
                providerFlags,
                extraArgs
        );

        return startProcess(cmd);
    }

    static String runSClientWithHttpGet(int port, String ciphersuite, String curves,
                                        long timeoutMs, String... extraArgs) throws Exception {
        Process client = startSClient(port, ciphersuite, curves, extraArgs);
        try {
            OutputStream stdin = client.getOutputStream();
            stdin.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            stdin.close();
            return readOutput(client, timeoutMs);
        } finally {
            destroyProcess(client);
        }
    }

    static String runSClientWithData(int port, String ciphersuite, String curves,
                                     byte[] data, long timeoutMs, String... extraArgs) throws Exception {
        Process client = startSClient(port, ciphersuite, curves, extraArgs);
        try {
            OutputStream stdin = client.getOutputStream();
            stdin.write(data);
            stdin.flush();
            stdin.close();
            return readOutput(client, timeoutMs);
        } finally {
            destroyProcess(client);
        }
    }

    static Process startSServer(int port, String ciphersuite, String curves,
                                 Path tmpDir) throws Exception {
        generateGostCert(tmpDir);
        return startSServer(port, ciphersuite, curves,
                tmpDir.resolve("cert.pem").toString(),
                tmpDir.resolve("key.pem").toString());
    }

    static Process startSServer(int port, String ciphersuite, String curves,
                                 String certPem, String keyPem,
                                 String... extraArgs) throws IOException {
        String openssl = OpenSslChecker.resolveOpenSslBinary();
        String[] providerFlags = resolveTls13Flags();

        String[] cmd = CrossValUtils.concat(
                new String[]{openssl, "s_server", "-accept", String.valueOf(port),
                        "-tls1_3", "-ciphersuites", ciphersuite, "-curves", curves,
                        "-cert", certPem, "-key", keyPem, "-www"},
                providerFlags,
                extraArgs
        );

        return startProcess(cmd);
    }

    private static Process startProcess(String[] cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
        return pb.start();
    }

    static boolean waitForString(Process process, String expected, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        while (System.currentTimeMillis() < deadline) {
            while (reader.ready()) {
                String line = reader.readLine();
                if (line != null && line.contains(expected)) return true;
            }
            if (!process.isAlive()) {
                return false;
            }
            Thread.sleep(50);
        }
        return false;
    }

    static String readOutput(Process process, long timeoutMs) throws Exception {
        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            throw new RuntimeException("Process timed out after " + timeoutMs + "ms");
        }
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    static void generateGostCert(Path tmpDir) throws Exception {
        generateGostCert(tmpDir, "gost2012_256", "A");
    }

    static void generateGostCert(Path tmpDir, String algo, String paramset) throws Exception {
        generateGostCert(tmpDir, algo, paramset, (String) null);
    }

    static void generateGostCert(Path tmpDir, String algo, String paramset, String ekuOid) throws Exception {
        Path keyDer = tmpDir.resolve("key.der");
        Path keyPem = tmpDir.resolve("key.pem");
        Path certPem = tmpDir.resolve("cert.pem");
        String[] flags = resolveTls13Flags();

        exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "genpkey"},
                flags,
                new String[]{"-algorithm", algo,
                        "-pkeyopt", "paramset:" + paramset,
                        "-outform", "DER",
                        "-out", keyDer.toString()}));

        exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "pkey"},
                flags,
                new String[]{"-in", keyDer.toString(), "-inform", "DER",
                        "-out", keyPem.toString()}));

        String[] reqArgs = ekuOid != null
                ? new String[]{"-addext", "extendedKeyUsage=OID:" + ekuOid}
                : new String[0];
        exec(CrossValUtils.concat(
                new String[]{OpenSslChecker.resolveOpenSslBinary(), "req", "-new", "-x509"},
                flags,
                new String[]{"-key", keyPem.toString(),
                        "-out", certPem.toString(),
                        "-subj", "/CN=TestServer",
                        "-days", "365",
                        "-config", "/dev/null"},
                reqArgs));
    }

    /**
     * Генерирует PKI для mTLS через Java API.
     * Сервер пакуется в PFX через OpenSSL pkcs12 -export (проверка wire-формата).
     * Клиентский сертификат НЕ генерируется — тест создаёт самоподписанный отдельно.
     */
    static MtlsPkiResult generateMtlsPKI(Path tmpDir, String algo, String paramset) throws Exception {
        ECParameters params = toECParameters(algo, paramset);

        // CA: Java
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);

        // Сервер: CA-подписанный
        TlsTestHelper.CertBundle srv = TlsTestHelper.createCertSignedBy(
                params,
                ca.priv, ca.cert.getPublicKey(), ca.subjectDn,
                "20240101120000Z", "21060101120000Z",
                null, null, null, null, false, null);

        // PEM-файлы для OpenSSL pkcs12 -export
        Path srvCertPem = tmpDir.resolve("server-cert.pem");
        Path srvKeyPem  = tmpDir.resolve("server-key.pem");
        Path caCertPem  = tmpDir.resolve("ca-cert.pem");
        Path srvPfx     = tmpDir.resolve("server.pfx");

        Files.writeString(srvCertPem, srv.cert.toPem());
        Files.writeString(caCertPem,  ca.cert.toPem());
        Files.writeString(srvKeyPem,  privateKeyToPem(GostDerCodec.encodePrivateKey(srv.priv)));

        // PFX: OpenSSL pkcs12 -export (проверка wire-формата)
        String[] flags = resolveTls13Flags();
        exec(CrossValUtils.concat(new String[]{OpenSslChecker.resolveOpenSslBinary(), "pkcs12", "-export"}, flags,
                new String[]{"-inkey", srvKeyPem.toString(), "-in", srvCertPem.toString(),
                        "-certfile", caCertPem.toString(), "-out", srvPfx.toString(),
                        "-passout", "pass:mtls"}));

        return new MtlsPkiResult(
                Files.readAllBytes(srvPfx), "mtls".toCharArray(),
                null, null);
    }

    /** PEM-обёртка приватного ключа: PKCS#8 DER → -----BEGIN PRIVATE KEY-----. */
    static String privateKeyToPem(byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    private static ECParameters toECParameters(String algo, String paramset) {
        if ("gost2012_256".equals(algo) && "A".equals(paramset)) return ECParameters.cryptoProA();
        if ("gost2012_512".equals(algo) && "A".equals(paramset)) return ECParameters.tc26a512();
        if ("gost2012_512".equals(algo) && "B".equals(paramset)) return ECParameters.tc26b512();
        throw new IllegalArgumentException("Unknown algo+paramset: " + algo + " " + paramset);
    }

    static final class MtlsPkiResult {
        final byte[] serverPfx;
        final char[] password;
        final String clientCertPem;
        final String clientKeyPem;

        MtlsPkiResult(byte[] serverPfx, char[] password,
                      String clientCertPem, String clientKeyPem) {
            this.serverPfx = serverPfx;
            this.password = password;
            this.clientCertPem = clientCertPem;
            this.clientKeyPem = clientKeyPem;
        }
    }

    static void exec(String... cmd) throws Exception {
        OpenSslChecker.exec(cmd);
    }

    static void destroyProcess(Process process) {
        if (process != null) {
            process.destroyForcibly();
            try { process.waitFor(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
