package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Проверка доступности OpenSSL с необходимыми возможностями.
 * Все методы — {@code static void assume*()}: при недоступности прерывают тест (abort/skip).
 */
public final class OpenSslChecker {

    private static volatile String cachedOpenSslBinary;
    private static String[] cachedEngineFlag;
    private static String[] cachedTls13Flags;
    private static String[] cachedTls13AssumeFlags;
    private static volatile String cachedConfigPath;

    private OpenSslChecker() {}

    /**
     * Возвращает корневую директорию openssl (родитель bin/).
     * Например, для /opt/openssl/bin/openssl -> /opt/openssl.
     */
    public static String resolveOpenSslRoot() {
        String binary = resolveOpenSslBinary();
        if (!binary.contains(File.separator)) return "";
        Path binPath = Path.of(binary).toAbsolutePath().normalize();
        Path parent = binPath.getParent();
        if (parent != null && parent.getFileName().toString().equals("bin")) {
            return parent.getParent().toString();
        }
        return parent != null ? parent.toString() : "";
    }

    /**
     * Возвращает переменные окружения для кастомного openssl.
     * Если openssl из PATH — пустая мапа.
     */
    public static Map<String, String> getOpenSslEnv() {
        Map<String, String> env = new HashMap<>();
        String root = resolveOpenSslRoot();
        if (root.isEmpty()) return env;

        String libPath = Paths.get(root, "lib").toString();
        String ldPath = System.getenv("LD_LIBRARY_PATH");
        env.put("LD_LIBRARY_PATH", ldPath != null ? libPath + ":" + ldPath : libPath);
        env.put("OPENSSL_MODULES", Paths.get(root, "lib", "ossl-modules").toString());

        if (cachedConfigPath != null) {
            env.put("OPENSSL_CONF", cachedConfigPath);
        } else {
            Path configPath = Paths.get(root, "ssl", "openssl-gost.cnf");
            if (Files.exists(configPath)) {
                cachedConfigPath = configPath.toString();
                env.put("OPENSSL_CONF", cachedConfigPath);
            }
        }
        return env;
    }

    /**
     * Возвращает путь к бинарнику openssl.
     * <p>
     * Сначала проверяет системное свойство {@code openssl.binary},
     * затем переменную окружения {@code OPENSSL_BIN},
     * затем probe на {@code ~/bin/bin/openssl} (патченая сборка разработчика),
     * иначе — {@code "openssl"} из PATH.
     * Результат кешируется.
     */
    public static String resolveOpenSslBinary() {
        if (cachedOpenSslBinary != null) return cachedOpenSslBinary;
        String override = System.getProperty("openssl.binary");
        if (override != null && !override.isEmpty()) {
            cachedOpenSslBinary = override;
        } else {
            String env = System.getenv("OPENSSL_BIN");
            if (env != null && !env.isEmpty()) {
                cachedOpenSslBinary = env;
            } else {
                Path probe = Path.of("/opt/openssl-3.6.0-gost/bin/openssl");
                if (Files.isExecutable(probe)) {
                    cachedOpenSslBinary = probe.toAbsolutePath().toString();
                } else {
                    cachedOpenSslBinary = "openssl";
                }
            }
        }
        return cachedOpenSslBinary;
    }

    /**
     * Проверяет, что {@code openssl version} выполняется успешно.
     */
    public static void assumeOpenSslAvailable() {
        try {
            ProcessBuilder pb = new ProcessBuilder(resolveOpenSslBinary(), "version");
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            int code = p.waitFor();
            assertTrue(code == 0, "openssl не найден — пропуск");
        } catch (Exception e) {
            fail("Проверка openssl version не удалась: " + e.getMessage());
        }
    }

    /**
     * Проверяет, что доступен {@code engine gost}.
     */
    public static void assumeEngineGost() {
        try {
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "genpkey"},
                            resolveEngineFlag(),
                            new String[] {
                                "-algorithm", "gost2012_256",
                                "-pkeyopt", "paramset:A",
                                "-out", "/dev/null"
                            });
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            int code = p.waitFor();
            assertTrue(code == 0, "OpenSSL GOST (engine/provider) не найден — пропуск");
        } catch (Exception e) {
            fail("Проверка GOST (engine/provider) не удалась: " + e.getMessage());
        }
    }

    /**
     * Проверяет, что OpenSSL собран с поддержкой Кузнечика
     * (присутствует в списке cipher-algorithms).
     */
    public static void assumeKuznyechikCipher() {
        try {
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "list", "-cipher-algorithms"},
                            resolveEngineFlag());
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            String ciphers = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            assertTrue(
                    ciphers.toLowerCase().contains("kuznyechik"),
                    "OpenSSL собран без поддержки Кузнечика — пропуск");
        } catch (Exception e) {
            fail("Проверка cipher-algorithms не удалась: " + e.getMessage());
        }
    }

    /**
     * Проверяет, что {@code openssl dgst -streebog256} поддерживается.
     */
    public static void assumeStreebog() {
        try {
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "dgst", "-md_gost12_256"},
                            resolveEngineFlag(),
                            new String[] {"/dev/null"});
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            int code = p.waitFor();
            assertTrue(
                    code == 0,
                    "openssl не поддерживает -md_gost12_256 (нужен GOST-провайдер) — пропуск");
        } catch (Exception e) {
            fail("Проверка -streebog256 не удалась: " + e.getMessage());
        }
    }

    /**
     * Проверяет, что {@code openssl mac CMAC kuznyechik-cbc} поддерживается.
     */
    /**
     * Проверяет полную готовность gost-pkcs12:
     * genpkey -> req -> pkcs12 -export.
     * Определяет синтаксис engine vs provider по версии OpenSSL.
     * При любом сбое — assumeTrue/abort (тест пропускается).
     */
    public static void assumeGostPkcs12() {
        assumeOpenSslAvailable();
        Path tmp = null;
        try {
            tmp = Files.createTempDirectory("ossl-probe-");
            Path keyFile = tmp.resolve("probe.key");
            Path certFile = tmp.resolve("probe.crt");
            Path pfxFile = tmp.resolve("probe.pfx");

            String[] engineFlag = resolveEngineFlag();

            String[] genCmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "genpkey"},
                            engineFlag,
                            new String[] {
                                "-algorithm", "gost2012_256",
                                "-pkeyopt", "paramset:A",
                                "-out", keyFile.toString()
                            });
            int c1 = run(genCmd);
            assertTrue(c1 == 0, "OpenSSL gost2012_256 genpkey недоступен — пропуск");

            String[] reqCmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "req", "-new", "-x509"},
                            engineFlag,
                            new String[] {
                                "-key",
                                keyFile.toString(),
                                "-out",
                                certFile.toString(),
                                "-subj",
                                "/CN=probe",
                                "-days",
                                "1",
                                "-config",
                                "/dev/null"
                            });
            int c2 = run(reqCmd);
            assertTrue(c2 == 0, "OpenSSL req с gost2012_256 недоступен — пропуск");

            String[] p12Cmd =
                    CrossValUtils.concat(
                            new String[] {resolveOpenSslBinary(), "pkcs12", "-export"},
                            engineFlag,
                            new String[] {
                                "-inkey", keyFile.toString(),
                                "-in", certFile.toString(),
                                "-out", pfxFile.toString(),
                                "-passout", "pass:probe"
                            });
            int c3 = run(p12Cmd);
            assertTrue(c3 == 0, "OpenSSL pkcs12 -export с ГОСТ недоступен — пропуск");

        } catch (Exception e) {
            fail("Проверка gost pkcs12 не удалась: " + e.getMessage());
        } finally {
            if (tmp != null) TempDirUtils.deleteRecursively(tmp);
        }
    }

    /**
     * Определяет флаг провайдера/движка для команд OpenSSL.
     * <p>
     * Порядок проверки:
     * <ol>
     *   <li>{@code -provider-path root/lib/ossl-modules -provider gostprov -provider default}
     *       (патченая сборка OpenSSL 3.x с gostprov.so);</li>
     *   <li>{@code -provider gost -provider default} (системный gost-engine пакет);</li>
     *   <li>{@code -engine gost} (legacy engine API).</li>
     * </ol>
     * Результат кешируется.
     */
    public static String[] resolveEngineFlag() {
        if (cachedEngineFlag != null) return cachedEngineFlag;

        String opensslBin = resolveOpenSslBinary();
        String root = resolveOpenSslRoot();

        // 1) provider-path + gostprov (патченая сборка)
        if (!root.isEmpty()) {
            Path osslModules = Paths.get(root, "lib", "ossl-modules");
            if (Files.isDirectory(osslModules)) {
                String[] candidate =
                        new String[] {
                            "-provider-path",
                            osslModules.toString(),
                            "-provider",
                            "gostprov",
                            "-provider",
                            "default"
                        };
                try {
                    ProcessBuilder pb =
                            new ProcessBuilder(
                                    opensslBin,
                                    "genpkey",
                                    "-provider-path",
                                    osslModules.toString(),
                                    "-provider",
                                    "gostprov",
                                    "-provider",
                                    "default",
                                    "-algorithm",
                                    "gost2012_256",
                                    "-pkeyopt",
                                    "paramset:A",
                                    "-out",
                                    "/dev/null");
                    pb.environment().putAll(getOpenSslEnv());
                    Process p = pb.start();
                    p.getInputStream().readAllBytes();
                    int code = p.waitFor();
                    if (code == 0) {
                        cachedEngineFlag = candidate;
                        return cachedEngineFlag;
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // 2) provider gost (системный gost-engine)
        try {
            ProcessBuilder pb =
                    new ProcessBuilder(
                            opensslBin,
                            "genpkey",
                            "-provider",
                            "gost",
                            "-provider",
                            "default",
                            "-algorithm",
                            "gost2012_256",
                            "-pkeyopt",
                            "paramset:A",
                            "-out",
                            "/dev/null");
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            int code = p.waitFor();
            if (code == 0) {
                cachedEngineFlag = new String[] {"-provider", "gost", "-provider", "default"};
                return cachedEngineFlag;
            }
        } catch (Exception ignored) {
        }

        // 3) engine gost (legacy)
        cachedEngineFlag = new String[] {"-engine", "gost"};
        return cachedEngineFlag;
    }

    /**
     * Проверяет, что {@code openssl pkeyutl -derive} с ГОСТ-ключами работает.
     * Генерирует два probe-ключа, запускает derive, проверяет exit code.
     * Пропускает тест, если pkeyutl -derive не поддерживается (например,
     * legacy engine gost требует UKM, который не выставляется через pkeyopt).
     */
    public static void assumeGostDerive() {
        Path tmp = null;
        try {
            tmp = Files.createTempDirectory("ossl-derive-probe-");
            Path priv = tmp.resolve("probe.der");
            Path pub = tmp.resolve("probe_pub.der");
            Path shared = tmp.resolve("shared.bin");

            int c1 =
                    run(
                            CrossValUtils.concat(
                                    new String[] {resolveOpenSslBinary(), "genpkey"},
                                    resolveEngineFlag(),
                                    new String[] {
                                        "-algorithm",
                                        "gost2012_256",
                                        "-pkeyopt",
                                        "paramset:A",
                                        "-outform",
                                        "DER",
                                        "-out",
                                        priv.toString()
                                    }));
            assertTrue(c1 == 0, "OpenSSL genpkey gost2012_256 недоступен — пропуск");

            int c2 =
                    run(
                            CrossValUtils.concat(
                                    new String[] {resolveOpenSslBinary(), "pkey"},
                                    resolveEngineFlag(),
                                    new String[] {
                                        "-in",
                                        priv.toString(),
                                        "-inform",
                                        "DER",
                                        "-pubout",
                                        "-outform",
                                        "DER",
                                        "-out",
                                        pub.toString()
                                    }));
            assertTrue(c2 == 0, "OpenSSL pkey -pubout недоступен — пропуск");

            int c3 =
                    run(
                            CrossValUtils.concat(
                                    new String[] {resolveOpenSslBinary(), "pkeyutl", "-derive"},
                                    resolveEngineFlag(),
                                    new String[] {
                                        "-inkey",
                                        priv.toString(),
                                        "-keyform",
                                        "DER",
                                        "-peerkey",
                                        pub.toString(),
                                        "-peerform",
                                        "DER",
                                        "-out",
                                        shared.toString()
                                    }));
            assertTrue(c3 == 0, "OpenSSL pkeyutl -derive с ГОСТ недоступен — пропуск");
        } catch (Exception e) {
            fail("Проверка pkeyutl -derive не удалась: " + e.getMessage());
        } finally {
            if (tmp != null) TempDirUtils.deleteRecursively(tmp);
        }
    }

    public static int run(String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.environment().putAll(getOpenSslEnv());
        Process p = pb.start();
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    public static void exec(String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.environment().putAll(getOpenSslEnv());
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(
                    "Command failed (exit="
                            + exitCode
                            + "): "
                            + String.join(" ", cmd)
                            + "\n"
                            + out);
        }
    }

    /**
     * Определяет флаги провайдера/движка для команд OpenSSL,
     * специфичные для GOST TLS 1.3 (s_client/s_server).
     * <p>
     * Порядок проверки:
     * <ol>
     *   <li>{@code -provider gost -provider default} (системный gost-engine);</li>
     *   <li>{@code -provider gostprov -provider default} (gostprov по имени);</li>
     *   <li>{@code -provider-path &lt;path&gt; -provider gostprov -provider default}
     *       (gostprov из кастомного пути);</li>
     *   <li>{@code -engine gost} (legacy engine API).</li>
     * </ol>
     * Результат кешируется. Может вернуть пустой массив, если
     * конфигурация задана через OPENSSL_CONF.
     */
    public static String[] resolveTls13Flags() {
        if (cachedTls13Flags != null) return cachedTls13Flags;

        String openssl = resolveOpenSslBinary();
        String root = resolveOpenSslRoot();

        // Если есть конфиг — флаги не нужны, OPENSSL_CONF всё настроит
        if (!root.isEmpty()) {
            Path configPath = Paths.get(root, "ssl", "openssl-gost.cnf");
            if (Files.exists(configPath)) {
                cachedTls13Flags = new String[0];
                return cachedTls13Flags;
            }
        }

        // 1) provider gost (системный gost-engine)
        if (testTls13Flags(openssl, new String[] {"-provider", "gost", "-provider", "default"})) {
            cachedTls13Flags = new String[] {"-provider", "gost", "-provider", "default"};
            return cachedTls13Flags;
        }

        // 2) provider gostprov (установлен в system-wide)
        if (testTls13Flags(
                openssl, new String[] {"-provider", "gostprov", "-provider", "default"})) {
            cachedTls13Flags = new String[] {"-provider", "gostprov", "-provider", "default"};
            return cachedTls13Flags;
        }

        // 3) provider-path + gostprov (патченая сборка)
        if (!root.isEmpty()) {
            Path osslModules = Paths.get(root, "lib", "ossl-modules");
            if (Files.isDirectory(osslModules)) {
                String[] candidate =
                        new String[] {
                            "-provider-path",
                            osslModules.toString(),
                            "-provider",
                            "gostprov",
                            "-provider",
                            "default"
                        };
                if (testTls13Flags(openssl, candidate)) {
                    cachedTls13Flags = candidate;
                    return cachedTls13Flags;
                }
            }
        }

        // 4) engine gost (legacy)
        cachedTls13Flags = new String[] {"-engine", "gost"};
        return cachedTls13Flags;
    }

    /**
     * Возвращает те же флаги, что {@link #resolveTls13Flags()}, но
     * без {@code -provider-path} (некоторые команды OpenSSL его не принимают).
     */
    public static String[] resolveTls13AssumeFlags() {
        if (cachedTls13AssumeFlags != null) return cachedTls13AssumeFlags;
        String[] full = resolveTls13Flags();
        if (full.length == 0) {
            cachedTls13AssumeFlags = full;
            return full;
        }
        java.util.ArrayList<String> list = new java.util.ArrayList<>();
        for (int i = 0; i < full.length; i++) {
            if (full[i].equals("-provider-path")) {
                i++;
            } else {
                list.add(full[i]);
            }
        }
        cachedTls13AssumeFlags = list.toArray(new String[0]);
        return cachedTls13AssumeFlags;
    }

    /**
     * Запускает {@code openssl ciphers -s -tls1_3} с указанными флагами
     * и проверяет, что GOST TLS 1.3 suite распознаётся.
     */
    private static boolean testTls13Flags(String openssl, String[] flags) {
        try {
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {
                                openssl,
                                "ciphers",
                                "-s",
                                "-tls1_3",
                                "-ciphersuites",
                                "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"
                            },
                            flags);
            Process p = new ProcessBuilder(cmd).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return out.contains("TLS_GOSTR341112");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Проверяет, что OpenSSL поддерживает GOST TLS 1.3 cipher suite.
     * Запускает {@code openssl ciphers -s -tls1_3 -ciphersuites <suite>}
     * и проверяет, что suite распознаётся.
     */
    public static void assumeGostTls13() {
        String opensslBin = resolveOpenSslBinary();
        String[] flags = resolveTls13AssumeFlags();
        try {
            String suite = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {
                                opensslBin, "ciphers", "-s", "-tls1_3", "-ciphersuites", suite
                            },
                            flags);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(getOpenSslEnv());
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            int code = p.waitFor();
            assertTrue(
                    code == 0 && out.contains(suite),
                    "OpenSSL не поддерживает GOST TLS 1.3 cipher suite ("
                            + opensslBin
                            + ") — пропуск");
        } catch (Exception e) {
            fail("Проверка GOST TLS 1.3 не удалась: " + e.getMessage());
        }
    }

    public static void assumeCmacKuznyechik() {
        try {
            String[] cmd =
                    CrossValUtils.concat(
                            new String[] {
                                resolveOpenSslBinary(),
                                "mac",
                                "-cipher",
                                "kuznyechik-cbc",
                                "-macopt",
                                "hexkey:0000000000000000000000000000000000000000000000000000000000000000"
                            },
                            resolveEngineFlag(),
                            new String[] {"CMAC"});
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().putAll(getOpenSslEnv());
            pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
            Process p = pb.start();
            int code = p.waitFor();
            assertTrue(
                    code == 0,
                    "openssl не поддерживает CMAC-Kuznyechik (нужен GOST-провайдер) — пропуск");
        } catch (Exception e) {
            fail("Проверка CMAC-Kuznyechik не удалась: " + e.getMessage());
        }
    }
}
