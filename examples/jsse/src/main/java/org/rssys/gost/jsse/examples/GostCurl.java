package org.rssys.gost.jsse.examples;

import okhttp3.*;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Консольный HTTP-клиент с поддержкой ГОСТ TLS 1.3 — gost-curl.
 * <p>
 * Использует OkHttp + {@code crypto-gost-jsse} для HTTP/1.1 и HTTP/2
 * через ГОСТ TLS 1.3.
 * <p>
 * ПОЧЕМУ не HttpsURLConnection: OkHttp даёт HTTP/2, connection reuse,
 * удобное API. HttpsURLConnection остаётся рабочим вариантом, но OkHttp
 * удобнее для будущих расширений.
 * <p>
 * Предусловие: провайдер RssysGostJsse доступен (регистрируется автоматически).
 * Постусловие: HTTP-ответ выведен в stdout или в файл.
 */
public final class GostCurl {

    private GostCurl() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }

        CliOptions opts = parseArgs(args);
        if (opts.url == null) {
            System.err.println("Ошибка: не указан URL. Используйте gost-curl <url>");
            System.exit(1);
            return;
        }

        // JUL: без -v — только WARNING и выше, с -v — INFO, с -vv — ALL
        Logger gostLog = Logger.getLogger("org.rssys.gost");
        if (opts.verboseLevel == 0) {
            gostLog.setLevel(Level.WARNING);
        } else if (opts.verboseLevel >= 2) {
            gostLog.setLevel(Level.ALL);
        }

        SslSetup ssl = createSslSetup(opts);
        if (ssl == null) {
            System.err.println("Ошибка: укажите --ca <файл> для проверки сертификата " +
                    "или --insecure для пропуска проверки (только разработка)");
            System.exit(1);
            return;
        }

        OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(ssl.context.getSocketFactory(), ssl.trustManager)
                // ConnectionSpec без фильтрации cipher suites — OkHttp по умолчанию
                // разрешает только JDK-наборы, не пропуская ГОСТ.
                .connectionSpecs(List.of(
                        new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                                .allEnabledCipherSuites()
                                .tlsVersions(TlsVersion.TLS_1_3)
                                .build()
                ))
                // Hostname verification выполняется GostX509TrustManager внутри
                // TLS-handshake (verifyHostname). OkHttp-верификатор не знает
                // ГОСТ-сертификаты — пропускаем.
                .hostnameVerifier((host, session) -> true)
                .connectTimeout(opts.connectTimeout, java.util.concurrent.TimeUnit.MILLISECONDS)
                .readTimeout(opts.readTimeout, java.util.concurrent.TimeUnit.MILLISECONDS)
                .followRedirects(opts.followRedirects)
                .build();

        RequestBody body = opts.body != null
                ? RequestBody.create(opts.body, MediaType.get("application/octet-stream"))
                : null;

        Request.Builder rb = new Request.Builder()
                .url(opts.url)
                .method(opts.method, body);
        for (Map.Entry<String, String> h : opts.headers.entrySet()) {
            rb.addHeader(h.getKey(), h.getValue());
        }

        if (opts.verboseLevel >= 1) {
            printRequest(opts.url, opts.method, opts.headers, opts.body);
        }

        try (Response resp = client.newCall(rb.build()).execute()) {
            if (opts.verboseLevel >= 1) {
                printResponse(resp);
            }
            try (ResponseBody respBody = resp.body()) {
                byte[] bytes = respBody != null ? respBody.bytes() : new byte[0];
                if (opts.outputFile != null) {
                    Files.write(Path.of(opts.outputFile), bytes);
                    if (opts.verboseLevel >= 1) {
                        System.err.println("Ответ сохранён в " + opts.outputFile);
                    }
                } else {
                    System.out.write(bytes);
                    System.out.flush();
                }
            }
        }
    }

    // ========================================================================
    // SSL setup
    // ========================================================================

    private record SslSetup(SSLContext context, X509TrustManager trustManager) {}

    /**
     * Создаёт SSLContext + X509TrustManager под режим (--insecure / --ca).
     * TrustManager возвращается явно — OkHttp требует его для sslSocketFactory().
     */
    private static SslSetup createSslSetup(CliOptions opts) throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        SSLContext ctx = SSLContext.getInstance(
                GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        GostX509TrustManager tm;

        if (opts.insecure) {
            tm = new GostX509TrustManager(null, false);
        } else if (opts.caFile != null) {
            tm = createTrustManager(Files.readAllBytes(Path.of(opts.caFile)));
        } else {
            return null;
        }

        KeyManager[] keyManagers = null;
        if (opts.certFile != null && opts.keyFile != null) {
            keyManagers = new KeyManager[]{loadClientKeyManager(opts)};
        } else if (opts.certFile != null || opts.keyFile != null) {
            System.err.println("Ошибка: --cert и --key должны быть указаны вместе");
            System.exit(1);
        }

        ctx.init(keyManagers, new TrustManager[]{tm}, null);
        return new SslSetup(ctx, tm);
    }

    private static GostX509KeyManager loadClientKeyManager(CliOptions opts) throws Exception {
        byte[] certRaw = Files.readAllBytes(Path.of(opts.certFile));
        byte[] keyRaw = Files.readAllBytes(Path.of(opts.keyFile));
        TlsCertificate clientCert = new TlsCertificate(pemToDer(certRaw));
        PrivateKeyParameters clientKey = org.rssys.gost.jca.spec.GostDerCodec
                .decodePrivateKey(pemToDer(keyRaw));
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("client",
                CertificateBridge.toJcaChain(clientCert), clientKey);
        return km;
    }

    private static GostX509TrustManager createTrustManager(byte[] raw) throws Exception {
        PublicKeyParameters caKey = new TlsCertificate(pemToDer(raw)).getPublicKey();
        return new GostX509TrustManager(caKey, false);
    }

    private static byte[] pemToDer(byte[] raw) {
        String asStr = new String(raw, StandardCharsets.US_ASCII).trim();
        if (asStr.startsWith("-----BEGIN")) {
            String b64 = asStr.replaceAll("-----[A-Z ]+-----", "")
                    .replaceAll("\\s", "");
            return Base64.getDecoder().decode(b64);
        }
        return raw;
    }

    // ========================================================================
    // Аргументы командной строки
    // ========================================================================

    private static final class CliOptions {
        String url;
        String method = "GET";
        String body;
        Map<String, String> headers = new LinkedHashMap<>();
        int verboseLevel;
        String outputFile;
        boolean followRedirects;
        boolean insecure;
        String caFile;
        String certFile;
        String keyFile;
        int connectTimeout = 10000;
        int readTimeout = 30000;
    }

    private static CliOptions parseArgs(String[] args) {
        CliOptions opts = new CliOptions();
        int i = 0;
        while (i < args.length) {
            String a = args[i++];
            switch (a) {
                case "-X":
                case "--request":
                    opts.method = nextArg(args, i++, a).toUpperCase(Locale.ROOT);
                    break;
                case "-d":
                case "--data":
                    opts.body = nextArg(args, i++, a);
                    if ("GET".equals(opts.method)) opts.method = "POST";
                    break;
                case "-H":
                case "--header": {
                    String hv = nextArg(args, i++, a);
                    int colon = hv.indexOf(':');
                    if (colon < 1) {
                        die("Неверный формат заголовка: " + hv + " — ожидается Имя: Значение");
                    }
                    opts.headers.put(hv.substring(0, colon).trim(),
                            hv.substring(colon + 1).trim());
                    break;
                }
                case "--verbose":
                    opts.verboseLevel++;
                    break;
                case "-o":
                case "--output":
                    opts.outputFile = nextArg(args, i++, a);
                    break;
                case "-L":
                case "--location":
                    opts.followRedirects = true;
                    break;
                case "-k":
                case "--insecure":
                    opts.insecure = true;
                    break;
                case "--ca":
                    opts.caFile = nextArg(args, i++, a);
                    break;
                case "--cert":
                    opts.certFile = nextArg(args, i++, a);
                    break;
                case "--key":
                    opts.keyFile = nextArg(args, i++, a);
                    break;
                case "--connect-timeout":
                    opts.connectTimeout = parseInt(nextArg(args, i++, a), a);
                    break;
                case "--read-timeout":
                    opts.readTimeout = parseInt(nextArg(args, i++, a), a);
                    break;
                case "--help":
                    printUsage();
                    System.exit(0);
                default:
                    if (a.matches("-v+")) {
                        opts.verboseLevel += a.length() - 1;
                        break;
                    }
                    if (a.startsWith("-")) {
                        die("Неизвестный флаг: " + a);
                    }
                    if (opts.url == null) {
                        opts.url = a;
                    } else {
                        die("Несколько URL не поддерживаются: " + a);
                    }
            }
        }
        return opts;
    }

    private static String nextArg(String[] args, int idx, String flag) {
        if (idx >= args.length) {
            die("Флаг " + flag + " требует аргумент");
        }
        return args[idx];
    }

    private static int parseInt(String s, String flag) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            die("Флаг " + flag + " ожидает число, получено: " + s);
            return 0;
        }
    }

    private static void die(String msg) {
        System.err.println("Ошибка: " + msg);
        System.err.println("Используйте gost-curl --help для справки.");
        System.exit(1);
    }

    // ========================================================================
    // Вывод
    // ========================================================================

    private static void printUsage() {
        System.err.println("""
                gost-curl — консольный HTTP-клиент с поддержкой ГОСТ TLS 1.3
                Использование: gost-curl [опции] <url>

                Опции:
                  -X, --request <метод>    HTTP-метод (по умолчанию: GET)
                  -d, --data <тело>        Тело запроса (меняет метод на POST)
                  -H, --header <Имя:Знч>   Заголовок запроса (можно повторять)
                  -v, --verbose            Показать заголовки запроса и ответа
                  -o, --output <файл>      Сохранить ответ в файл (по умолчанию: stdout)
                  -L, --location           Следовать перенаправлениям (3xx)
                  -k, --insecure           Отключить проверку сертификата (только разработка)
                      --ca <файл>          CA-сертификат (PEM или DER) для проверки сервера
                      --cert <файл>        Клиентский сертификат (PEM или DER) для mTLS
                      --key <файл>         Закрытый ключ клиента (PEM или DER) для mTLS
                      --connect-timeout мс Таймаут соединения (по умолчанию: 10000)
                      --read-timeout мс    Таймаут чтения (по умолчанию: 30000)
                      --help               Показать эту справку

                Примеры:
                  gost-curl --ca ca.pem https://gost-server.example/api
                  gost-curl --ca ca.pem --cert client.pem --key client-key.pem \\
                            https://mtls-server.example/api
                  gost-curl -k -X POST -d '{"key":"value"}' -H "Content-Type: application/json" \\
                            --ca ca.pem https://gost-server.example/api
                  gost-curl -k -L -o page.html https://gost-server.example/redirect""");
    }

    private static void printRequest(String url, String method,
                                     Map<String, String> headers, String body) {
        System.err.println("> " + method + " " + url);
        for (Map.Entry<String, String> h : headers.entrySet()) {
            System.err.println("> " + h.getKey() + ": " + h.getValue());
        }
        if (body != null) {
            System.err.println(">");
            System.err.println("> " + body);
        }
        System.err.println(">");
    }

    private static void printResponse(Response resp) {
        System.err.println("< " + resp.code() + " " + resp.message());
        for (int i = 0; i < resp.headers().size(); i++) {
            System.err.println("< " + resp.headers().name(i) + ": " + resp.headers().value(i));
        }
        System.err.println("<");
    }
}
