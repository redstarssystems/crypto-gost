package org.rssys.gost.tls13.examples;

import org.rssys.gost.jsse.crl.JdkHttpCrlFetcher;
import org.rssys.gost.jsse.ocsp.JdkHttpOcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspFetchResult;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsCrlVerifier;
import org.rssys.gost.tls13.cert.TlsOcspVerifier;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Пример проверки статуса сертификата ГОСТ Р 34.10-2012
 * через OCSP (RFC 6960) и CRL (RFC 5280) с использованием
 * криптографической библиотеки crypto-gost.
 *
 * <p>Демонстрирует полный цикл:
 * <ul>
 *   <li>загрузка сертификата субъекта и CA из DER-файлов;</li>
 *   <li>извлечение OCSP-uri, caIssuers-uri и CDP-uri из расширений;</li>
 *   <li>автоматическое скачивание CA из caIssuers (RFC 5280 §4.2.2.1);</li>
 *   <li>OCSP-запрос с nonce (RFC 8954) через {@link JdkHttpOcspFetcher}
 *       и верификация ответа {@link TlsOcspVerifier}: проверка подписи,
 *       CertID (issuerNameHash + issuerKeyHash), nonce, статуса (good/revoked/unknown),
 *       а также извлечение сертификата делегированного OCSP-responder'а;</li>
 *   <li>загрузка CRL через {@link JdkHttpCrlFetcher} с failover по всем
 *       CDP-точкам и верификация {@link TlsCrlVerifier}: подпись CRL,
 *       срок действия, поиск серийного номера в списке отозванных.</li>
 * </ul>
 *
 * <p>Пример запуска:
 * <pre>
 * mvn exec:java -pl examples/tls \
 *   -Dexec.mainClass="org.rssys.gost.tls13.examples.CertificateStatusCheck" \
 *   -Dexec.args="/путь/к/сертификату.der /путь/к/ca.der"
 * </pre>
 *
 * @see TlsCertificate
 * @see TlsOcspVerifier
 * @see TlsCrlVerifier
 * @see JdkHttpOcspFetcher
 * @see JdkHttpCrlFetcher
 */
public final class CertificateStatusCheck {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Использование: CertificateStatusCheck <cert.der> <ca.der>");
            System.exit(1);
        }

        byte[] certDer = Files.readAllBytes(Path.of(args[0]));
        byte[] caDer = Files.readAllBytes(Path.of(args[1]));

        TlsCertificate cert = TlsCertificate.fromDer(certDer);
        TlsCertificate caCert = TlsCertificate.fromDer(caDer);

        System.out.println("Субъект: " + cert.getSubjectDn());
        System.out.println("Издатель: " + cert.getIssuerDn());
        System.out.println("Истекает: " + cert.getNotAfter());
        System.out.println("Просрочен: " + cert.isExpired());
        System.out.println();

        String[] ocspUris = cert.getOcspUris();
        String[] caIssuersUris = cert.getCaIssuersUris();
        String[] cdpUris = cert.getCdpUris();

        if (ocspUris != null && ocspUris.length > 0) {
            System.out.println("OCSP responder: " + ocspUris[0]);
        }
        if (caIssuersUris != null && caIssuersUris.length > 0) {
            System.out.println("CA issuers: " + caIssuersUris[0]);
        }
        if (cdpUris != null && cdpUris.length > 0) {
            System.out.println("CRL точек распространения: " + cdpUris.length);
            for (int i = 0; i < Math.min(2, cdpUris.length); i++) {
                System.out.println("  " + cdpUris[i]);
            }
            if (cdpUris.length > 2) {
                System.out.println("  и ещё " + (cdpUris.length - 2));
            }
        }
        System.out.println();

        // Скачиваем CA из caIssuers, если указан
        TlsCertificate caFromIssuer = null;
        if (caIssuersUris != null && caIssuersUris.length > 0) {
            try {
                HttpClient http = HttpClient.newHttpClient();
                HttpRequest req = HttpRequest.newBuilder(URI.create(caIssuersUris[0]))
                        .timeout(Duration.ofSeconds(10)).GET().build();
                byte[] caDer2 = http.send(req, HttpResponse.BodyHandlers.ofByteArray()).body();
                caFromIssuer = TlsCertificate.fromDer(caDer2);
                System.out.println("CA скачан из caIssuers: " + caFromIssuer.getSubjectDn());
            } catch (Exception e) {
                System.out.println("Не удалось скачать CA из caIssuers: " + e.getMessage());
            }
            System.out.println();
        }

        // OCSP
        if (ocspUris != null && ocspUris.length > 0) {
            JdkHttpOcspFetcher ocspFetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(15), 65536);
            OcspFetchResult result = ocspFetcher.fetchWithNonce(certDer, caDer, ocspUris[0]);

            if (result.response() != null) {
                System.out.println("OCSP-ответ получен (" + result.response().length + " байт)");
                try {
                    TlsOcspVerifier.verify(result.response(), cert.getSerialNumber(),
                            caCert.getPublicKey());
                    System.out.println("OCSP: сертификат действителен (good)");
                } catch (Exception e) {
                    System.out.println("OCSP (по ключу CA): " + e.getMessage());
                }

                // Пробуем с проверкой имени издателя (subject DN CA)
                try {
                    TlsOcspVerifier.verify(result.response(), cert.getSerialNumber(),
                            caCert.getPublicKey(), caCert.getSubjectDnBytes(), caDer);
                    System.out.println("OCSP (с проверкой DN издателя): сертификат действителен");
                } catch (Exception e) {
                    System.out.println("OCSP (с проверкой DN издателя): " + e.getMessage());
                }

                // Если скачали CA из caIssuers — пробуем и с ним
                if (caFromIssuer != null) {
                    try {
                        TlsOcspVerifier.verify(result.response(), cert.getSerialNumber(),
                                caFromIssuer.getPublicKey());
                        System.out.println("OCSP (по ключу CA из caIssuers): сертификат действителен");
                    } catch (Exception e) {
                        System.out.println("OCSP (по ключу CA из caIssuers): " + e.getMessage());
                    }
                }

                if (result.nonce() != null) {
                    try {
                        TlsOcspVerifier.verifyNonce(result.response(), result.nonce(), false);
                        System.out.println("OCSP: nonce совпадает");
                    } catch (Exception e) {
                        System.out.println("OCSP: nonce не совпадает (" + e.getMessage() + ")");
                    }
                }

                // Пробуем извлечь сертификат делегированного OCSP-responder'а
                try {
                    var delegated = TlsOcspVerifier.extractDelegatedCerts(result.response());
                    if (!delegated.isEmpty()) {
                        TlsCertificate dc = TlsCertificate.fromDer(delegated.get(0));
                        System.out.println("OCSP: делегированный responder: " + dc.getSubjectDn());
                    } else {
                        System.out.println("OCSP: делегированных сертификатов responder'а нет, подписано тем же CA");
                    }
                } catch (Exception e) {
                    System.out.println("OCSP: ошибка разбора делегированных сертификатов (" + e.getMessage() + ")");
                }
            } else {
                System.out.println("OCSP: не удалось получить ответ");
            }
        }
        System.out.println();

        // CRL
        if (cdpUris != null && cdpUris.length > 0) {
            JdkHttpCrlFetcher crlFetcher = new JdkHttpCrlFetcher(Duration.ofSeconds(30), 50 * 1024 * 1024);
            byte[] crlDer = null;
            String usedCdp = null;
            for (String cdp : cdpUris) {
                try {
                    crlDer = crlFetcher.fetch(cdp);
                    if (crlDer != null) {
                        usedCdp = cdp;
                        break;
                    }
                } catch (IOException e) {
                    System.out.println("Ошибка загрузки CRL с " + cdp + ": " + e.getMessage());
                }
            }

            if (crlDer != null) {
                System.out.println("CRL загружен с " + usedCdp + " (" + crlDer.length + " байт)");
                try {
                    TlsCrlVerifier.verify(crlDer, cert.getSerialNumber(), caCert.getPublicKey());
                    System.out.println("CRL: сертификат не отозван");
                } catch (Exception e) {
                    System.out.println("CRL: " + e.getMessage());
                }
            } else {
                System.out.println("CRL: не удалось загрузить ни с одного CDP");
            }
        }

        System.out.println();
        System.out.println("Готово.");
    }
}
