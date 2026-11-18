package org.rssys.gost.crossval.cadest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertId;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspRequest;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;

/**
 * Локальный сервер TSA, OCSP и CRL для получения вектора через {@code cryptcp -enhance}.
 *
 * <p>Сервер нужен как воспроизводимый инструмент: вектор не создаётся при обычной сборке,
 * а только при смене фикстур. Требования КриптоПро, которые он выполняет:
 * <ul>
 *   <li>ответчик OCSP выбирается по серийному номеру в запросе, так как делегированный
 *       ответчик одного УЦ не вправе подписывать ответ о сертификате другого;</li>
 *   <li>хеш в {@code CertID} должен совпадать с хешем запроса. Первый запрос КриптоПро
 *       приходит с SHA-1, которого построитель ответа не поддерживает, поэтому на не-ГОСТ хеш
 *       сервер отвечает {@code unauthorized}, и клиент повторяет запрос со Стрибогом;</li>
 *   <li>CRL корня выпущен за сутки до запуска: он старше штампа подписи, и политика
 *       {@code STRICT} отвергает его однозначно. CRL службы штампов свежий.</li>
 * </ul>
 */
final class CryptoproVectorServer implements AutoCloseable {

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String TSP_REPLY_TYPE = "application/timestamp-reply";
    private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";
    private static final String CRL_TYPE = "application/pkix-crl";
    private static final String GET_METHOD = "GET";
    private static final int HTTP_OK = 200;
    private static final int HTTP_BAD_REQUEST = 400;
    private static final int HTTP_NOT_FOUND = 404;
    private static final int OCSP_STATUS_UNAUTHORIZED = 6;
    private static final Duration ROOT_CRL_AGE = Duration.ofDays(1);
    private static final Duration CRL_VALIDITY = Duration.ofDays(30);

    private final CryptoproIntermediateFixtures fixtures;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicLong tspSerial = new AtomicLong(1);
    private final byte[] rootCrl;
    private final byte[] tsaCaCrl;

    CryptoproVectorServer(CryptoproIntermediateFixtures fixtures) throws IOException {
        this.fixtures = fixtures;
        Instant now = Instant.now();
        this.rootCrl = buildCrl(fixtures.root(), now.minus(ROOT_CRL_AGE));
        this.tsaCaCrl = buildCrl(fixtures.tsaCa(), now);
        this.server =
                HttpServer.create(
                        new InetSocketAddress(
                                InetAddress.getLoopbackAddress(),
                                CryptoproIntermediateFixtures.SERVER_PORT),
                        0);
        server.setExecutor(executor);
        server.createContext(CryptoproIntermediateFixtures.TSP_PATH, this::handleTsp);
        server.createContext(CryptoproIntermediateFixtures.OCSP_PATH, this::handleOcsp);
        server.createContext(
                CryptoproIntermediateFixtures.ROOT_CRL_PATH,
                exchange -> sendCrl(exchange, rootCrl));
        server.createContext(
                CryptoproIntermediateFixtures.TSA_CA_CRL_PATH,
                exchange -> sendCrl(exchange, tsaCaCrl));
    }

    void start() {
        server.start();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private static byte[] buildCrl(CryptoproFixtureGenerator.Fixture issuer, Instant thisUpdate) {
        return GostCrlBuilder.create(issuer.cert().getSubjectDnBytes())
                .thisUpdate(thisUpdate)
                .nextUpdate(thisUpdate.plus(CRL_VALIDITY))
                .withCrlNumber(1)
                .withAki(issuer.pub())
                .sign(issuer.key());
    }

    private void handleTsp(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] request = exchange.getRequestBody().readAllBytes();
            byte[] reply =
                    DerAlgorithmIdentifierNormalizer.normalizeTimeStampResp(
                            TspResponseBuilder.create(request)
                                    .signer(fixtures.tsa().key(), fixtures.tsa().cert())
                                    .policyOid(TestData.DUMMY_TSA_POLICY_OID)
                                    .serialNumber(BigInteger.valueOf(tspSerial.getAndIncrement()))
                                    .accuracy(1)
                                    .withCAdES()
                                    // промежуточный УЦ службы штампов едет в токене: AIA caIssuers
                                    // в фикстурах нет
                                    .addChainCert(fixtures.tsaCa().cert())
                                    .buildGranted());
            send(exchange, HTTP_OK, TSP_REPLY_TYPE, reply);
            log("TSP: выдан штамп, запрос " + request.length + " байт");
        } catch (Exception e) {
            log("TSP: ошибка " + e);
            exchange.sendResponseHeaders(HTTP_BAD_REQUEST, -1);
        }
    }

    private void handleOcsp(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] requestDer = readOcspRequest(exchange);
            GostOcspRequest request = GostOcspRequest.fromDer(requestDer);
            CertId certId = request.getCertIds().get(0);
            BigInteger serial = new BigInteger(certId.serialNumber());
            if (!GostOids.DIGEST_256.equals(certId.hashAlgOid())) {
                log("OCSP: хеш " + certId.hashAlgOid() + " не поддерживается, ответ unauthorized");
                send(exchange, HTTP_OK, OCSP_RESPONSE_TYPE, unauthorizedResponse());
                return;
            }
            byte[] reply = answer(serial, request.getNonce());
            if (reply == null) {
                log("OCSP: неизвестный серийный номер " + serial);
                send(exchange, HTTP_OK, OCSP_RESPONSE_TYPE, unauthorizedResponse());
                return;
            }
            log("OCSP: " + exchange.getRequestMethod() + ", good для серийного номера " + serial);
            send(exchange, HTTP_OK, OCSP_RESPONSE_TYPE, reply);
        } catch (Exception e) {
            log("OCSP: ошибка " + e);
            exchange.sendResponseHeaders(HTTP_BAD_REQUEST, -1);
        }
    }

    /**
     * RFC 6960 приложение A.1: запрос приходит либо телом POST, либо в пути GET в виде
     * base64 (со знаками, закодированными в URL). КриптоПро использует оба способа.
     */
    private static byte[] readOcspRequest(HttpExchange exchange) throws IOException {
        if (!GET_METHOD.equals(exchange.getRequestMethod())) {
            return exchange.getRequestBody().readAllBytes();
        }
        String rawPath = exchange.getRequestURI().getRawPath();
        String encoded = rawPath.substring(CryptoproIntermediateFixtures.OCSP_PATH.length() + 1);
        return Base64.getDecoder().decode(URLDecoder.decode(encoded, StandardCharsets.UTF_8));
    }

    /** Подписывает ответ «good» ответчиком того УЦ, который выпустил сертификат с этим номером. */
    private byte[] answer(BigInteger serial, byte[] nonce) {
        CryptoproFixtureGenerator.Fixture issuer;
        CryptoproFixtureGenerator.Fixture responder;
        if (serial.equals(CryptoproIntermediateFixtures.SIGNER_SERIAL)) {
            issuer = fixtures.signerCa();
            responder = fixtures.signerOcspResponder();
        } else if (serial.equals(CryptoproIntermediateFixtures.TSA_SERIAL)) {
            issuer = fixtures.tsaCa();
            responder = fixtures.tsaOcspResponder();
        } else {
            return null;
        }
        Instant now = Instant.now();
        return GostOcspResponseBuilder.create(serial.toByteArray())
                .issuerDn(issuer.cert().getSubjectDnBytes())
                .caPublicKey(issuer.cert().getPublicKey())
                .good()
                // КриптоПро шлёт nonce и ждёт его эхо в ответе
                .nonce(nonce)
                .producedAt(now)
                .thisUpdate(now)
                .nextUpdate(now.plus(CRL_VALIDITY))
                // ResponderID строится по имени встроенного сертификата ответчика; без него
                // оно указывало бы на УЦ, и подпись ответчика не сошлась бы
                .withDelegatedCerts(responder.cert().getEncoded())
                .sign(responder.key());
    }

    private static byte[] unauthorizedResponse() {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED } без responseBytes (RFC 6960
        // §4.2.1)
        return new byte[] {0x30, 0x03, 0x0A, 0x01, OCSP_STATUS_UNAUTHORIZED};
    }

    private static void sendCrl(HttpExchange exchange, byte[] crl) throws IOException {
        try (exchange) {
            send(exchange, HTTP_OK, CRL_TYPE, crl);
            log("CRL: отдан " + exchange.getRequestURI().getPath());
        }
    }

    private static void send(HttpExchange exchange, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set(CONTENT_TYPE, contentType);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void log(String message) {
        System.out.println(Instant.now() + " " + message);
    }
}
