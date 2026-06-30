package org.rssys.gost.tls13.examples;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Цепочка сертификатов из 3 звеньев: leaf -> intermediate -> root.
 * <p>
 * Сервер отправляет цепочку {serverCert, intermediateCert, rootCert}.
 * Клиент проверяет всю цепочку через CA public key корневого сертификата.
 * Демонстрирует List<GostCertificate> цепочку в TlsServerConfig.
 */
public final class ThreeCertChain {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();

        // 1. Корневой CA (самоподписанный)
        KeyPair rootKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters rootPriv = rootKp.getPrivate();
        byte[] rootDn = ExampleUtils.buildDN("Example Root CA " + (System.nanoTime()));
        byte[] rootBcExt = ExampleUtils.buildBasicConstraintsExt(true, null);
        GostCertificate root =
                ExampleUtils.createCert(
                        rootPriv, rootKp.getPublic(), params, rootDn, rootDn, rootBcExt);

        // 2. Промежуточный CA (подписан корнем)
        KeyPair intermediateKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters intermediatePriv = intermediateKp.getPrivate();
        byte[] intermediateDn = ExampleUtils.buildDN("Example Intermediate " + (System.nanoTime()));
        byte[] bcExt = ExampleUtils.buildBasicConstraintsExt(true, 0);
        GostCertificate intermediate =
                ExampleUtils.createCert(
                        rootPriv,
                        intermediateKp.getPublic(),
                        params,
                        rootDn,
                        intermediateDn,
                        bcExt);

        // 3. Серверный сертификат (подписан промежуточным CA)
        KeyPair serverKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        byte[] serverDn = ExampleUtils.buildDN("Example Server " + (System.nanoTime()));
        byte[] sanExt = ExampleUtils.buildSanExt(new String[] {"localhost"}, null);
        byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[] {(byte) 0x80});
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(sanExt);
        extBuf.write(kuExt);
        GostCertificate serverCert =
                ExampleUtils.createCert(
                        intermediatePriv,
                        serverKp.getPublic(),
                        params,
                        intermediateDn,
                        serverDn,
                        extBuf.toByteArray());

        // 4. Создаём пару транспортов
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
                InMemoryTlsTransport clientTp = pair.getClientTransport();
                TlsSession server =
                        TlsSession.createServer(
                                new TlsServerConfig(
                                        cs,
                                        Arrays.asList(serverCert, intermediate, root),
                                        serverPriv),
                                serverTp);
                TlsSession client =
                        TlsSession.createClient(
                                new TlsClientConfig(cs)
                                        .withServerHostname("localhost")
                                        .withCaPublicKey(root.getPublicKey()),
                                clientTp)) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf =
                        exec.submit(
                                () -> {
                                    server.handshakeAsServer();
                                    return null;
                                });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                client.write("3-cert chain verified".getBytes(StandardCharsets.UTF_8));
                byte[] received = server.read();
                System.out.println(new String(received, StandardCharsets.UTF_8));
                System.out.println("SUCCESS");
            } finally {
                exec.shutdown();
                try {
                    exec.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }
}
