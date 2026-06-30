package org.rssys.gost.tls13.examples;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Сертификат с IP-адресом в SubjectAltName.
 * <p>
 * Сервер использует сертификат с SAN iPAddress.
 * Клиент подключается по IP-адресу — verifyHostname проверяет iPAddress.
 * Демонстрирует проверку IP SAN в GostCertificate.verifyHostname().
 */
public final class IpSan {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 1. Генерируем CA + сертификат сервера с DNS + IP SAN
        ExampleUtils.CertBundle caBundle = ExampleUtils.createRootCABundle();
        org.rssys.gost.api.KeyPair serverKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters serverPriv = serverKp.getPrivate();

        // Создаём серверный сертификат с SAN: DNS localhost + IP 127.0.0.1
        GostCertificate serverCert;
        {
            byte[] subjectDn = ExampleUtils.buildDN("Example Server " + (System.nanoTime()));
            byte[] sanExt =
                    ExampleUtils.buildSanExt(
                            new String[] {"localhost"}, new String[] {"127.0.0.1"});
            byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[] {(byte) 0x80});
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(sanExt);
            buf.write(kuExt);
            serverCert =
                    ExampleUtils.createCert(
                            caBundle.priv(),
                            serverKp.getPublic(),
                            ECParameters.tc26a256(),
                            caBundle.cert().getSubjectDnBytes(),
                            subjectDn,
                            buf.toByteArray());
        }

        // 2. Создаём пару транспортов
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
                InMemoryTlsTransport clientTp = pair.getClientTransport();
                TlsSession server =
                        TlsSession.createServer(
                                new TlsServerConfig(
                                        cs, Collections.singletonList(serverCert), serverPriv),
                                serverTp);
                TlsSession client =
                        TlsSession.createClient(
                                new TlsClientConfig(cs).withServerHostname("127.0.0.1"),
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

                client.write("Connected via IP SAN".getBytes(StandardCharsets.UTF_8));
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
