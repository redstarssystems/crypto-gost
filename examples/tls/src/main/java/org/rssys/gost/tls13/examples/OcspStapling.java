package org.rssys.gost.tls13.examples;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * OCSP stapling — сервер прикладывает OCSP-ответ к сертификату.
 * <p>
 * Сервер загружает OCSP-ответ (через {@link GostOcspResponseBuilder})
 * и передаёт его в ServerConfig через withOcspStaplingResponse().
 * Клиент может запросить проверку через withRequireOcspStapling().
 * Демонстрирует TlsServerConfig.withOcspStaplingResponse().
 */
public final class OcspStapling {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();

        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        byte[] caDn = ExampleUtils.buildDN("Example CA " + (System.nanoTime()));
        byte[] caBcExt = ExampleUtils.buildBasicConstraintsExt(true, null);
        GostCertificate ca =
                ExampleUtils.createCert(caPriv, caKp.getPublic(), params, caDn, caDn, caBcExt);

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
                        caPriv, serverKp.getPublic(), params, caDn, serverDn, extBuf.toByteArray());

        byte[] serialNum = serverCert.getSerialNumber();
        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNum)
                        .signer(caPriv, caKp.getPublic())
                        .issuerDn(caDn)
                        .build();

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
                InMemoryTlsTransport clientTp = pair.getClientTransport();
                TlsSession server =
                        TlsSession.createServer(
                                new TlsServerConfig(
                                                cs,
                                                Collections.singletonList(serverCert),
                                                serverPriv)
                                        .withOcspStaplingResponse(ocspDer),
                                serverTp);
                TlsSession client =
                        TlsSession.createClient(
                                new TlsClientConfig(cs)
                                        .withServerHostname("localhost")
                                        .withCaPublicKey(ca.getPublicKey()),
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

                client.write("OCSP stapling verified".getBytes(StandardCharsets.UTF_8));
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
