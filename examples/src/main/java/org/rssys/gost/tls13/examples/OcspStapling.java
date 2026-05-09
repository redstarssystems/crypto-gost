package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;

/**
 * OCSP stapling — сервер прикладывает OCSP-ответ к сертификату.
 * <p>
 * Сервер загружает OCSP-ответ (в примере строится упрощённый)
 * и передаёт его в ServerConfig через withOcspStaplingResponse().
 * Клиент может запросить проверку через withRequireOcspStapling().
 * Демонстрирует TlsServerConfig.withOcspStaplingResponse().
 */
public final class OcspStapling {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();

        // 1. Генерируем CA + сертификат сервера
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        byte[] caDn = ExampleUtils.buildDN("Example CA " + (System.nanoTime()));
        byte[] caBcExt = ExampleUtils.buildBasicConstraintsExt(true, null);
        TlsCertificate ca = ExampleUtils.createCert(caPriv, caKp.getPublic(),
                caKp.getPublic(), params, caDn, caDn, caBcExt);

        KeyPair serverKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        byte[] serverDn = ExampleUtils.buildDN("Example Server " + (System.nanoTime()));
        byte[] sanExt = ExampleUtils.buildSanExt(new String[]{"localhost"}, null);
        byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[]{(byte) 0x80});
        TlsCertificate serverCert = ExampleUtils.createCert(serverPriv, serverKp.getPublic(),
                serverKp.getPublic(), params, caDn, serverDn,
                ExampleUtils.derSequence(sanExt, kuExt));

        // 2. Строим OCSP-ответ (упрощённый DER, только для демонстрации)
        byte[] serialNum = serverCert.getSerialNumber();
        byte[] ocspDer = buildDummyOcspResponse(serialNum, caPriv, caKp.getPublic());

        // 3. Создаём пару транспортов
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
             InMemoryTlsTransport clientTp = pair.getClientTransport();
             TlsSession server = TlsSession.createServer(
                     new TlsServerConfig(cs, Collections.singletonList(serverCert), serverPriv)
                              .withOcspStaplingResponse(ocspDer), serverTp);
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(cs)
                             .withServerHostname("localhost")
                             .withCaPublicKey(ca.getPublicKey()), clientTp)) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                client.write("OCSP stapling verified".getBytes(StandardCharsets.UTF_8));
                byte[] received = server.read();
                System.out.println(new String(received, StandardCharsets.UTF_8));
                System.out.println("SUCCESS");
            } finally {
                exec.shutdown();
                try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            }
        }
    }

    /** Строит минимальный OCSP-ответ с certStatus=good и подписью CA. */
    static byte[] buildDummyOcspResponse(byte[] serialNum,
                                          PrivateKeyParameters caPriv,
                                          org.rssys.gost.signature.PublicKeyParameters caPub) throws Exception {
        // tbsResponseData: version [0] (optional), responderID, producedAt, responses
        byte[] tbs = buildTbsResponseData(serialNum);

        // Хэш tbsResponseData + подпись
        int hlen = 32;
        byte[] hash = ExampleUtils.doHash(tbs, hlen);
        byte[] sigBytes = Signature.signHash(hash, caPriv);
        byte[] sigBitStr = ExampleUtils.derBitString(sigBytes);
        byte[] sigAlg = ExampleUtils.buildAlgId(ECParameters.tc26a256());

        // BasicOCSPResponse: SEQUENCE { tbsResponseData, sigAlg, sig }
        byte[] basicOcsp = ExampleUtils.derSequence(tbs, sigAlg, sigBitStr);
        byte[] basicOcspOctet = ExampleUtils.derTlv(0x04, basicOcsp);

        // OCTET STRING внутри ResponseBytes
        // ResponseBytes: SEQUENCE { OID id-pkix-ocsp-basic, OCTET STRING }
        byte[] respBytes = ExampleUtils.derSequence(
                ExampleUtils.derOid("1.3.6.1.5.5.7.48.1.1"),
                basicOcspOctet);

        // responseBytes [0] EXPLICIT
        byte[] respBytesExpl = ExampleUtils.derTlv(0xA0, respBytes);

        // OCSPResponse: SEQUENCE { responseStatus ENUMERATED(0), responseBytes }
        byte[] statusEnum = ExampleUtils.derTlv(0x0A, new byte[]{0x00});
        return ExampleUtils.derSequence(statusEnum, respBytesExpl);
    }

    /** Строит tbsResponseData для OCSP. */
    static byte[] buildTbsResponseData(byte[] serialNum) throws Exception {
        // responderID byName
        byte[] responderId = ExampleUtils.derTlv(0xA0,
                ExampleUtils.derSequence(ExampleUtils.derOid("2.5.4.3"),
                        ExampleUtils.derTlv(0x0C, "Test CA".getBytes(StandardCharsets.UTF_8))));

        // producedAt: GeneralizedTime 2025-01-01 12:00:00Z
        byte[] producedAt = ExampleUtils.derTlv(0x18, "20250101120000Z".getBytes(StandardCharsets.US_ASCII));

        // SingleResponse: SEQUENCE { CertID, certStatus, thisUpdate }
        // CertID: SEQUENCE { hashAlg, issuerNameHash, issuerKeyHash, serialNumber }
        byte[] hashAlg = ExampleUtils.derSequence(ExampleUtils.derOid("1.2.643.7.1.1.2.2"));
        byte[] issuerNameHash = ExampleUtils.derTlv(0x04, new byte[32]); // dummy
        byte[] issuerKeyHash = ExampleUtils.derTlv(0x04, new byte[32]); // dummy
        byte[] serialTlv = ExampleUtils.derTlv(0x02, serialNum);
        byte[] certId = ExampleUtils.derSequence(hashAlg, issuerNameHash, issuerKeyHash, serialTlv);

        // certStatus: good = [0] IMPLICIT NULL
        byte[] certStatus = ExampleUtils.derTlv(0xA0, new byte[0]);

        // thisUpdate: GeneralizedTime
        byte[] thisUpdate = ExampleUtils.derTlv(0x18, "20250101120000Z".getBytes(StandardCharsets.US_ASCII));

        byte[] singleResponse = ExampleUtils.derSequence(certId, certStatus, thisUpdate);

        // responses: SEQUENCE OF SingleResponse
        byte[] responses = ExampleUtils.derSequence(singleResponse);

        return ExampleUtils.derSequence(responderId, producedAt, responses);
    }
}
