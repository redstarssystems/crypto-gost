package org.rssys.gost.pkix.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.pkix.cert.GostPemUtils;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Генерация тестовых сертификатов для стенда Angie + FileReceiveServer.
 *
 * <p>Создаёт:
 * <ul>
 *   <li>CA-сертификат (самоподписанный, корневой УЦ)</li>
 *   <li>Серверный сертификат для Angie (CN=angie-gost-test)</li>
 *   <li>Серверный сертификат для FileReceiveServer (CN=backend-gost-test)</li>
 *   <li>Клиентский сертификат для mTLS upstream (CN=angie-mtls-client)</li>
 *   <li>Клиентский сертификат для mTLS gost-curl (CN=gost-curl-client)</li>
 * </ul>
 * Экспортирует:
 * <ul>
 *   <li>{@code ca.pem} — CA-сертификат (trust store для Angie)</li>
 *   <li>{@code server.pem} — цепочка Angie (leaf + CA) для ssl_certificate</li>
 *   <li>{@code server-key.pem} — закрытый ключ Angie в PKCS#8 PEM</li>
 *   <li>{@code backend.p12} — PFX-контейнер для FileReceiveServer</li>
 *   <li>{@code angie-client.pem} — цепочка mTLS-клиента Angie (upstream)</li>
 *   <li>{@code angie-client-key.pem} — закрытый ключ mTLS-клиента Angie</li>
 *   <li>{@code gost-curl-client.pem} — цепочка mTLS-клиента gost-curl</li>
 *   <li>{@code gost-curl-client-key.pem} — закрытый ключ mTLS-клиента gost-curl</li>
 * </ul>
 */
public final class GenerateTestCerts {

    private GenerateTestCerts() {}

    public static void main(String[] args) throws Exception {
        Path outDir = args.length > 0 ? Path.of(args[0]) : Path.of("/etc/angie");
        String caPassword = "changeit";
        Files.createDirectories(outDir);

        // GC256B (CryptoPro-A) — единственная кривая, которую openssl gost-provider
        // поддерживает в key_share без HRR. GC256A требует HelloRetryRequest,
        // который gostprov не осиливает (см. x-validation-tests, HRR @Disabled).
        ECParameters params = ECParameters.cryptoProA();

        // —————— CA (самоподписанный) ——————
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters caPriv = caKp.getPrivate();
        PublicKeyParameters caPub = caKp.getPublic();

        GostCertificate caCert =
                GostCertificateBuilder.create(params, "CN=Test GOST CA,O=Test")
                        .publicKey(caPub)
                        .notBeforeNow()
                        .validForYears(10)
                        .basicConstraints(true, null)
                        .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                        .randomSerial()
                        .sign(caPriv);

        // —————— Серверный сертификат для Angie (порт 443) ——————
        KeyPair angieKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters angiePriv = angieKp.getPrivate();
        PublicKeyParameters angiePub = angieKp.getPublic();

        GostCertificate angieCert =
                GostCertificateBuilder.create(params, "CN=angie-gost-test")
                        .publicKey(angiePub)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBeforeNow()
                        .validForDays(365)
                        .sanDns("localhost")
                        .sanIp("127.0.0.1")
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .randomSerial()
                        .sign(caPriv);

        // —————— Серверный сертификат для FileReceiveServer (порт 8443) ——————
        KeyPair backendKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters backendPriv = backendKp.getPrivate();
        PublicKeyParameters backendPub = backendKp.getPublic();

        GostCertificate backendCert =
                GostCertificateBuilder.create(params, "CN=backend-gost-test")
                        .publicKey(backendPub)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBeforeNow()
                        .validForDays(365)
                        .sanDns("localhost")
                        .sanIp("127.0.0.1")
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .randomSerial()
                        .sign(caPriv);

        // —————— Клиентский сертификат для mTLS (Angie на upstream-ноге) ——————
        KeyPair clientKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters clientPriv = clientKp.getPrivate();
        PublicKeyParameters clientPub = clientKp.getPublic();

        GostCertificate clientCert =
                GostCertificateBuilder.create(params, "CN=angie-mtls-client")
                        .publicKey(clientPub)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_CLIENT_AUTH)
                        .randomSerial()
                        .sign(caPriv);

        // —————— Клиентский сертификат для gost-curl (mTLS на порту 443) ——————
        KeyPair gostCurlKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters gostCurlPriv = gostCurlKp.getPrivate();
        PublicKeyParameters gostCurlPub = gostCurlKp.getPublic();

        GostCertificate gostCurlCert =
                GostCertificateBuilder.create(params, "CN=gost-curl-client")
                        .publicKey(gostCurlPub)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_CLIENT_AUTH)
                        .randomSerial()
                        .sign(caPriv);

        // —————— Экспорт ——————

        // ca.pem — корневой CA для trust store
        String caPem = caCert.toPem();
        Path caPath = outDir.resolve("ca.pem");
        Files.writeString(caPath, caPem);
        System.out.println("CA: " + caPath.toAbsolutePath());

        // server.pem — цепочка Angie (leaf + CA) для ssl_certificate
        String serverChainPem = GostCertificate.chainToPem(List.of(angieCert, caCert));
        Path serverPemPath = outDir.resolve("server.pem");
        Files.writeString(serverPemPath, serverChainPem);
        System.out.println("Angie cert chain: " + serverPemPath.toAbsolutePath());

        // server-key.pem — закрытый ключ Angie в PKCS#8 PEM
        byte[] angieKeyDer = GostDerCodec.encodePrivateKey(angiePriv);
        String angieKeyPem = GostPemUtils.toPem(angieKeyDer, "PRIVATE KEY");
        Path angieKeyPath = outDir.resolve("server-key.pem");
        Files.writeString(angieKeyPath, angieKeyPem);
        System.out.println("Angie key: " + angieKeyPath.toAbsolutePath());

        // backend.p12 — PFX для FileReceiveServer
        byte[] backendPfx =
                GostPkcs12Builder.create()
                        .key(backendPriv)
                        .certificate(backendCert)
                        .caCertificate(caCert)
                        .password(caPassword.toCharArray())
                        .friendlyName("backend-gost-test")
                        .build();
        Path backendPfxPath = outDir.resolve("backend.p12");
        Files.write(backendPfxPath, backendPfx);
        System.out.println("Backend PFX: " + backendPfxPath.toAbsolutePath());

        // angie-client.pem — цепочка mTLS-клиента (leaf + CA) для proxy_ssl_certificate
        String clientChainPem = GostCertificate.chainToPem(List.of(clientCert, caCert));
        Path clientPemPath = outDir.resolve("angie-client.pem");
        Files.writeString(clientPemPath, clientChainPem);
        System.out.println("Angie mTLS client cert: " + clientPemPath.toAbsolutePath());

        // angie-client-key.pem — закрытый ключ mTLS-клиента в PKCS#8 PEM
        byte[] clientKeyDer = GostDerCodec.encodePrivateKey(clientPriv);
        String clientKeyPem = GostPemUtils.toPem(clientKeyDer, "PRIVATE KEY");
        Path clientKeyPath = outDir.resolve("angie-client-key.pem");
        Files.writeString(clientKeyPath, clientKeyPem);
        System.out.println("Angie mTLS client key: " + clientKeyPath.toAbsolutePath());

        // gost-curl-client.pem — цепочка mTLS-клиента gost-curl (leaf + CA)
        String gostCurlChainPem = GostCertificate.chainToPem(List.of(gostCurlCert, caCert));
        Path gostCurlPemPath = outDir.resolve("gost-curl-client.pem");
        Files.writeString(gostCurlPemPath, gostCurlChainPem);
        System.out.println("gost-curl mTLS client cert: " + gostCurlPemPath.toAbsolutePath());

        // gost-curl-client-key.pem — закрытый ключ mTLS-клиента gost-curl
        byte[] gostCurlKeyDer = GostDerCodec.encodePrivateKey(gostCurlPriv);
        String gostCurlKeyPem = GostPemUtils.toPem(gostCurlKeyDer, "PRIVATE KEY");
        Path gostCurlKeyPath = outDir.resolve("gost-curl-client-key.pem");
        Files.writeString(gostCurlKeyPath, gostCurlKeyPem);
        System.out.println("gost-curl mTLS client key: " + gostCurlKeyPath.toAbsolutePath());

        // —————— Защита ключевого материала ——————
        angiePriv.destroy();
        backendPriv.destroy();
        clientPriv.destroy();
        gostCurlPriv.destroy();
        caPriv.destroy();

        System.out.println("DONE");
    }
}
