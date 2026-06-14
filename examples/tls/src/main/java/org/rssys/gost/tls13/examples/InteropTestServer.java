package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.ByteArrayOutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class InteropTestServer {

    private InteropTestServer() {}

    public static void main(String[] args) throws Exception {
        int port = 8443;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i])) {
                port = Integer.parseInt(args[++i]);
            }
        }

        String localIp = detectLocalIp();

        /* Создаём корневой CA (самоподписанный, basicConstraints CA:TRUE, keyCertSign) */
        ECParameters caParams = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair caKp = KeyGenerator.generateKeyPair(caParams);
        byte[] caDn = ExampleUtils.buildDN("GOST Test Root CA");
        byte[] caBcExt = ExampleUtils.buildBasicConstraintsExt(true, null);
        byte[] caKuExt = ExampleUtils.buildKeyUsageExt(new byte[]{0x06}); /* keyCertSign + cRLSign */
        ByteArrayOutputStream caExtBuf = new ByteArrayOutputStream();
        caExtBuf.write(caBcExt); caExtBuf.write(caKuExt);
        TlsCertificate caCert = ExampleUtils.createCert(
                caKp.getPrivate(), caKp.getPublic(),
                caKp.getPublic(), caParams, caDn, caDn, caExtBuf.toByteArray());
        byte[] caDer = caCert.getCertData();
        try { java.nio.file.Files.write(
            java.nio.file.Paths.get(System.getProperty("gost.certs.dir", "/tmp"), "gost-ca.der"), caDer); } catch (Exception e) {}

        /* Создаём/загружаем серверный ключ (фиксированный, чтобы совпадал с импортированным в Firefox) */
        ECParameters srvParams = ECParameters.tc26a256();
        PrivateKeyParameters srvPriv;
        PublicKeyParameters srvPub;
        java.nio.file.Path privPath = java.nio.file.Paths.get(
            System.getProperty("gost.certs.dir", "/tmp") + "/gost-srv-priv.der");
        java.nio.file.Path pubPath = java.nio.file.Paths.get(
            System.getProperty("gost.certs.dir", "/tmp") + "/gost-srv-pub.der");
        if (java.nio.file.Files.exists(privPath) && java.nio.file.Files.exists(pubPath)) {
            byte[] privDer = java.nio.file.Files.readAllBytes(privPath);
            srvPriv = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(privDer);
            byte[] pubDer = java.nio.file.Files.readAllBytes(pubPath);
            srvPub = org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(pubDer);
        } else {
            org.rssys.gost.api.KeyPair srvKp = KeyGenerator.generateKeyPair(srvParams);
            srvPriv = srvKp.getPrivate();
            srvPub = srvKp.getPublic();
            try { java.nio.file.Files.write(privPath, org.rssys.gost.jca.spec.GostDerCodec.encodePrivateKey(srvPriv)); } catch (Exception e) {}
            try { java.nio.file.Files.write(pubPath, org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(srvPub)); } catch (Exception e) {}
        }

        /* Создаём серверный сертификат, подписанный CA */
        byte[] subjectDn = ExampleUtils.buildDN("Interop Test Server");
        byte[] sanExt = ExampleUtils.buildSanExt(null, new String[]{localIp});
        byte[] kuExt = ExampleUtils.buildKeyUsageExt(new byte[]{(byte) 0x80}); /* digitalSignature */
        byte[] ekuExt = ExampleUtils.buildEkuExt("1.3.6.1.5.5.7.3.1");
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(sanExt); extBuf.write(kuExt); extBuf.write(ekuExt);
        TlsCertificate serverCert = ExampleUtils.createCert(
                caKp.getPrivate(), caKp.getPublic(),
                srvPub, srvParams,
                caCert.getSubjectDnBytes(), subjectDn,
                extBuf.toByteArray());
        try { java.nio.file.Files.write(
            java.nio.file.Paths.get(System.getProperty("gost.certs.dir", "/tmp"), "gost-server.der"), serverCert.getCertData()); } catch (Exception e) {}

        TlsCiphersuite suite = TlsCiphersuite.byId(0xC103);
        System.out.println("=== Interop Test Server ===");
        System.out.println("Listening on " + localIp + ":" + port);
        System.out.println("Cipher: KUZNYECHIK_MGM_L (0xC103)");
        System.out.println("CA: CN extracted from DER");
        System.out.println("Cert: CN=Interop Test Server, SAN=IP:" + localIp);
        System.out.println("URL: https://" + localIp + ":" + port + "/");
        System.out.println("Waiting for connection...");

        try (ServerSocket ss = new ServerSocket(port)) {
            while (true) {
                try (Socket socket = ss.accept()) {
                    System.out.println("Accepted: " + socket.getRemoteSocketAddress());
                    socket.setSoTimeout(15000);
                    TlsServerConfig config = new TlsServerConfig(suite,
                            Arrays.asList(serverCert, caCert), srvPriv);
                    try (SocketTlsTransport transport = new SocketTlsTransport(socket);
                         TlsSession server = TlsSession.createServer(config, transport)) {
                        server.handshakeAsServer();

                        System.out.println("Handshake OK");
                        System.out.println("Negotiated: 0x" + Integer.toHexString(server.getCipherSuite().getId()));
                        System.out.println("Peer certs: "
                                + (server.getPeerCertificates() != null ? server.getPeerCertificates().size() : 0));
                        System.out.println("SNI: " + server.getRequestedServerName());

                        byte[] req = server.read();
                        System.out.println("Received " + req.length + " bytes from client");

                        byte[] resp = ("HTTP/1.1 200 OK\r\n"
                                + "Content-Type: text/plain\r\n"
                                + "Content-Length: 10\r\n"
                                + "Connection: close\r\n"
                                + "\r\n"
                                + "INTEROP_OK").getBytes("UTF-8");
                        server.write(resp);
                        System.out.println("Response sent: INTEROP_OK");
                    }
                } catch (Exception e) {
                    System.err.println("[server] connection error: " + e);
                }
            }
        }
    }

    private static String detectLocalIp() throws SocketException {
        Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
        while (nis.hasMoreElements()) {
            NetworkInterface ni = nis.nextElement();
            if (ni.isLoopback() || !ni.isUp()) continue;
            Enumeration<InetAddress> addrs = ni.getInetAddresses();
            while (addrs.hasMoreElements()) {
                InetAddress addr = addrs.nextElement();
                if (addr instanceof Inet4Address) {
                    return addr.getHostAddress();
                }
            }
        }
        return "127.0.0.1";
    }
}
